/*
 * Decision store in shared memory.
 *
 * Every decision is an entry in a red-black tree keyed by a lookup key:
 * for IP actors a compact binary form of the (masked) network, for other
 * actors the canonical "<type>:<value>" string. Request processing only
 * ever takes the read side of a rwlock; the sync worker takes the write side.
 *
 * Network matching does not need a trie: the store tracks how many entries
 * exist for each prefix length, and a lookup masks the client address to
 * each prefix length in use and probes the tree. Real deployments use a
 * handful of distinct prefix lengths, so this is a few hash lookups.
 */
#include "ngx_http_repsheet_module.h"

typedef struct {
    ngx_str_node_t   sn;
    ngx_queue_t      queue;
    uint64_t         generation;
    int64_t          expires;
    uint8_t          status;
    uint8_t          family;
    uint8_t          prefix;
    u_short          actor_len;
    u_short          reason_len;
    u_char           data[1];       /* [ip key] actor reason */
} ngx_http_repsheet_entry_t;


int64_t
ngx_http_repsheet_now_ms(void)
{
    ngx_time_t *tp = ngx_timeofday();
    return (int64_t) tp->sec * 1000 + tp->msec;
}


ngx_int_t
ngx_http_repsheet_store_init_zone(ngx_shm_zone_t *zone, void *data)
{
    ngx_http_repsheet_store_t  *ostore = data;
    ngx_http_repsheet_store_t  *store = zone->data;
    ngx_http_repsheet_shctx_t  *sh;
    ngx_slab_pool_t            *shpool;

    if (ostore) {
        /* Configuration reload: keep the populated store. */
        store->sh = ostore->sh;
        store->shpool = ostore->shpool;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) zone->shm.addr;

    sh = ngx_slab_calloc(shpool, sizeof(ngx_http_repsheet_shctx_t));
    if (sh == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(&sh->rbtree, &sh->sentinel, ngx_str_rbtree_insert_value);
    ngx_queue_init(&sh->entries);

    shpool->data = sh;
    shpool->log_nomem = 0;

    store->sh = sh;
    store->shpool = shpool;
    return NGX_OK;
}


static uint32_t *
prefix_counter(ngx_http_repsheet_shctx_t *sh, ngx_http_repsheet_entry_t *e)
{
    if (e->family == 4) {
        return &sh->v4_prefixes[e->prefix];
    }
    if (e->family == 6) {
        return &sh->v6_prefixes[e->prefix];
    }
    return NULL;
}


static void
remove_entry(ngx_http_repsheet_store_t *store, ngx_http_repsheet_entry_t *e)
{
    uint32_t *counter = prefix_counter(store->sh, e);

    if (counter) {
        (*counter)--;
    }

    ngx_rbtree_delete(&store->sh->rbtree, &e->sn.node);
    ngx_queue_remove(&e->queue);
    store->sh->count--;
    ngx_slab_free(store->shpool, e);
}


static ngx_http_repsheet_entry_t *
find_entry(ngx_http_repsheet_shctx_t *sh, u_char *key, size_t len)
{
    ngx_str_t  name = { len, key };
    uint32_t   hash = ngx_murmur_hash2(key, len);

    return (ngx_http_repsheet_entry_t *) ngx_str_rbtree_lookup(&sh->rbtree, &name, hash);
}


static void
consider(ngx_http_repsheet_entry_t *e, int64_t now, ngx_http_repsheet_verdict_t *v,
    ngx_pool_t *pool)
{
    u_char *actor, *reason;

    if (e == NULL || (e->expires && e->expires <= now) || e->status <= v->status) {
        return;
    }

    actor = e->data + (e->family ? e->sn.str.len : 0);
    reason = actor + e->actor_len;

    v->status = e->status;
    v->actor.len = 0;
    v->reason.len = 0;

    v->actor.data = ngx_pnalloc(pool, e->actor_len + e->reason_len);
    if (v->actor.data == NULL) {
        return;
    }

    ngx_memcpy(v->actor.data, actor, e->actor_len);
    v->actor.len = e->actor_len;
    v->reason.data = v->actor.data + e->actor_len;
    ngx_memcpy(v->reason.data, reason, e->reason_len);
    v->reason.len = e->reason_len;
}


void
ngx_http_repsheet_store_lookup_ip(ngx_http_repsheet_store_t *store, const rs_ip_t *ip,
    ngx_http_repsheet_verdict_t *v, ngx_pool_t *pool)
{
    ngx_http_repsheet_shctx_t  *sh = store->sh;
    uint32_t                   *counts;
    int64_t                     now = ngx_http_repsheet_now_ms();
    u_char                      key[RS_IP_KEY_MAX];
    size_t                      len;
    rs_ip_t                     net;
    int                         prefix;

    counts = ip->family == 4 ? sh->v4_prefixes : sh->v6_prefixes;

    ngx_rwlock_rlock(&sh->lock);

    /* Most specific first, so it wins ties between equal statuses. */
    for (prefix = ip->prefix; prefix >= 0; prefix--) {
        if (counts[prefix] == 0) {
            continue;
        }

        net = *ip;
        rs_ip_mask(&net, (uint8_t) prefix);
        len = rs_ip_key(&net, key);
        consider(find_entry(sh, key, len), now, v, pool);
    }

    ngx_rwlock_unlock(&sh->lock);
}


void
ngx_http_repsheet_store_lookup_key(ngx_http_repsheet_store_t *store, u_char *key, size_t len,
    ngx_http_repsheet_verdict_t *v, ngx_pool_t *pool)
{
    int64_t now = ngx_http_repsheet_now_ms();

    ngx_rwlock_rlock(&store->sh->lock);
    consider(find_entry(store->sh, key, len), now, v, pool);
    ngx_rwlock_unlock(&store->sh->lock);
}


ngx_int_t
ngx_http_repsheet_store_set(ngx_http_repsheet_store_t *store, ngx_str_t *actor,
    rs_status_t status, ngx_str_t *reason, int64_t expires, ngx_log_t *log)
{
    ngx_http_repsheet_shctx_t  *sh = store->sh;
    ngx_http_repsheet_entry_t  *e;
    u_char                      canonical[RS_ACTOR_MAX + 1];
    u_char                      ipkey[RS_IP_KEY_MAX];
    u_char                     *key, *p;
    size_t                      actor_len, key_len, reason_len;
    rs_ip_t                     ip;
    const char                 *err = NULL;
    uint32_t                   *counter;

    actor_len = rs_actor_canonicalize((const char *) actor->data, actor->len,
                                      (char *) canonical, sizeof(canonical), &ip, &err);
    if (actor_len == 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0, "repsheet: ignoring invalid actor \"%V\": %s",
                      actor, err);
        return NGX_DECLINED;
    }

    reason_len = ngx_min(reason->len, RS_REASON_MAX);

    if (ip.family) {
        key_len = rs_ip_key(&ip, ipkey);
        key = ipkey;
    } else {
        key_len = actor_len;
        key = canonical;
    }

    ngx_rwlock_wlock(&sh->lock);

    e = find_entry(sh, key, key_len);
    if (e) {
        remove_entry(store, e);
    }

    e = ngx_slab_alloc(store->shpool, offsetof(ngx_http_repsheet_entry_t, data)
                       + (ip.family ? key_len : 0) + actor_len + reason_len);
    if (e == NULL) {
        ngx_rwlock_unlock(&sh->lock);
        (void) ngx_atomic_fetch_add(&sh->counters.alloc_failures, 1);
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "repsheet: zone is full, could not store decision for \"%s\"; "
                      "increase repsheet_zone_size", canonical);
        return NGX_ERROR;
    }

    e->generation = sh->generation;
    e->expires = expires;
    e->status = (uint8_t) status;
    e->family = ip.family;
    e->prefix = ip.prefix;
    e->actor_len = (u_short) actor_len;
    e->reason_len = (u_short) reason_len;

    p = e->data;
    if (ip.family) {
        p = ngx_cpymem(p, key, key_len);
    }
    e->sn.str.data = ip.family ? e->data : p;
    e->sn.str.len = key_len;
    p = ngx_cpymem(p, canonical, actor_len);
    ngx_memcpy(p, reason->data, reason_len);

    e->sn.node.key = ngx_murmur_hash2(key, key_len);
    ngx_rbtree_insert(&sh->rbtree, &e->sn.node);
    ngx_queue_insert_tail(&sh->entries, &e->queue);
    sh->count++;

    counter = prefix_counter(sh, e);
    if (counter) {
        (*counter)++;
    }

    ngx_rwlock_unlock(&sh->lock);
    return NGX_OK;
}


void
ngx_http_repsheet_store_delete(ngx_http_repsheet_store_t *store, ngx_str_t *actor)
{
    ngx_http_repsheet_entry_t  *e;
    u_char                      canonical[RS_ACTOR_MAX + 1];
    u_char                      ipkey[RS_IP_KEY_MAX];
    size_t                      len;
    rs_ip_t                     ip;
    const char                 *err;

    len = rs_actor_canonicalize((const char *) actor->data, actor->len, (char *) canonical,
                                sizeof(canonical), &ip, &err);
    if (len == 0) {
        return;
    }

    ngx_rwlock_wlock(&store->sh->lock);

    e = ip.family ? find_entry(store->sh, ipkey, rs_ip_key(&ip, ipkey))
                  : find_entry(store->sh, canonical, len);
    if (e) {
        remove_entry(store, e);
    }

    ngx_rwlock_unlock(&store->sh->lock);
}


uint64_t
ngx_http_repsheet_store_begin_snapshot(ngx_http_repsheet_store_t *store)
{
    uint64_t generation;

    ngx_rwlock_wlock(&store->sh->lock);
    generation = ++store->sh->generation;
    ngx_rwlock_unlock(&store->sh->lock);

    return generation;
}


static void
sweep(ngx_http_repsheet_store_t *store, uint64_t generation, int64_t now)
{
    ngx_queue_t                *q, *next;
    ngx_http_repsheet_entry_t  *e;

    ngx_rwlock_wlock(&store->sh->lock);

    for (q = ngx_queue_head(&store->sh->entries);
         q != ngx_queue_sentinel(&store->sh->entries);
         q = next)
    {
        next = ngx_queue_next(q);
        e = ngx_queue_data(q, ngx_http_repsheet_entry_t, queue);

        if ((generation && e->generation != generation)
            || (now && e->expires && e->expires <= now))
        {
            remove_entry(store, e);
        }
    }

    ngx_rwlock_unlock(&store->sh->lock);
}


/* Remove everything the snapshot did not mention. */
void
ngx_http_repsheet_store_end_snapshot(ngx_http_repsheet_store_t *store, uint64_t generation)
{
    sweep(store, generation, 0);
}


void
ngx_http_repsheet_store_expire(ngx_http_repsheet_store_t *store)
{
    sweep(store, 0, ngx_http_repsheet_now_ms());
}

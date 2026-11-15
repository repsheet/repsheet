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
 * each prefix length in use and probes the tree.
 *
 * Most of those probes miss, and a tree probe costs ~15 scattered memory
 * reads, so each prefix length also has a 16,384-bit filter: a decision sets
 * the bit for a hash of its network, and a lookup only probes the tree when
 * the bit for the client's masked address is set. A set bit can be stale or
 * shared (the tree has the final say); a clear bit is always right.
 *
 * Housekeeping never holds the write lock for long: a background sweep walks
 * the entries a slice at a time (ngx_http_repsheet_store_sweep_step), freeing
 * expired decisions (reads already ignore them) and, after a snapshot,
 * decisions the snapshot did not contain. Each pass also refills a second set
 * of filters from the entries it keeps and swaps it in at the end, which
 * clears the bits of removed decisions.
 */
#include "ngx_http_repsheet_module.h"

#define FILTER_BITS_LOG 14
#define FILTER_BYTES (1 << (FILTER_BITS_LOG - 3))
#define FILTER_SLOTS (33 + 129)     /* IPv4 /0-/32, IPv6 /0-/128 */

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

    /* 2 x ~324 KB. Without them (a very small zone) lookups just probe the tree. */
    sh->filters = ngx_slab_calloc(shpool, FILTER_SLOTS * FILTER_BYTES);
    sh->filters_next = sh->filters ? ngx_slab_calloc(shpool, FILTER_SLOTS * FILTER_BYTES) : NULL;
    if (sh->filters_next == NULL && sh->filters) {
        ngx_slab_free(shpool, sh->filters);
        sh->filters = NULL;
    }

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


/* The filter bit of a masked network: Fibonacci hashing of its address. */
static ngx_inline u_char *
filter_byte(u_char *filters, const rs_ip_t *net, u_char *mask)
{
    const uint8_t  *a = net->addr;
    uint64_t        h, hi, lo;
    ngx_uint_t      bit, slot;

    if (net->family == 4) {
        h = (uint64_t) (((uint32_t) a[0] << 24) | ((uint32_t) a[1] << 16) | ((uint32_t) a[2] << 8) | a[3])
            * 0x9e3779b97f4a7c15ULL;
        slot = net->prefix;
    } else {
        hi = ((uint64_t) a[0] << 56) | ((uint64_t) a[1] << 48) | ((uint64_t) a[2] << 40) | ((uint64_t) a[3] << 32)
             | ((uint64_t) a[4] << 24) | ((uint64_t) a[5] << 16) | ((uint64_t) a[6] << 8) | a[7];
        lo = ((uint64_t) a[8] << 56) | ((uint64_t) a[9] << 48) | ((uint64_t) a[10] << 40) | ((uint64_t) a[11] << 32)
             | ((uint64_t) a[12] << 24) | ((uint64_t) a[13] << 16) | ((uint64_t) a[14] << 8) | a[15];
        h = (hi * 0x9e3779b97f4a7c15ULL) ^ (lo * 0xc2b2ae3d27d4eb4fULL);
        h = (h ^ (h >> 29)) * 0xbf58476d1ce4e5b9ULL;
        slot = 33 + net->prefix;
    }

    bit = (ngx_uint_t) (h >> (64 - FILTER_BITS_LOG));
    *mask = (u_char) (1 << (bit & 7));
    return filters + slot * FILTER_BYTES + (bit >> 3);
}


/* Into the live filters and the ones the current sweep pass is building. */
static void
filter_add(ngx_http_repsheet_shctx_t *sh, const rs_ip_t *net)
{
    u_char  mask, *b;

    if (sh->filters) {
        b = filter_byte(sh->filters, net, &mask);
        *b |= mask;
        b = filter_byte(sh->filters_next, net, &mask);
        *b |= mask;
    }
}


/* An IP entry's network, from its lookup key ('I', family, prefix, address). */
static void
entry_network(ngx_http_repsheet_entry_t *e, rs_ip_t *net)
{
    ngx_memzero(net, sizeof(rs_ip_t));
    net->family = e->family;
    net->prefix = e->prefix;
    ngx_memcpy(net->addr, e->data + 3, e->family == 4 ? 4 : 16);
}


static void
remove_entry(ngx_http_repsheet_store_t *store, ngx_http_repsheet_entry_t *e)
{
    uint32_t *counter = prefix_counter(store->sh, e);

    if (counter) {
        (*counter)--;
    }

    /* Keep the sweep's cursor off freed memory. */
    if (store->sh->cursor == &e->queue) {
        store->sh->cursor = ngx_queue_next(&e->queue);
    }

    ngx_rbtree_delete(&store->sh->rbtree, &e->sn.node);
    ngx_queue_remove(&e->queue);
    store->sh->count--;
    ngx_slab_free(store->shpool, e);
}


/*
 * FNV-1a. nginx's murmur hash shifts signed ints and trips UBSan on bytes
 * >= 0x80, which every IPv4 key above 127.x contains.
 */
static uint32_t
key_hash(u_char *key, size_t len)
{
    uint32_t  h = 2166136261u;

    while (len--) {
        h ^= *key++;
        h *= 16777619u;
    }

    return h;
}


static ngx_http_repsheet_entry_t *
find_entry(ngx_http_repsheet_shctx_t *sh, u_char *key, size_t len)
{
    ngx_str_t  name = { len, key };
    uint32_t   hash = key_hash(key, len);

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
    u_char                      key[RS_IP_KEY_MAX], mask, *b;
    size_t                      len;
    rs_ip_t                     net = *ip;
    int                         prefix;

    counts = ip->family == 4 ? sh->v4_prefixes : sh->v6_prefixes;

    ngx_rwlock_rlock(&sh->lock);

    /* Most specific first, so it wins ties between equal statuses. Masking
     * the already-masked address to a shorter prefix is the same as masking
     * the original. */
    for (prefix = ip->prefix; prefix >= 0; prefix--) {
        if (counts[prefix] == 0) {
            continue;
        }

        rs_ip_mask(&net, (uint8_t) prefix);

        if (sh->filters) {
            b = filter_byte(sh->filters, &net, &mask);
            if (!(*b & mask)) {
                continue;   /* no decision for this network */
            }
        }

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

    e->sn.node.key = key_hash(key, key_len);
    ngx_rbtree_insert(&sh->rbtree, &e->sn.node);
    ngx_queue_insert_tail(&sh->entries, &e->queue);
    sh->count++;

    counter = prefix_counter(sh, e);
    if (counter) {
        (*counter)++;
        filter_add(sh, &ip);
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
    /* Entries are being reloaded: do not drop any for being "old" meanwhile. */
    store->sh->sweep_generation = 0;
    ngx_rwlock_unlock(&store->sh->lock);

    return generation;
}


/*
 * The snapshot is complete: everything it did not mention (an older
 * generation) goes. The sweep does it in slices, starting a fresh pass so it
 * covers every entry; lookups keep working meanwhile.
 */
void
ngx_http_repsheet_store_end_snapshot(ngx_http_repsheet_store_t *store, uint64_t generation)
{
    ngx_http_repsheet_shctx_t *sh = store->sh;

    ngx_rwlock_wlock(&sh->lock);
    sh->sweep_generation = generation;
    sh->cursor = NULL;
    if (sh->filters_next) {
        ngx_memzero(sh->filters_next, FILTER_SLOTS * FILTER_BYTES);
    }
    ngx_rwlock_unlock(&sh->lock);
}


ngx_flag_t
ngx_http_repsheet_store_sweep_pending(ngx_http_repsheet_store_t *store)
{
    return store->sh->sweep_generation != 0;
}


/*
 * One slice of the background sweep: visit up to `budget` entries from where
 * the last slice stopped, freeing expired ones and, after a snapshot, ones of
 * an older generation. Returns 1 when the pass reached the end (the rebuilt
 * filters are then swapped in and the next pass starts from the beginning).
 */
ngx_int_t
ngx_http_repsheet_store_sweep_step(ngx_http_repsheet_store_t *store, ngx_uint_t budget)
{
    ngx_http_repsheet_shctx_t  *sh = store->sh;
    ngx_http_repsheet_entry_t  *e;
    ngx_queue_t                *q, *next;
    ngx_uint_t                  n;
    int64_t                     now = ngx_http_repsheet_now_ms();
    rs_ip_t                     net;
    u_char                     *swap;
    ngx_int_t                   done = 0;

    ngx_rwlock_wlock(&sh->lock);

    q = sh->cursor ? sh->cursor : ngx_queue_head(&sh->entries);
    for (n = 0; n < budget && q != ngx_queue_sentinel(&sh->entries); n++, q = next) {
        next = ngx_queue_next(q);
        e = ngx_queue_data(q, ngx_http_repsheet_entry_t, queue);

        if ((e->expires && e->expires <= now)
            || (sh->sweep_generation && e->generation != sh->sweep_generation))
        {
            remove_entry(store, e);
            continue;
        }
        if (e->family && sh->filters_next) {
            entry_network(e, &net);
            filter_add(sh, &net);   /* sets it in both; only the next set matters here */
        }
    }

    if (q == ngx_queue_sentinel(&sh->entries)) {
        if (sh->filters) {
            swap = sh->filters;
            sh->filters = sh->filters_next;
            sh->filters_next = swap;
            ngx_memzero(sh->filters_next, FILTER_SLOTS * FILTER_BYTES);
        }
        sh->cursor = NULL;
        sh->sweep_generation = 0;
        done = 1;
    } else {
        sh->cursor = q;
    }

    ngx_rwlock_unlock(&sh->lock);
    return done;
}

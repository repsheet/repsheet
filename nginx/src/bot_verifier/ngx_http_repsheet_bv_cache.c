/*
 * Shared-memory cache of verification results, keyed by client address.
 * Entries expire by TTL; when the zone is full the least recently used
 * entries are evicted. The zone survives `nginx -s reload`.
 */
#include "ngx_http_repsheet_bv.h"

typedef struct {
    ngx_rbtree_node_t  node;    /* key: hash of addr */
    ngx_queue_t        queue;   /* LRU, most recent at the head */
    time_t             expires;
    uint32_t           provider;  /* hash of the provider name: survives reloads */
    u_char             result;
    bv_addr_t          addr;
} bv_entry_t;


static uint32_t
bv_provider_hash(ngx_uint_t index)
{
    bv_main_conf_t  *mcf = bv_main_conf();
    bv_provider_t   *p = mcf->providers.elts;

    return ngx_crc32_short(p[index].name.data, p[index].name.len);
}


/* Index of the provider with this name hash, or -1 if it no longer exists. */
static ngx_int_t
bv_provider_index(uint32_t hash)
{
    bv_main_conf_t  *mcf = bv_main_conf();
    bv_provider_t   *p = mcf->providers.elts;
    ngx_uint_t       i;

    for (i = 0; i < mcf->providers.nelts; i++) {
        if (ngx_crc32_short(p[i].name.data, p[i].name.len) == hash) {
            return (ngx_int_t) i;
        }
    }
    return -1;
}


static uint32_t
bv_hash(bv_addr_t *a)
{
    uint32_t    h = 2166136261u;
    size_t      i, n = a->family == AF_INET ? 4 : 16;

    h = (h ^ a->family) * 16777619u;
    for (i = 0; i < n; i++) {
        h = (h ^ a->addr[i]) * 16777619u;
    }
    return h;
}


static ngx_int_t
bv_addr_cmp(bv_addr_t *a, bv_addr_t *b)
{
    if (a->family != b->family) {
        return (ngx_int_t) a->family - (ngx_int_t) b->family;
    }
    return ngx_memcmp(a->addr, b->addr, a->family == AF_INET ? 4 : 16);
}


static void
bv_rbtree_insert(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t  **p;
    bv_entry_t          *n, *t;

    for (;;) {
        if (node->key < temp->key) {
            p = &temp->left;
        } else if (node->key > temp->key) {
            p = &temp->right;
        } else {
            n = (bv_entry_t *) node;
            t = (bv_entry_t *) temp;
            p = bv_addr_cmp(&n->addr, &t->addr) < 0 ? &temp->left : &temp->right;
        }
        if (*p == sentinel) {
            break;
        }
        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static bv_entry_t *
bv_find(bv_shctx_t *sh, bv_addr_t *addr, uint32_t hash)
{
    ngx_rbtree_node_t  *node = sh->rbtree.root, *sentinel = sh->rbtree.sentinel;
    bv_entry_t         *e;
    ngx_int_t           rc;

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }
        if (hash > node->key) {
            node = node->right;
            continue;
        }
        e = (bv_entry_t *) node;
        rc = bv_addr_cmp(addr, &e->addr);
        if (rc == 0) {
            return e;
        }
        node = rc < 0 ? node->left : node->right;
    }
    return NULL;
}


static void
bv_remove(bv_cache_t *cache, bv_entry_t *e)
{
    ngx_queue_remove(&e->queue);
    ngx_rbtree_delete(&cache->sh->rbtree, &e->node);
    ngx_slab_free_locked(cache->shpool, e);
    cache->sh->count--;
}


ngx_flag_t
bv_cache_get(bv_cache_t *cache, bv_addr_t *addr, bv_verdict_t *out)
{
    bv_entry_t  *e;
    ngx_flag_t   found = 0;
    ngx_int_t    index;

    ngx_shmtx_lock(&cache->shpool->mutex);

    e = bv_find(cache->sh, addr, bv_hash(addr));
    if (e) {
        index = bv_provider_index(e->provider);
        if (e->expires <= ngx_time() || index < 0) {
            bv_remove(cache, e);
        } else {
            out->result = e->result;
            out->provider = (ngx_uint_t) index;
            ngx_queue_remove(&e->queue);
            ngx_queue_insert_head(&cache->sh->lru, &e->queue);
            found = 1;
        }
    }

    ngx_shmtx_unlock(&cache->shpool->mutex);
    return found;
}


void
bv_cache_put(bv_cache_t *cache, bv_addr_t *addr, bv_verdict_t *v, time_t ttl)
{
    bv_entry_t   *e;
    ngx_queue_t  *q;
    uint32_t      hash = bv_hash(addr);
    ngx_uint_t    i, evicted = 0;
    time_t        now = ngx_time();

    if (ttl <= 0) {
        return;
    }

    ngx_shmtx_lock(&cache->shpool->mutex);

    e = bv_find(cache->sh, addr, hash);
    if (e == NULL) {
        e = ngx_slab_alloc_locked(cache->shpool, sizeof(bv_entry_t));
        for (i = 0; e == NULL && i < 3; i++) {
            /* Full: evict up to 32 entries from the cold end, then retry. */
            for (evicted = 0; evicted < 32 && !ngx_queue_empty(&cache->sh->lru); evicted++) {
                q = ngx_queue_last(&cache->sh->lru);
                bv_remove(cache, ngx_queue_data(q, bv_entry_t, queue));
            }
            (void) ngx_atomic_fetch_add(&cache->sh->counters.evictions, evicted);
            e = ngx_slab_alloc_locked(cache->shpool, sizeof(bv_entry_t));
        }
        if (e == NULL) {
            ngx_shmtx_unlock(&cache->shpool->mutex);
            return;
        }
        ngx_memzero(e, sizeof(bv_entry_t));
        e->addr = *addr;
        e->node.key = hash;
        ngx_rbtree_insert(&cache->sh->rbtree, &e->node);
        ngx_queue_insert_head(&cache->sh->lru, &e->queue);
        cache->sh->count++;
    } else {
        ngx_queue_remove(&e->queue);
        ngx_queue_insert_head(&cache->sh->lru, &e->queue);
    }

    e->result = (u_char) v->result;
    e->provider = bv_provider_hash(v->provider);
    e->expires = now + ttl;

    /* Opportunistically drop a couple of expired entries from the cold end. */
    for (i = 0; i < 2 && !ngx_queue_empty(&cache->sh->lru); i++) {
        q = ngx_queue_last(&cache->sh->lru);
        e = ngx_queue_data(q, bv_entry_t, queue);
        if (e->expires > now) {
            break;
        }
        bv_remove(cache, e);
    }

    ngx_shmtx_unlock(&cache->shpool->mutex);
}


ngx_int_t
bv_cache_init_zone(ngx_shm_zone_t *zone, void *data)
{
    bv_cache_t  *old = data, *cache = zone->data;

    if (old) {
        /* Reload: keep the cached results. */
        cache->sh = old->sh;
        cache->shpool = old->shpool;
        return NGX_OK;
    }

    cache->shpool = (ngx_slab_pool_t *) zone->shm.addr;

    if (zone->shm.exists) {
        cache->sh = cache->shpool->data;
        return NGX_OK;
    }

    cache->sh = ngx_slab_calloc(cache->shpool, sizeof(bv_shctx_t));
    if (cache->sh == NULL) {
        return NGX_ERROR;
    }
    cache->shpool->data = cache->sh;

    ngx_rbtree_init(&cache->sh->rbtree, &cache->sh->sentinel, bv_rbtree_insert);
    ngx_queue_init(&cache->sh->lru);

    cache->shpool->log_nomem = 0;
    cache->shpool->log_ctx = ngx_slab_alloc(cache->shpool, sizeof(" in repsheet_bot_verifier zone \"\"") + zone->shm.name.len);
    if (cache->shpool->log_ctx) {
        ngx_sprintf(cache->shpool->log_ctx, " in repsheet_bot_verifier zone \"%V\"%Z", &zone->shm.name);
    }
    return NGX_OK;
}

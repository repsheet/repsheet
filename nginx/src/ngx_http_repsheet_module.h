#ifndef NGX_HTTP_REPSHEET_MODULE_H
#define NGX_HTTP_REPSHEET_MODULE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "repsheet_actor.h"
#include "ngx_http_repsheet_public.h"

#define NGX_HTTP_REPSHEET_OFF 0
#define NGX_HTTP_REPSHEET_ON 1
#define NGX_HTTP_REPSHEET_MONITOR 2

/* Counters live in shared memory and are exported by repsheet_metrics. */
typedef struct {
    ngx_atomic_t requests[RS_STATUS_ALLOW + 1]; /* indexed by rs_status_t */
    ngx_atomic_t blocked;                       /* requests actually rejected */
    ngx_atomic_t snapshots;
    ngx_atomic_t changes;
    ngx_atomic_t sync_errors;
    ngx_atomic_t alloc_failures;
    ngx_atomic_t detector_decisions;            /* recorded by active detectors */
    ngx_atomic_t detector_redis_errors;
} ngx_http_repsheet_counters_t;

typedef struct {
    ngx_rbtree_t                 rbtree;
    ngx_rbtree_node_t            sentinel;
    ngx_queue_t                  entries;
    ngx_atomic_t                 lock;          /* ngx_rwlock */
    ngx_uint_t                   count;
    uint32_t                     v4_prefixes[33];
    uint32_t                     v6_prefixes[129];
    uint64_t                     generation;

    /* Sync state, owned by one worker at a time. */
    ngx_pid_t                    owner;
    u_char                       epoch[17];
    int64_t                      seq;
    ngx_flag_t                   synced;
    int64_t                      last_sync;     /* ms since epoch */

    ngx_http_repsheet_counters_t counters;
} ngx_http_repsheet_shctx_t;

typedef struct {
    ngx_http_repsheet_shctx_t   *sh;
    ngx_slab_pool_t             *shpool;
} ngx_http_repsheet_store_t;

typedef struct {
    ngx_http_repsheet_redis_conf_t  redis;     /* must stay first: read by other modules */
    ngx_msec_t                   timeout;
    ngx_msec_t                   interval;
    size_t                       zone_size;
    ngx_shm_zone_t              *zone;
    ngx_flag_t                   detectors;     /* an active detector is enabled */
} ngx_http_repsheet_main_conf_t;

typedef struct {
    ngx_str_t                    type;
    ngx_http_complex_value_t     value;
} ngx_http_repsheet_actor_conf_t;

typedef struct {
    ngx_uint_t                   mode;
    ngx_uint_t                   block_status;
    ngx_array_t                 *actors;        /* ngx_http_repsheet_actor_conf_t */
} ngx_http_repsheet_loc_conf_t;

typedef struct {
    rs_status_t                  status;
    ngx_str_t                    reason;
    ngx_str_t                    actor;
    ngx_flag_t                   counted;       /* in repsheet_requests_total */
} ngx_http_repsheet_verdict_t;

extern ngx_module_t ngx_http_repsheet_module;

/* store.c */
ngx_int_t ngx_http_repsheet_store_init_zone(ngx_shm_zone_t *zone, void *data);
int64_t ngx_http_repsheet_now_ms(void);
void ngx_http_repsheet_store_lookup_ip(ngx_http_repsheet_store_t *store, const rs_ip_t *ip,
    ngx_http_repsheet_verdict_t *v, ngx_pool_t *pool);
void ngx_http_repsheet_store_lookup_key(ngx_http_repsheet_store_t *store, u_char *key, size_t len,
    ngx_http_repsheet_verdict_t *v, ngx_pool_t *pool);
ngx_int_t ngx_http_repsheet_store_set(ngx_http_repsheet_store_t *store, ngx_str_t *actor,
    rs_status_t status, ngx_str_t *reason, int64_t expires, ngx_log_t *log);
void ngx_http_repsheet_store_delete(ngx_http_repsheet_store_t *store, ngx_str_t *actor);
uint64_t ngx_http_repsheet_store_begin_snapshot(ngx_http_repsheet_store_t *store);
void ngx_http_repsheet_store_end_snapshot(ngx_http_repsheet_store_t *store, uint64_t generation);
void ngx_http_repsheet_store_expire(ngx_http_repsheet_store_t *store);

/* redis.c: record an active detector's decision (local store + Valkey) */
ngx_int_t ngx_http_repsheet_record(ngx_str_t *actor, rs_status_t status, ngx_str_t *reason, time_t ttl,
    const char *by, ngx_log_t *log);

/* sync.c */
ngx_int_t ngx_http_repsheet_sync_init_process(ngx_cycle_t *cycle);
void ngx_http_repsheet_sync_exit_process(ngx_cycle_t *cycle);

#endif

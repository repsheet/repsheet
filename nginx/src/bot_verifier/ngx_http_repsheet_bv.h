/*
 * Bot verifier: an active detector in the Repsheet nginx module.
 *
 * A request whose User-Agent claims to be a known crawler is verified once
 * per address: by the provider's published IP ranges, or by a reverse DNS
 * lookup whose name must fall under one of the provider's domains followed by
 * a forward lookup that must return the client address. Lookups use nginx's
 * asynchronous resolver; results are cached in shared memory and in
 * Valkey/Redis so a fleet of nginx servers shares them.
 *
 * A failed verification becomes a Repsheet decision (block or mark, with a
 * TTL, BY bot_verifier) through ngx_http_repsheet_record().
 */
#ifndef NGX_HTTP_REPSHEET_BV_H
#define NGX_HTTP_REPSHEET_BV_H

#include "ngx_http_repsheet_module.h"

#define BV_DETECTOR "bot_verifier"
#define BV_MAX_PROVIDERS 64
#define BV_MAX_INFLIGHT 1024 /* concurrent lookups per worker */
#define BV_REASON_MAX 192

/* Lookup duration histogram (seconds): Prometheus "le" bounds, in ms. */
#define BV_BUCKETS 11
#define BV_BUCKET_BOUNDS_MS { 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000 }
#define BV_TIMED_REDIS 0
#define BV_TIMED_DNS 1

typedef enum {
    BV_OFF = 0,
    BV_ON,
    BV_MONITOR,
} bv_mode_e;

typedef enum {
    BV_NONE = 0,     /* not checked: no crawler claim */
    BV_VERIFIED,
    BV_FAILED,
    BV_UNKNOWN,      /* could not verify (DNS error, timeout, no data) */
} bv_result_e;

typedef enum {
    BV_SRC_NONE = 0,
    BV_SRC_ZONE,
    BV_SRC_RANGES,
    BV_SRC_REDIS,
    BV_SRC_DNS,
} bv_source_e;

/* An address, v4-mapped IPv6 folded to IPv4. */
typedef struct {
    u_char  family;     /* AF_INET or AF_INET6 */
    u_char  addr[16];
} bv_addr_t;

typedef struct {
    ngx_str_t     name;
    ngx_uint_t    index;
    ngx_regex_t  *user_agent;
    ngx_str_t     user_agent_src;
    ngx_uint_t    user_agent_captures;  /* groups in its own pattern */
    ngx_uint_t    group;                /* its group in the combined pattern */
    ngx_array_t  *domains;      /* ngx_str_t, lowercase, no leading dot */
    ngx_array_t  *range_files;  /* ngx_str_t */
    ngx_array_t  *ranges;       /* ngx_cidr_t, loaded from range_files */
} bv_provider_t;

typedef struct {
    ngx_atomic_t  requests[4];      /* by bv_result_e */
    ngx_atomic_t  hits[5];          /* by bv_source_e */
    ngx_atomic_t  dns_lookups;
    ngx_atomic_t  dns_errors;
    ngx_atomic_t  decisions;        /* decisions recorded in Repsheet */
    ngx_atomic_t  evictions;
    /* lookups answered by Redis or DNS: duration histogram, sum (ms), count */
    ngx_atomic_t  duration_buckets[2][BV_BUCKETS];
    ngx_atomic_t  duration_sum_ms[2];
    ngx_atomic_t  duration_count[2];
} bv_counters_t;

typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
    ngx_queue_t        lru;
    ngx_uint_t         count;
    bv_counters_t      counters;
} bv_shctx_t;

typedef struct {
    bv_shctx_t       *sh;
    ngx_slab_pool_t  *shpool;
} bv_cache_t;

typedef struct {
    bv_result_e   result;
    ngx_uint_t    provider;     /* index; meaningful for every result */
} bv_verdict_t;

typedef struct {
    ngx_array_t      providers;         /* bv_provider_t */
    /* All providers' User-Agent patterns as one, JIT-compiled (PCRE2). */
    void            *user_agents;       /* pcre2_code */
    void            *match_data;        /* pcre2_match_data */
    ngx_shm_zone_t  *zone;
    size_t           zone_size;
    time_t           ttl[4];            /* by bv_result_e */
    ngx_msec_t       cache_timeout;     /* bounded wait for the Redis cache */
    rs_status_t      action;            /* RS_STATUS_BLOCK or RS_STATUS_MARK */
    time_t           action_ttl;
    ngx_flag_t       used;              /* repsheet_bot_verifier on somewhere */
} bv_main_conf_t;

typedef struct {
    ngx_uint_t   mode;
    ngx_msec_t   timeout;
} bv_loc_conf_t;

/* Per-request state. */
typedef struct {
    bv_verdict_t           verdict;
    bv_source_e            source;
    ngx_flag_t             evaluated;
    ngx_flag_t             waiting;
    ngx_flag_t             starting;   /* inside bv_verify: do not resume */
    ngx_flag_t             counted;
    ngx_msec_t             started;    /* when the request began waiting */
    ngx_msec_t             waited;     /* ms spent waiting for a lookup */
    ngx_queue_t            wait;       /* in the lookup's waiters */
    ngx_http_request_t    *request;
    bv_addr_t              addr;
    ngx_str_t              reason;     /* why it failed, when known */
} bv_ctx_t;

extern ngx_module_t ngx_http_repsheet_bot_verifier_module;

/* Called by the repsheet handler; see ngx_http_repsheet_bv_module.c. */
ngx_int_t ngx_http_repsheet_bot_verifier_check(ngx_http_request_t *r, ngx_http_repsheet_verdict_t *v);
ngx_chain_t *ngx_http_repsheet_bot_verifier_metrics(ngx_http_request_t *r);

/* providers.c */
char *bv_providers_add_builtin(ngx_conf_t *cf, bv_main_conf_t *mcf);
char *bv_provider_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *bv_providers_load_ranges(ngx_conf_t *cf, bv_main_conf_t *mcf);
char *bv_providers_compile(ngx_conf_t *cf, bv_main_conf_t *mcf);
bv_provider_t *bv_provider_for_user_agent(bv_main_conf_t *mcf, ngx_str_t *ua);
char *bv_ranges_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
ngx_flag_t bv_domain_matches(bv_provider_t *p, ngx_str_t *host);

/* cache.c */
ngx_int_t bv_cache_init_zone(ngx_shm_zone_t *zone, void *data);
ngx_flag_t bv_cache_get(bv_cache_t *cache, bv_addr_t *addr, bv_verdict_t *out);
void bv_cache_put(bv_cache_t *cache, bv_addr_t *addr, bv_verdict_t *v, time_t ttl);

/* verify.c */
void bv_ctx_cleanup(void *data);
ngx_int_t bv_verify(ngx_http_request_t *r, bv_ctx_t *ctx, bv_provider_t *provider,
    bv_addr_t *addr, struct sockaddr *sa, socklen_t socklen);
ngx_int_t bv_verify_init_process(ngx_cycle_t *cycle);
void bv_verify_exit_process(ngx_cycle_t *cycle);

/* helpers (module.c) */
size_t bv_addr_format(bv_addr_t *addr, u_char *buf, size_t len);
bv_cache_t *bv_cache(void);
bv_main_conf_t *bv_main_conf(void);
const char *bv_result_name(bv_result_e r);

#endif

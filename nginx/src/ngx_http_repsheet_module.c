/*
 * Repsheet for nginx: enforce reputation decisions held in Valkey/Redis.
 *
 * Decisions are mirrored into shared memory by a background sync loop (see
 * ngx_http_repsheet_sync.c), so evaluating a request is a local lookup that
 * never blocks on the network.
 */
#include "ngx_http_repsheet_module.h"

#define DEFAULT_ZONE_SIZE (32 * 1024 * 1024)

typedef struct {
    ngx_http_repsheet_verdict_t  verdict;
} ngx_http_repsheet_ctx_t;

static ngx_int_t ngx_http_repsheet_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_repsheet_init(ngx_conf_t *cf);
static void *ngx_http_repsheet_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_repsheet_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_repsheet_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_repsheet_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_repsheet_redis(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_repsheet_redis_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_repsheet_actor(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_repsheet_metrics(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_repsheet_init_process(ngx_cycle_t *cycle);
static void ngx_http_repsheet_exit_process(ngx_cycle_t *cycle);


static ngx_conf_enum_t ngx_http_repsheet_modes[] = {
    { ngx_string("off"), NGX_HTTP_REPSHEET_OFF },
    { ngx_string("on"), NGX_HTTP_REPSHEET_ON },
    { ngx_string("monitor"), NGX_HTTP_REPSHEET_MONITOR },
    { ngx_null_string, 0 }
};

static ngx_conf_num_bounds_t ngx_http_repsheet_status_bounds = {
    ngx_conf_check_num_bounds, 400, 599
};


static ngx_command_t ngx_http_repsheet_commands[] = {

    { ngx_string("repsheet"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_repsheet_loc_conf_t, mode),
      &ngx_http_repsheet_modes },

    { ngx_string("repsheet_redis"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_repsheet_redis,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("repsheet_redis_auth"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
      ngx_http_repsheet_redis_auth,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("repsheet_redis_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_repsheet_main_conf_t, timeout),
      NULL },

    { ngx_string("repsheet_sync_interval"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_repsheet_main_conf_t, interval),
      NULL },

    { ngx_string("repsheet_zone_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_repsheet_main_conf_t, zone_size),
      NULL },

    { ngx_string("repsheet_actor"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_repsheet_actor,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("repsheet_block_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_repsheet_loc_conf_t, block_status),
      &ngx_http_repsheet_status_bounds },

    { ngx_string("repsheet_metrics"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_repsheet_metrics,
      0,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_repsheet_module_ctx = {
    ngx_http_repsheet_add_variables,      /* preconfiguration */
    ngx_http_repsheet_init,               /* postconfiguration */
    ngx_http_repsheet_create_main_conf,   /* create main configuration */
    ngx_http_repsheet_init_main_conf,     /* init main configuration */
    NULL,                                 /* create server configuration */
    NULL,                                 /* merge server configuration */
    ngx_http_repsheet_create_loc_conf,    /* create location configuration */
    ngx_http_repsheet_merge_loc_conf      /* merge location configuration */
};


ngx_module_t ngx_http_repsheet_module = {
    NGX_MODULE_V1,
    &ngx_http_repsheet_module_ctx,        /* module context */
    ngx_http_repsheet_commands,           /* module directives */
    NGX_HTTP_MODULE,                      /* module type */
    NULL,                                 /* init master */
    NULL,                                 /* init module */
    ngx_http_repsheet_init_process,       /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    ngx_http_repsheet_exit_process,       /* exit process */
    NULL,                                 /* exit master */
    NGX_MODULE_V1_PADDING
};


/* ------------------------------------------------------------------------ */
/* evaluation                                                                */
/* ------------------------------------------------------------------------ */

static ngx_flag_t
ngx_http_repsheet_client_ip(ngx_http_request_t *r, rs_ip_t *ip)
{
    struct sockaddr *sa = r->connection->sockaddr;

    switch (sa->sa_family) {
    case AF_INET:
        rs_ip_from_bytes(ip, 4, (uint8_t *) &((struct sockaddr_in *) sa)->sin_addr);
        return 1;
#if (NGX_HAVE_INET6)
    case AF_INET6:
        rs_ip_from_bytes(ip, 6, (uint8_t *) &((struct sockaddr_in6 *) sa)->sin6_addr);
        return 1;
#endif
    default:
        return 0;
    }
}


static void
ngx_http_repsheet_lookup_actor(ngx_http_request_t *r, ngx_http_repsheet_store_t *store,
    ngx_http_repsheet_actor_conf_t *actor, ngx_http_repsheet_verdict_t *v)
{
    ngx_str_t  value;
    u_char     key[RS_ACTOR_MAX];
    u_char    *p;
    rs_ip_t    ip;
    size_t     i;

    if (ngx_http_complex_value(r, &actor->value, &value) != NGX_OK || value.len == 0) {
        return;
    }

    /* "repsheet_actor ip $http_x_client_ip" matches networks like the client address. */
    if (actor->type.len == 2 && ngx_strncmp(actor->type.data, "ip", 2) == 0) {
        /* Only a single address: "0.0.0.0/0" must not skip specific entries. */
        if (ngx_strlchr(value.data, value.data + value.len, '/') == NULL
            && rs_ip_parse((char *) value.data, value.len, &ip) == 0)
        {
            ngx_http_repsheet_store_lookup_ip(store, &ip, v, r->pool);
        }
        return;
    }

    if (actor->type.len + 1 + value.len > RS_ACTOR_MAX) {
        return;
    }

    for (i = 0; i < value.len; i++) {
        if (value.data[i] < 0x20 || value.data[i] == 0x7f) {
            return;
        }
    }

    p = ngx_cpymem(key, actor->type.data, actor->type.len);
    *p++ = ':';
    p = ngx_cpymem(p, value.data, value.len);

    ngx_http_repsheet_store_lookup_key(store, key, p - key, v, r->pool);
}


static ngx_http_repsheet_verdict_t *
ngx_http_repsheet_evaluate(ngx_http_request_t *r)
{
    ngx_http_repsheet_ctx_t         *ctx;
    ngx_http_repsheet_main_conf_t   *mcf;
    ngx_http_repsheet_loc_conf_t    *lcf;
    ngx_http_repsheet_store_t       *store;
    ngx_http_repsheet_actor_conf_t  *actors;
    rs_ip_t                          ip;
    ngx_uint_t                       i;

    ctx = ngx_http_get_module_ctx(r, ngx_http_repsheet_module);
    if (ctx) {
        return &ctx->verdict;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_repsheet_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }
    ngx_http_set_ctx(r, ctx, ngx_http_repsheet_module);

    mcf = ngx_http_get_module_main_conf(r, ngx_http_repsheet_module);
    if (mcf->zone == NULL) {
        return &ctx->verdict;
    }

    store = mcf->zone->data;
    if (store->sh == NULL) {
        return &ctx->verdict;
    }

    if (ngx_http_repsheet_client_ip(r, &ip)) {
        ngx_http_repsheet_store_lookup_ip(store, &ip, &ctx->verdict, r->pool);
    }

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_repsheet_module);
    if (lcf->actors) {
        actors = lcf->actors->elts;
        for (i = 0; i < lcf->actors->nelts; i++) {
            ngx_http_repsheet_lookup_actor(r, store, &actors[i], &ctx->verdict);
        }
    }

    return &ctx->verdict;
}


static ngx_int_t
ngx_http_repsheet_handler(ngx_http_request_t *r)
{
    ngx_http_repsheet_loc_conf_t   *lcf;
    ngx_http_repsheet_main_conf_t  *mcf;
    ngx_http_repsheet_verdict_t    *v;
    ngx_http_repsheet_store_t      *store;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_repsheet_module);
    if (lcf->mode == NGX_HTTP_REPSHEET_OFF) {
        return NGX_DECLINED;
    }

    mcf = ngx_http_get_module_main_conf(r, ngx_http_repsheet_module);
    if (mcf->zone == NULL) {
        return NGX_DECLINED;
    }

    v = ngx_http_repsheet_evaluate(r);
    if (v == NULL) {
        return NGX_DECLINED;
    }

    store = mcf->zone->data;

    /* Count each client request once, not again after internal redirects. */
    if (!r->internal) {
        (void) ngx_atomic_fetch_add(&store->sh->counters.requests[v->status], 1);
    }

    if (v->status != RS_STATUS_BLOCK) {
        return NGX_DECLINED;
    }

    if (lcf->mode == NGX_HTTP_REPSHEET_MONITOR) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "repsheet: would block request, actor \"%V\", reason \"%V\"",
                      &v->actor, &v->reason);
        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "repsheet: blocked request, actor \"%V\", reason \"%V\"",
                  &v->actor, &v->reason);

    if (!r->internal) {
        (void) ngx_atomic_fetch_add(&store->sh->counters.blocked, 1);
    }

    return lcf->block_status;
}


/* ------------------------------------------------------------------------ */
/* variables                                                                 */
/* ------------------------------------------------------------------------ */

enum { VAR_STATUS, VAR_REASON, VAR_ACTOR };

static ngx_int_t
ngx_http_repsheet_variable(ngx_http_request_t *r, ngx_http_variable_value_t *vv, uintptr_t data)
{
    ngx_http_repsheet_verdict_t  *v = ngx_http_repsheet_evaluate(r);
    ngx_str_t                     value = ngx_null_string;

    if (v == NULL) {
        return NGX_ERROR;
    }

    if (v->status != RS_STATUS_NONE) {
        switch (data) {
        case VAR_STATUS:
            value.data = (u_char *) rs_status_name(v->status);
            value.len = ngx_strlen(value.data);
            break;
        case VAR_REASON:
            value = v->reason;
            break;
        case VAR_ACTOR:
            value = v->actor;
            break;
        }
    }

    vv->data = value.data;
    vv->len = value.len;
    vv->valid = 1;
    vv->no_cacheable = 0;
    vv->not_found = 0;
    return NGX_OK;
}


static ngx_http_variable_t ngx_http_repsheet_vars[] = {
    { ngx_string("repsheet_status"), NULL, ngx_http_repsheet_variable, VAR_STATUS, 0, 0 },
    { ngx_string("repsheet_reason"), NULL, ngx_http_repsheet_variable, VAR_REASON, 0, 0 },
    { ngx_string("repsheet_actor"), NULL, ngx_http_repsheet_variable, VAR_ACTOR, 0, 0 },
    ngx_http_null_variable
};


static ngx_int_t
ngx_http_repsheet_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;

    for (v = ngx_http_repsheet_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }
        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


/* ------------------------------------------------------------------------ */
/* metrics                                                                   */
/* ------------------------------------------------------------------------ */

static ngx_int_t
ngx_http_repsheet_metrics_handler(ngx_http_request_t *r)
{
    ngx_http_repsheet_main_conf_t  *mcf;
    ngx_http_repsheet_store_t      *store;
    ngx_http_repsheet_shctx_t      *sh;
    ngx_buf_t                      *b;
    ngx_chain_t                     out;
    ngx_int_t                       rc;
    ngx_msec_t                      stale_after;
    int64_t                         now;
    ngx_flag_t                      ok;
    size_t                          size = 4096;
    rs_status_t                     s;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    mcf = ngx_http_get_module_main_conf(r, ngx_http_repsheet_module);
    if (mcf->zone == NULL || ((ngx_http_repsheet_store_t *) mcf->zone->data)->sh == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    store = mcf->zone->data;
    sh = store->sh;

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    now = ngx_http_repsheet_now_ms();
    stale_after = ngx_max(3 * mcf->interval, 3 * mcf->timeout);
    ok = sh->synced && now - sh->last_sync <= (int64_t) stale_after;

    b->last = ngx_slprintf(b->last, b->end,
        "# HELP repsheet_requests_total Requests evaluated, by decision.\n"
        "# TYPE repsheet_requests_total counter\n");
    for (s = RS_STATUS_NONE; s <= RS_STATUS_ALLOW; s++) {
        b->last = ngx_slprintf(b->last, b->end, "repsheet_requests_total{decision=\"%s\"} %uA\n",
                               rs_status_name(s), sh->counters.requests[s]);
    }

    b->last = ngx_slprintf(b->last, b->end,
        "# HELP repsheet_blocked_total Requests rejected (excludes monitor mode).\n"
        "# TYPE repsheet_blocked_total counter\n"
        "repsheet_blocked_total %uA\n"
        "# HELP repsheet_decisions Decisions held in shared memory.\n"
        "# TYPE repsheet_decisions gauge\n"
        "repsheet_decisions %ui\n"
        "# HELP repsheet_sync_up Whether decisions are in sync with the store.\n"
        "# TYPE repsheet_sync_up gauge\n"
        "repsheet_sync_up %d\n"
        "# HELP repsheet_sync_last_success_timestamp_seconds Last successful sync.\n"
        "# TYPE repsheet_sync_last_success_timestamp_seconds gauge\n"
        "repsheet_sync_last_success_timestamp_seconds %L.%03L\n"
        "# HELP repsheet_sync_seq Change log position.\n"
        "# TYPE repsheet_sync_seq gauge\n"
        "repsheet_sync_seq %L\n"
        "# TYPE repsheet_sync_snapshots_total counter\n"
        "repsheet_sync_snapshots_total %uA\n"
        "# TYPE repsheet_sync_changes_total counter\n"
        "repsheet_sync_changes_total %uA\n"
        "# TYPE repsheet_sync_errors_total counter\n"
        "repsheet_sync_errors_total %uA\n"
        "# HELP repsheet_zone_alloc_failures_total Decisions dropped because the zone was full.\n"
        "# TYPE repsheet_zone_alloc_failures_total counter\n"
        "repsheet_zone_alloc_failures_total %uA\n"
        "# TYPE repsheet_zone_size_bytes gauge\n"
        "repsheet_zone_size_bytes %uz\n"
        "# TYPE repsheet_zone_free_bytes gauge\n"
        "repsheet_zone_free_bytes %uz\n",
        sh->counters.blocked,
        sh->count,
        ok ? 1 : 0,
        sh->last_sync / 1000, sh->last_sync % 1000,
        sh->seq,
        sh->counters.snapshots,
        sh->counters.changes,
        sh->counters.sync_errors,
        sh->counters.alloc_failures,
        mcf->zone->shm.size,
        (size_t) store->shpool->pfree * ngx_pagesize);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;
    ngx_str_set(&r->headers_out.content_type, "text/plain; version=0.0.4");
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;
    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static char *
ngx_http_repsheet_metrics(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_repsheet_metrics_handler;
    return NGX_CONF_OK;
}


/* ------------------------------------------------------------------------ */
/* configuration                                                             */
/* ------------------------------------------------------------------------ */

static char *
ngx_http_repsheet_redis(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_repsheet_main_conf_t  *mcf = conf;
    ngx_str_t                      *value = cf->args->elts;
    ngx_url_t                       u;

    if (mcf->configured) {
        return "is duplicate";
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = value[1];
    u.default_port = 6379;
    u.no_resolve = 1;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid repsheet_redis address \"%V\": %s",
                           &value[1], u.err ? u.err : "parse error");
        return NGX_CONF_ERROR;
    }

#if (NGX_HAVE_UNIX_DOMAIN)
    if (u.family == AF_UNIX) {
        mcf->unix_path = u.host;
        mcf->configured = 1;
        return NGX_CONF_OK;
    }
#endif

    mcf->host = u.host;
    /* hiredis wants a bare IPv6 address, not "[::1]". */
    if (mcf->host.len > 2 && mcf->host.data[0] == '[') {
        mcf->host.data++;
        mcf->host.len -= 2;
    }
    mcf->port = u.port;
    mcf->configured = 1;
    return NGX_CONF_OK;
}


static char *
ngx_http_repsheet_redis_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_repsheet_main_conf_t  *mcf = conf;
    ngx_str_t                      *value = cf->args->elts;

    if (cf->args->nelts == 3) {
        mcf->user = value[1];
        mcf->password = value[2];
    } else {
        mcf->password = value[1];
    }
    return NGX_CONF_OK;
}


static char *
ngx_http_repsheet_actor(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_repsheet_loc_conf_t      *lcf = conf;
    ngx_str_t                         *value = cf->args->elts;
    ngx_http_repsheet_actor_conf_t    *actor;
    ngx_http_compile_complex_value_t   ccv;
    ngx_uint_t                         i;

    if (value[1].len == 0 || value[1].len > RS_TYPE_MAX) {
        return "has an invalid actor type";
    }

    for (i = 0; i < value[1].len; i++) {
        u_char c = ngx_tolower(value[1].data[i]);
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) {
            return "has an invalid actor type, use [a-z0-9_-]";
        }
        value[1].data[i] = c;
    }

    if (lcf->actors == NGX_CONF_UNSET_PTR || lcf->actors == NULL) {
        lcf->actors = ngx_array_create(cf->pool, 2, sizeof(ngx_http_repsheet_actor_conf_t));
        if (lcf->actors == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    actor = ngx_array_push(lcf->actors);
    if (actor == NULL) {
        return NGX_CONF_ERROR;
    }

    actor->type = value[1];

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &actor->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_repsheet_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_repsheet_main_conf_t *mcf;

    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_repsheet_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    mcf->timeout = NGX_CONF_UNSET_MSEC;
    mcf->interval = NGX_CONF_UNSET_MSEC;
    mcf->zone_size = NGX_CONF_UNSET_SIZE;
    return mcf;
}


static char *
ngx_http_repsheet_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_repsheet_main_conf_t  *mcf = conf;
    ngx_http_repsheet_store_t      *store;
    ngx_str_t                       name = ngx_string("repsheet");

    ngx_conf_init_msec_value(mcf->timeout, 1000);
    ngx_conf_init_msec_value(mcf->interval, 1000);
    ngx_conf_init_size_value(mcf->zone_size, DEFAULT_ZONE_SIZE);

    if (mcf->timeout == 0 || mcf->interval == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "repsheet_redis_timeout and repsheet_sync_interval must be positive");
        return NGX_CONF_ERROR;
    }

    if (mcf->zone_size < 8 * ngx_pagesize) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "repsheet_zone_size is too small");
        return NGX_CONF_ERROR;
    }

    if (!mcf->configured) {
        return NGX_CONF_OK;
    }

    store = ngx_pcalloc(cf->pool, sizeof(ngx_http_repsheet_store_t));
    if (store == NULL) {
        return NGX_CONF_ERROR;
    }

    mcf->zone = ngx_shared_memory_add(cf, &name, mcf->zone_size, &ngx_http_repsheet_module);
    if (mcf->zone == NULL) {
        return NGX_CONF_ERROR;
    }

    mcf->zone->init = ngx_http_repsheet_store_init_zone;
    mcf->zone->data = store;
    return NGX_CONF_OK;
}


static void *
ngx_http_repsheet_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_repsheet_loc_conf_t *lcf;

    lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_repsheet_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    lcf->mode = NGX_CONF_UNSET_UINT;
    lcf->block_status = NGX_CONF_UNSET_UINT;
    lcf->actors = NGX_CONF_UNSET_PTR;
    return lcf;
}


static char *
ngx_http_repsheet_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_repsheet_loc_conf_t *prev = parent;
    ngx_http_repsheet_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->mode, prev->mode, NGX_HTTP_REPSHEET_OFF);
    ngx_conf_merge_uint_value(conf->block_status, prev->block_status, NGX_HTTP_FORBIDDEN);
    ngx_conf_merge_ptr_value(conf->actors, prev->actors, NULL);
    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_repsheet_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_array_t                *handlers;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /*
     * PREACCESS rather than ACCESS: a block must not be overridden by
     * "satisfy any". Handlers of a phase run in reverse order of registration,
     * so put ours at the front of the array to run after the realip module's
     * PREACCESS handler (realip configured at location level).
     */
    handlers = &cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers;
    h = ngx_array_push(handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h = handlers->elts;
    ngx_memmove(&h[1], &h[0], (handlers->nelts - 1) * sizeof(ngx_http_handler_pt));
    h[0] = ngx_http_repsheet_handler;
    return NGX_OK;
}


static ngx_int_t
ngx_http_repsheet_init_process(ngx_cycle_t *cycle)
{
    return ngx_http_repsheet_sync_init_process(cycle);
}


static void
ngx_http_repsheet_exit_process(ngx_cycle_t *cycle)
{
    ngx_http_repsheet_sync_exit_process(cycle);
}

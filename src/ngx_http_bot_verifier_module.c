/*
 * Directives, the request handler, variables and metrics.
 */
#include "ngx_http_bot_verifier.h"

static ngx_int_t ngx_http_bot_verifier_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_bot_verifier_add_variables(ngx_conf_t *cf);
static void *ngx_http_bot_verifier_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_bot_verifier_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_bot_verifier_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_bot_verifier_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_bot_verifier_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_bot_verifier_ttl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_bot_verifier_redis(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_bot_verifier_redis_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_bot_verifier_repsheet(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_bot_verifier_metrics(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_bot_verifier_init_process(ngx_cycle_t *cycle);
static void ngx_http_bot_verifier_exit_process(ngx_cycle_t *cycle);

static bv_main_conf_t  *bv_mcf;   /* of the running configuration, set in each worker */


static ngx_command_t ngx_http_bot_verifier_commands[] = {

    { ngx_string("bot_verifier"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_bot_verifier_mode,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("bot_verifier_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(bv_loc_conf_t, timeout),
      NULL },

    { ngx_string("bot_verifier_block_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(bv_loc_conf_t, block_status),
      NULL },

    { ngx_string("bot_verifier_zone_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(bv_main_conf_t, zone_size),
      NULL },

    { ngx_string("bot_verifier_ttl"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE123,
      ngx_http_bot_verifier_ttl,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("bot_verifier_provider"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      bv_provider_block,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("bot_verifier_ranges"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      bv_ranges_directive,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("bot_verifier_redis"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_bot_verifier_redis,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("bot_verifier_redis_auth"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
      ngx_http_bot_verifier_redis_auth,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("bot_verifier_redis_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(bv_main_conf_t, redis_timeout),
      NULL },

    { ngx_string("bot_verifier_repsheet"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
      ngx_http_bot_verifier_repsheet,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("bot_verifier_metrics"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_bot_verifier_metrics,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_bot_verifier_module_ctx = {
    ngx_http_bot_verifier_add_variables,     /* preconfiguration */
    ngx_http_bot_verifier_init,              /* postconfiguration */
    ngx_http_bot_verifier_create_main_conf,  /* create main configuration */
    ngx_http_bot_verifier_init_main_conf,    /* init main configuration */
    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */
    ngx_http_bot_verifier_create_loc_conf,   /* create location configuration */
    ngx_http_bot_verifier_merge_loc_conf     /* merge location configuration */
};


ngx_module_t ngx_http_bot_verifier_module = {
    NGX_MODULE_V1,
    &ngx_http_bot_verifier_module_ctx,
    ngx_http_bot_verifier_commands,
    NGX_HTTP_MODULE,
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    ngx_http_bot_verifier_init_process,      /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    ngx_http_bot_verifier_exit_process,      /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


/* ------------------------------------------------------------------------ */
/* helpers                                                                   */
/* ------------------------------------------------------------------------ */

static const char *bv_result_names[] = { "", "verified", "failed", "unknown" };
static const char *bv_source_names[] = { "none", "zone", "ranges", "redis", "dns" };


const char *
bv_result_name(bv_result_e r)
{
    return r <= BV_UNKNOWN ? bv_result_names[r] : "";
}


bv_main_conf_t *
bv_main_conf(void)
{
    return bv_mcf;
}


bv_cache_t *
bv_cache(void)
{
    return bv_mcf->zone->data;
}


size_t
bv_addr_format(bv_addr_t *addr, u_char *buf, size_t len)
{
    return ngx_inet_ntop(addr->family, addr->addr, buf, len);
}


/* The client address after realip; v4-mapped IPv6 folded to IPv4. */
static ngx_flag_t
bv_client_addr(ngx_connection_t *c, bv_addr_t *out)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    ngx_memzero(out, sizeof(bv_addr_t));

    switch (c->sockaddr->sa_family) {
    case AF_INET:
        sin = (struct sockaddr_in *) c->sockaddr;
        out->family = AF_INET;
        ngx_memcpy(out->addr, &sin->sin_addr, 4);
        return 1;
#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) c->sockaddr;
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            out->family = AF_INET;
            ngx_memcpy(out->addr, &sin6->sin6_addr.s6_addr[12], 4);
        } else {
            out->family = AF_INET6;
            ngx_memcpy(out->addr, &sin6->sin6_addr, 16);
        }
        return 1;
#endif
    default:
        return 0;   /* unix socket */
    }
}


/* ------------------------------------------------------------------------ */
/* request handler                                                           */
/* ------------------------------------------------------------------------ */

static ngx_int_t
bv_decide(ngx_http_request_t *r, bv_ctx_t *ctx, bv_loc_conf_t *lcf)
{
    bv_counters_t  *counters = &bv_cache()->sh->counters;

    ctx->evaluated = 1;

    if (!ctx->counted && !r->internal) {
        ctx->counted = 1;
        (void) ngx_atomic_fetch_add(&counters->requests[ctx->verdict.result], 1);
        (void) ngx_atomic_fetch_add(&counters->hits[ctx->source], 1);
        if (ctx->verdict.result == BV_FAILED && lcf->mode == BV_ON) {
            (void) ngx_atomic_fetch_add(&counters->blocked, 1);
        }
    }

    if (ctx->verdict.result != BV_FAILED) {
        return NGX_DECLINED;
    }
    if (lcf->mode == BV_MONITOR) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "bot_verifier: would block a request claiming to be a crawler (monitor mode)");
        return NGX_DECLINED;
    }
    return lcf->block_status;
}


static ngx_int_t
ngx_http_bot_verifier_handler(ngx_http_request_t *r)
{
    bv_loc_conf_t   *lcf;
    bv_ctx_t        *ctx;
    bv_provider_t   *provider;
    bv_addr_t        addr;
    ngx_int_t        rc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_bot_verifier_module);
    if (lcf->mode == BV_OFF || r != r->main) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_bot_verifier_module);
    if (ctx) {
        if (ctx->waiting) {
            return NGX_AGAIN;   /* woken by an unrelated event; still waiting */
        }
        return bv_decide(r, ctx, lcf);
    }

    if (r->headers_in.user_agent == NULL) {
        return NGX_DECLINED;
    }
    provider = bv_provider_for_user_agent(bv_mcf, &r->headers_in.user_agent->value);
    if (provider == NULL) {
        return NGX_DECLINED;
    }
    if (!bv_client_addr(r->connection, &addr)) {
        return NGX_DECLINED;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(bv_ctx_t));
    if (ctx == NULL) {
        return NGX_DECLINED;
    }
    ngx_http_set_ctx(r, ctx, ngx_http_bot_verifier_module);

    rc = bv_verify(r, ctx, provider, &addr, r->connection->sockaddr, r->connection->socklen);

    if (rc == NGX_AGAIN) {
        /* As limit_req does while delaying: notice if the client goes away. */
        r->read_event_handler = ngx_http_test_reading;
        r->write_event_handler = ngx_http_request_empty_handler;
        return NGX_AGAIN;
    }
    if (rc != NGX_OK) {
        ctx->verdict.result = BV_UNKNOWN;
    }
    return bv_decide(r, ctx, lcf);
}


/* ------------------------------------------------------------------------ */
/* variables                                                                 */
/* ------------------------------------------------------------------------ */

static ngx_int_t
bv_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    bv_ctx_t        *ctx = ngx_http_get_module_ctx(r, ngx_http_bot_verifier_module);
    bv_provider_t   *p;
    const char      *s = "";

    if (ctx && ctx->evaluated && bv_mcf) {
        if (data == 0) {
            s = bv_result_name(ctx->verdict.result);
        } else {
            p = bv_mcf->providers.elts;
            v->data = p[ctx->verdict.provider].name.data;
            v->len = p[ctx->verdict.provider].name.len;
            goto done;
        }
    }

    v->data = (u_char *) s;
    v->len = ngx_strlen(s);

done:
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}


static ngx_http_variable_t bv_vars[] = {
    { ngx_string("bot_verifier_result"), NULL, bv_variable, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("bot_verifier_provider"), NULL, bv_variable, 1, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    ngx_http_null_variable
};


static ngx_int_t
ngx_http_bot_verifier_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;

    for (v = bv_vars; v->name.len; v++) {
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
ngx_http_bot_verifier_metrics_handler(ngx_http_request_t *r)
{
    bv_main_conf_t  *mcf = ngx_http_get_module_main_conf(r, ngx_http_bot_verifier_module);
    bv_cache_t      *cache;
    bv_counters_t   *c;
    ngx_buf_t       *b;
    ngx_chain_t      out;
    ngx_int_t        rc;
    ngx_uint_t       i, count;
    size_t           free_bytes, total;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }
    if (mcf->zone == NULL || ((bv_cache_t *) mcf->zone->data)->sh == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    cache = mcf->zone->data;
    c = &cache->sh->counters;

    ngx_shmtx_lock(&cache->shpool->mutex);
    count = cache->sh->count;
    total = cache->shpool->end - (u_char *) cache->shpool;
    free_bytes = cache->shpool->pfree << ngx_pagesize_shift;
    ngx_shmtx_unlock(&cache->shpool->mutex);

    b = ngx_create_temp_buf(r->pool, 4096);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_sprintf(b->last,
        "# HELP bot_verifier_requests_total Requests that claimed to be a crawler, by result.\n"
        "# TYPE bot_verifier_requests_total counter\n");
    for (i = BV_VERIFIED; i <= BV_UNKNOWN; i++) {
        b->last = ngx_sprintf(b->last, "bot_verifier_requests_total{result=\"%s\"} %uA\n",
                              bv_result_names[i], c->requests[i]);
    }
    b->last = ngx_sprintf(b->last,
        "# HELP bot_verifier_blocked_total Requests rejected (excludes monitor mode).\n"
        "# TYPE bot_verifier_blocked_total counter\n"
        "bot_verifier_blocked_total %uA\n"
        "# HELP bot_verifier_answers_total Where each request's result came from.\n"
        "# TYPE bot_verifier_answers_total counter\n",
        c->blocked);
    for (i = BV_SRC_NONE; i <= BV_SRC_DNS; i++) {
        b->last = ngx_sprintf(b->last, "bot_verifier_answers_total{source=\"%s\"} %uA\n",
                              bv_source_names[i], c->hits[i]);
    }
    b->last = ngx_sprintf(b->last,
        "# HELP bot_verifier_dns_queries_total DNS queries sent.\n"
        "# TYPE bot_verifier_dns_queries_total counter\n"
        "bot_verifier_dns_queries_total %uA\n"
        "# HELP bot_verifier_dns_errors_total Lookups that ended in a DNS error or timeout.\n"
        "# TYPE bot_verifier_dns_errors_total counter\n"
        "bot_verifier_dns_errors_total %uA\n"
        "# HELP bot_verifier_redis_errors_total Valkey/Redis errors.\n"
        "# TYPE bot_verifier_redis_errors_total counter\n"
        "bot_verifier_redis_errors_total %uA\n"
        "# HELP bot_verifier_repsheet_reports_total Failed verifications reported to Repsheet.\n"
        "# TYPE bot_verifier_repsheet_reports_total counter\n"
        "bot_verifier_repsheet_reports_total %uA\n"
        "# HELP bot_verifier_cache_entries Results in the shared-memory cache.\n"
        "# TYPE bot_verifier_cache_entries gauge\n"
        "bot_verifier_cache_entries %ui\n"
        "# HELP bot_verifier_cache_evictions_total Results evicted because the zone was full.\n"
        "# TYPE bot_verifier_cache_evictions_total counter\n"
        "bot_verifier_cache_evictions_total %uA\n"
        "# HELP bot_verifier_zone_size_bytes Size of the shared-memory zone.\n"
        "# TYPE bot_verifier_zone_size_bytes gauge\n"
        "bot_verifier_zone_size_bytes %uz\n"
        "# HELP bot_verifier_zone_free_bytes Free pages in the shared-memory zone.\n"
        "# TYPE bot_verifier_zone_free_bytes gauge\n"
        "bot_verifier_zone_free_bytes %uz\n",
        c->dns_lookups, c->dns_errors, c->redis_errors, c->reports, count, c->evictions, total, free_bytes);

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
ngx_http_bot_verifier_metrics(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    bv_main_conf_t           *mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_bot_verifier_module);

    clcf->handler = ngx_http_bot_verifier_metrics_handler;
    mcf->used = 1;  /* needs the zone */
    return NGX_CONF_OK;
}


/* ------------------------------------------------------------------------ */
/* configuration                                                             */
/* ------------------------------------------------------------------------ */

static char *
ngx_http_bot_verifier_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    bv_loc_conf_t   *lcf = conf;
    ngx_str_t       *value = cf->args->elts;
    bv_main_conf_t  *mcf;

    if (lcf->mode != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "on") == 0) {
        lcf->mode = BV_ON;
    } else if (ngx_strcmp(value[1].data, "monitor") == 0) {
        lcf->mode = BV_MONITOR;
    } else if (ngx_strcmp(value[1].data, "off") == 0) {
        lcf->mode = BV_OFF;
        return NGX_CONF_OK;
    } else {
        return "must be \"on\", \"off\" or \"monitor\"";
    }

    mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_bot_verifier_module);
    mcf->used = 1;
    return NGX_CONF_OK;
}


static char *
ngx_http_bot_verifier_ttl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    bv_main_conf_t  *mcf = conf;
    ngx_str_t       *value = cf->args->elts;
    ngx_uint_t       i;
    time_t           t;

    if (mcf->ttl[BV_VERIFIED] != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    for (i = 1; i < cf->args->nelts; i++) {
        t = ngx_parse_time(&value[i], 1);
        if (t == (time_t) NGX_ERROR || t == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid bot_verifier_ttl \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
        mcf->ttl[i] = t;   /* 1: verified, 2: failed, 3: unknown */
    }
    return NGX_CONF_OK;
}


static char *
ngx_http_bot_verifier_redis(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    bv_main_conf_t  *mcf = conf;
    ngx_str_t       *value = cf->args->elts;
    ngx_url_t        u;

    if (mcf->redis || mcf->redis_off) {
        return "is duplicate";
    }

    if (value[1].len == 3 && ngx_strncmp(value[1].data, "off", 3) == 0) {
        mcf->redis_off = 1;   /* also: do not use repsheet_redis */
        return NGX_CONF_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = value[1];
    u.default_port = 6379;
    u.no_resolve = 1;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid bot_verifier_redis address \"%V\": %s", &value[1],
                           u.err ? u.err : "parse error");
        return NGX_CONF_ERROR;
    }

    mcf->redis = 1;
#if (NGX_HAVE_UNIX_DOMAIN)
    if (u.family == AF_UNIX) {
        mcf->redis_unix = u.host;
        return NGX_CONF_OK;
    }
#endif

    mcf->redis_host = u.host;
    /* hiredis wants a bare IPv6 address, not "[::1]". */
    if (mcf->redis_host.len > 2 && mcf->redis_host.data[0] == '[') {
        mcf->redis_host.data++;
        mcf->redis_host.len -= 2;
    }
    mcf->redis_port = u.port;
    return NGX_CONF_OK;
}


static char *
ngx_http_bot_verifier_redis_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    bv_main_conf_t  *mcf = conf;
    ngx_str_t       *value = cf->args->elts;

    if (cf->args->nelts == 3) {
        mcf->redis_user = value[1];
        mcf->redis_password = value[2];
    } else {
        mcf->redis_password = value[1];
    }
    return NGX_CONF_OK;
}


/* bot_verifier_repsheet off | mark [ttl] | block [ttl] */
static char *
ngx_http_bot_verifier_repsheet(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    bv_main_conf_t  *mcf = conf;
    ngx_str_t       *value = cf->args->elts;
    time_t           t;

    if (ngx_strcmp(value[1].data, "off") == 0 && cf->args->nelts == 2) {
        mcf->repsheet = 0;
        return NGX_CONF_OK;
    }
    if (ngx_strcmp(value[1].data, "mark") == 0) {
        mcf->repsheet_block = 0;
    } else if (ngx_strcmp(value[1].data, "block") == 0) {
        mcf->repsheet_block = 1;
    } else {
        return "must be \"off\", \"mark [ttl]\" or \"block [ttl]\"";
    }
    mcf->repsheet = 1;

    if (cf->args->nelts == 3) {
        t = ngx_parse_time(&value[2], 1);
        if (t == (time_t) NGX_ERROR || t <= 0 || t > 315360000) {
            return "has an invalid ttl";
        }
        mcf->repsheet_ttl = t;
    }
    return NGX_CONF_OK;
}


static void *
ngx_http_bot_verifier_create_main_conf(ngx_conf_t *cf)
{
    bv_main_conf_t  *mcf;
    ngx_uint_t       i;

    mcf = ngx_pcalloc(cf->pool, sizeof(bv_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&mcf->providers, cf->pool, 8, sizeof(bv_provider_t)) != NGX_OK) {
        return NULL;
    }
    /* Pointers into this array are kept, so it must never grow (realloc). */
    mcf->providers.nalloc = BV_MAX_PROVIDERS;
    mcf->providers.elts = ngx_pcalloc(cf->pool, BV_MAX_PROVIDERS * sizeof(bv_provider_t));
    if (mcf->providers.elts == NULL) {
        return NULL;
    }

    if (bv_providers_add_builtin(cf, mcf) != NGX_CONF_OK) {
        return NULL;
    }

    mcf->zone_size = NGX_CONF_UNSET_SIZE;
    mcf->redis_timeout = NGX_CONF_UNSET_MSEC;
    for (i = 0; i < 4; i++) {
        mcf->ttl[i] = NGX_CONF_UNSET;
    }
    mcf->repsheet_ttl = 3600;
    return mcf;
}


/*
 * With the Repsheet nginx module loaded and repsheet_redis configured, use
 * its Redis settings unless bot_verifier_redis says otherwise (#16).
 */
static void
bv_use_repsheet_redis(ngx_conf_t *cf, bv_main_conf_t *mcf)
{
    ngx_module_t              **modules = cf->cycle->modules;
    bv_repsheet_redis_conf_t   *rs;
    ngx_uint_t                  i;

    if (mcf->redis || mcf->redis_off || modules == NULL) {
        return;
    }

    for (i = 0; modules[i]; i++) {
        if (modules[i]->type == NGX_HTTP_MODULE && modules[i]->name
            && ngx_strcmp(modules[i]->name, "ngx_http_repsheet_module") == 0)
        {
            break;
        }
    }
    if (modules[i] == NULL) {
        return;
    }

    rs = ((ngx_http_conf_ctx_t *) cf->ctx)->main_conf[modules[i]->ctx_index];
    if (rs == NULL || rs->magic != BV_REPSHEET_MAGIC) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "bot_verifier: this version of the repsheet module does not share its "
                           "redis settings; use bot_verifier_redis");
        return;
    }
    if (rs->version < BV_REPSHEET_VERSION || !rs->configured) {
        return;
    }

    mcf->redis = 1;
    mcf->redis_from_repsheet = 1;
    mcf->redis_host = rs->host;
    mcf->redis_port = rs->port;
    mcf->redis_unix = rs->unix_path;
    mcf->redis_user = rs->user;
    mcf->redis_password = rs->password;
}


static char *
ngx_http_bot_verifier_init_main_conf(ngx_conf_t *cf, void *conf)
{
    bv_main_conf_t  *mcf = conf;
    bv_cache_t      *cache;
    ngx_str_t        name = ngx_string("bot_verifier");
    time_t           defaults[4] = { 0, 86400, 3600, 60 };
    ngx_uint_t       i;

    for (i = 1; i < 4; i++) {
        if (mcf->ttl[i] == NGX_CONF_UNSET) {
            mcf->ttl[i] = defaults[i];
        }
    }
    mcf->ttl[BV_NONE] = 0;

    ngx_conf_init_size_value(mcf->zone_size, 16 * 1024 * 1024);
    ngx_conf_init_msec_value(mcf->redis_timeout, 100);

    bv_use_repsheet_redis(cf, mcf);

    if (mcf->repsheet && !mcf->redis) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "bot_verifier_repsheet requires repsheet_redis or bot_verifier_redis");
        return NGX_CONF_ERROR;
    }

    if (bv_providers_load_ranges(cf, mcf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    if (!mcf->used) {
        return NGX_CONF_OK;
    }

    if (mcf->zone_size < 8 * ngx_pagesize) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "bot_verifier_zone_size is too small");
        return NGX_CONF_ERROR;
    }

    cache = ngx_pcalloc(cf->pool, sizeof(bv_cache_t));
    if (cache == NULL) {
        return NGX_CONF_ERROR;
    }

    mcf->zone = ngx_shared_memory_add(cf, &name, mcf->zone_size, &ngx_http_bot_verifier_module);
    if (mcf->zone == NULL) {
        return NGX_CONF_ERROR;
    }
    if (mcf->zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "duplicate bot_verifier zone");
        return NGX_CONF_ERROR;
    }
    mcf->zone->init = bv_cache_init_zone;
    mcf->zone->data = cache;
    return NGX_CONF_OK;
}


static void *
ngx_http_bot_verifier_create_loc_conf(ngx_conf_t *cf)
{
    bv_loc_conf_t *lcf = ngx_pcalloc(cf->pool, sizeof(bv_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }
    lcf->mode = NGX_CONF_UNSET_UINT;
    lcf->timeout = NGX_CONF_UNSET_MSEC;
    lcf->block_status = NGX_CONF_UNSET_UINT;
    return lcf;
}


static char *
ngx_http_bot_verifier_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    bv_loc_conf_t             *prev = parent, *conf = child;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_conf_merge_uint_value(conf->mode, prev->mode, BV_OFF);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 5000);
    ngx_conf_merge_uint_value(conf->block_status, prev->block_status, NGX_HTTP_FORBIDDEN);

    if (conf->block_status < 400 || conf->block_status > 599) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "bot_verifier_block_status must be between 400 and 599");
        return NGX_CONF_ERROR;
    }

    if (conf->mode != BV_OFF) {
        /* The core module is merged first, so this location's resolver is final. */
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        if (clcf->resolver == NULL || clcf->resolver->connections.nelts == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "bot_verifier needs a DNS resolver: add a \"resolver\" directive");
            return NGX_CONF_ERROR;
        }
    }
    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_bot_verifier_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_array_t                *handlers;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /*
     * PREACCESS rather than ACCESS so "satisfy any" cannot override a block.
     * Handlers of a phase run in reverse order of registration: put ours at
     * the front to run after realip's PREACCESS handler.
     */
    handlers = &cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers;
    h = ngx_array_push(handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    h = handlers->elts;
    ngx_memmove(&h[1], &h[0], (handlers->nelts - 1) * sizeof(ngx_http_handler_pt));
    h[0] = ngx_http_bot_verifier_handler;
    return NGX_OK;
}


static ngx_int_t
ngx_http_bot_verifier_init_process(ngx_cycle_t *cycle)
{
    bv_main_conf_t *mcf;

    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE) {
        return NGX_OK;
    }

    mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_bot_verifier_module);
    if (mcf == NULL || mcf->zone == NULL) {
        return NGX_OK;
    }
    bv_mcf = mcf;

    if (bv_verify_init_process(cycle) != NGX_OK) {
        return NGX_ERROR;
    }
    return bv_redis_init_process(cycle, mcf);
}


static void
ngx_http_bot_verifier_exit_process(ngx_cycle_t *cycle)
{
    if (bv_mcf == NULL) {
        return;
    }
    bv_verify_exit_process(cycle);
    bv_redis_exit_process();
}

/*
 * The bot verifier detector: directives, the check called by the repsheet
 * handler, variables and metrics.
 *
 * It is a separate nginx module object compiled into the repsheet module, so
 * it keeps its own configuration and request context, but it registers no
 * phase handler of its own: ngx_http_repsheet_handler() calls
 * ngx_http_repsheet_bot_verifier_check() between looking up decisions and
 * acting on them.
 */
#include "ngx_http_repsheet_bv.h"

static ngx_int_t ngx_http_bot_verifier_add_variables(ngx_conf_t *cf);
static void *ngx_http_bot_verifier_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_bot_verifier_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_bot_verifier_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_bot_verifier_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_bot_verifier_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_bot_verifier_ttl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_bot_verifier_action(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_bot_verifier_init_process(ngx_cycle_t *cycle);
static void ngx_http_bot_verifier_exit_process(ngx_cycle_t *cycle);

static bv_main_conf_t  *bv_mcf;   /* of the running configuration, set in each worker */


static ngx_command_t ngx_http_bot_verifier_commands[] = {

    { ngx_string("repsheet_bot_verifier"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_bot_verifier_mode,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("repsheet_bot_verifier_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(bv_loc_conf_t, timeout),
      NULL },

    { ngx_string("repsheet_bot_verifier_action"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
      ngx_http_bot_verifier_action,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("repsheet_bot_verifier_zone_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(bv_main_conf_t, zone_size),
      NULL },

    { ngx_string("repsheet_bot_verifier_ttl"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE123,
      ngx_http_bot_verifier_ttl,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("repsheet_bot_verifier_cache_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(bv_main_conf_t, cache_timeout),
      NULL },

    { ngx_string("repsheet_bot_verifier_provider"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      bv_provider_block,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("repsheet_bot_verifier_ranges"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      bv_ranges_directive,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_repsheet_bot_verifier_module_ctx = {
    ngx_http_bot_verifier_add_variables,     /* preconfiguration */
    NULL,                                    /* postconfiguration */
    ngx_http_bot_verifier_create_main_conf,  /* create main configuration */
    ngx_http_bot_verifier_init_main_conf,    /* init main configuration */
    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */
    ngx_http_bot_verifier_create_loc_conf,   /* create location configuration */
    ngx_http_bot_verifier_merge_loc_conf     /* merge location configuration */
};


ngx_module_t ngx_http_repsheet_bot_verifier_module = {
    NGX_MODULE_V1,
    &ngx_http_repsheet_bot_verifier_module_ctx,
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


/*
 * An internal redirect (index, try_files, error_page) clears module contexts.
 * Like the realip module, find ours again through its pool cleanup so the
 * request keeps its result and timing and is not evaluated twice.
 */
static bv_ctx_t *
bv_get_ctx(ngx_http_request_t *r)
{
    ngx_pool_cleanup_t  *cln;
    bv_ctx_t            *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_repsheet_bot_verifier_module);
    if (ctx == NULL && (r->internal || r->filter_finalize)) {
        for (cln = r->pool->cleanup; cln; cln = cln->next) {
            if (cln->handler == bv_ctx_cleanup) {
                ctx = cln->data;
                ngx_http_set_ctx(r, ctx, ngx_http_repsheet_bot_verifier_module);
                break;
            }
        }
    }
    return ctx;
}


/* ------------------------------------------------------------------------ */
/* the detector                                                              */
/* ------------------------------------------------------------------------ */

/*
 * Turn a finished verification into a Repsheet decision. A failed claim is
 * recorded as a decision (repsheet_bot_verifier_action) unless the request
 * already carries one at least as strong, so a fresh failure is recorded
 * once, and an address that keeps faking after its decision was cleared is
 * recorded again.
 */
static ngx_int_t
bv_apply(ngx_http_request_t *r, bv_ctx_t *ctx, bv_loc_conf_t *lcf, ngx_http_repsheet_verdict_t *v)
{
    bv_counters_t  *counters = &bv_cache()->sh->counters;
    bv_provider_t  *p = bv_mcf->providers.elts;
    u_char          actor[64], reason[BV_REASON_MAX + 32], *e;
    ngx_str_t       actor_str, reason_str;

    ctx->evaluated = 1;

    if (!ctx->counted) {
        ctx->counted = 1;
        (void) ngx_atomic_fetch_add(&counters->requests[ctx->verdict.result], 1);
        (void) ngx_atomic_fetch_add(&counters->hits[ctx->source], 1);
    }

    if (ctx->verdict.result != BV_FAILED || v->status >= bv_mcf->action) {
        return NGX_DECLINED;
    }

    if (lcf->mode == BV_MONITOR) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "bot_verifier: would record a %s decision (monitor mode)", rs_status_name(bv_mcf->action));
        return NGX_DECLINED;
    }

    e = ngx_cpymem(actor, "ip:", 3);
    e += bv_addr_format(&ctx->addr, e, sizeof(actor) - 3);
    actor_str.data = actor;
    actor_str.len = e - actor;

    if (ctx->reason.len) {
        e = ngx_snprintf(reason, sizeof(reason), "bot_verifier: %V", &ctx->reason);
    } else {
        e = ngx_snprintf(reason, sizeof(reason), "bot_verifier: claimed %V: failed verification",
                         &p[ctx->verdict.provider].name);
    }
    reason_str.data = reason;
    reason_str.len = e - reason;

    if (ngx_http_repsheet_record(&actor_str, bv_mcf->action, &reason_str, bv_mcf->action_ttl, BV_DETECTOR,
                                 r->connection->log) != NGX_OK)
    {
        return NGX_DECLINED;
    }
    (void) ngx_atomic_fetch_add(&counters->decisions, 1);

    /* This request is judged by the new decision like any later one. */
    v->status = bv_mcf->action;
    v->actor.data = ngx_pstrdup(r->pool, &actor_str);
    v->actor.len = v->actor.data ? actor_str.len : 0;
    v->reason.data = ngx_pstrdup(r->pool, &reason_str);
    v->reason.len = v->reason.data ? reason_str.len : 0;
    return NGX_OK;
}


/*
 * Called by the repsheet handler for requests that are neither allowed nor
 * blocked. Returns NGX_DECLINED (nothing to add), NGX_OK (v now carries the
 * detector's decision) or NGX_AGAIN (the request is suspended; the handler
 * runs again when verification finishes).
 */
ngx_int_t
ngx_http_repsheet_bot_verifier_check(ngx_http_request_t *r, ngx_http_repsheet_verdict_t *v)
{
    bv_loc_conf_t       *lcf;
    bv_ctx_t            *ctx;
    bv_provider_t       *provider;
    bv_addr_t            addr;
    ngx_int_t            rc;
    ngx_pool_cleanup_t  *cln;

    if (bv_mcf == NULL) {
        return NGX_DECLINED;
    }

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_repsheet_bot_verifier_module);
    if (lcf->mode == BV_OFF) {
        return NGX_DECLINED;
    }

    ctx = bv_get_ctx(r);
    if (ctx) {
        if (ctx->waiting) {
            return NGX_AGAIN;   /* woken by an unrelated event; still waiting */
        }
        return bv_apply(r, ctx, lcf, v);
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

    cln = ngx_pool_cleanup_add(r->pool, sizeof(bv_ctx_t));
    if (cln == NULL) {
        return NGX_DECLINED;
    }
    ctx = cln->data;
    ngx_memzero(ctx, sizeof(bv_ctx_t));
    cln->handler = bv_ctx_cleanup;
    ngx_http_set_ctx(r, ctx, ngx_http_repsheet_bot_verifier_module);

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
    return bv_apply(r, ctx, lcf, v);
}


/* ------------------------------------------------------------------------ */
/* variables                                                                 */
/* ------------------------------------------------------------------------ */

static ngx_int_t
bv_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    bv_ctx_t        *ctx = bv_mcf ? bv_get_ctx(r) : NULL;
    bv_provider_t   *p;
    const char      *s = "";

    if (ctx && ctx->evaluated) {
        if (data == 0) {
            s = bv_result_name(ctx->verdict.result);
        } else if (data == 2) {
            /* Seconds spent waiting for verification, like $request_time. */
            v->data = ngx_pnalloc(r->pool, NGX_TIME_T_LEN + 4);
            if (v->data == NULL) {
                return NGX_ERROR;
            }
            v->len = ngx_sprintf(v->data, "%T.%03M", (time_t) (ctx->waited / 1000), ctx->waited % 1000)
                     - v->data;
            goto done;
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
    { ngx_string("repsheet_bot_verifier_result"), NULL, bv_variable, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("repsheet_bot_verifier_provider"), NULL, bv_variable, 1, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("repsheet_bot_verifier_time"), NULL, bv_variable, 2, NGX_HTTP_VAR_NOCACHEABLE, 0 },
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
/* metrics: appended to repsheet_metrics                                     */
/* ------------------------------------------------------------------------ */

ngx_chain_t *
ngx_http_repsheet_bot_verifier_metrics(ngx_http_request_t *r)
{
    bv_main_conf_t  *mcf = ngx_http_get_module_main_conf(r, ngx_http_repsheet_bot_verifier_module);
    bv_cache_t      *cache;
    bv_counters_t   *c;
    ngx_buf_t       *b;
    ngx_chain_t     *out;
    ngx_uint_t       i, count;
    size_t           free_bytes, total;

    if (mcf == NULL || mcf->zone == NULL || ((bv_cache_t *) mcf->zone->data)->sh == NULL) {
        return NULL;
    }

    cache = mcf->zone->data;
    c = &cache->sh->counters;

    ngx_shmtx_lock(&cache->shpool->mutex);
    count = cache->sh->count;
    total = cache->shpool->end - (u_char *) cache->shpool;
    free_bytes = cache->shpool->pfree << ngx_pagesize_shift;
    ngx_shmtx_unlock(&cache->shpool->mutex);

    b = ngx_create_temp_buf(r->pool, 8192);
    out = ngx_alloc_chain_link(r->pool);
    if (b == NULL || out == NULL) {
        return NULL;
    }
    out->buf = b;
    out->next = NULL;

    b->last = ngx_sprintf(b->last,
        "# HELP repsheet_bot_verifier_requests_total Requests that claimed to be a crawler, by result.\n"
        "# TYPE repsheet_bot_verifier_requests_total counter\n");
    for (i = BV_VERIFIED; i <= BV_UNKNOWN; i++) {
        b->last = ngx_sprintf(b->last, "repsheet_bot_verifier_requests_total{result=\"%s\"} %uA\n",
                              bv_result_names[i], c->requests[i]);
    }
    b->last = ngx_sprintf(b->last,
        "# HELP repsheet_bot_verifier_answers_total Where each request's result came from.\n"
        "# TYPE repsheet_bot_verifier_answers_total counter\n");
    for (i = BV_SRC_NONE; i <= BV_SRC_DNS; i++) {
        b->last = ngx_sprintf(b->last, "repsheet_bot_verifier_answers_total{source=\"%s\"} %uA\n",
                              bv_source_names[i], c->hits[i]);
    }
    b->last = ngx_sprintf(b->last,
        "# HELP repsheet_bot_verifier_decisions_total Decisions recorded for failed verifications.\n"
        "# TYPE repsheet_bot_verifier_decisions_total counter\n"
        "repsheet_bot_verifier_decisions_total %uA\n"
        "# HELP repsheet_bot_verifier_dns_queries_total DNS queries sent.\n"
        "# TYPE repsheet_bot_verifier_dns_queries_total counter\n"
        "repsheet_bot_verifier_dns_queries_total %uA\n"
        "# HELP repsheet_bot_verifier_dns_errors_total Lookups that ended in a DNS error or timeout.\n"
        "# TYPE repsheet_bot_verifier_dns_errors_total counter\n"
        "repsheet_bot_verifier_dns_errors_total %uA\n"
        "# HELP repsheet_bot_verifier_cache_entries Results in the shared-memory cache.\n"
        "# TYPE repsheet_bot_verifier_cache_entries gauge\n"
        "repsheet_bot_verifier_cache_entries %ui\n"
        "# HELP repsheet_bot_verifier_cache_evictions_total Results evicted because the zone was full.\n"
        "# TYPE repsheet_bot_verifier_cache_evictions_total counter\n"
        "repsheet_bot_verifier_cache_evictions_total %uA\n"
        "# HELP repsheet_bot_verifier_zone_size_bytes Size of the shared-memory zone.\n"
        "# TYPE repsheet_bot_verifier_zone_size_bytes gauge\n"
        "repsheet_bot_verifier_zone_size_bytes %uz\n"
        "# HELP repsheet_bot_verifier_zone_free_bytes Free pages in the shared-memory zone.\n"
        "# TYPE repsheet_bot_verifier_zone_free_bytes gauge\n"
        "repsheet_bot_verifier_zone_free_bytes %uz\n",
        c->decisions, c->dns_lookups, c->dns_errors, count, c->evictions, total, free_bytes);

    b->last = ngx_sprintf(b->last,
        "# HELP repsheet_bot_verifier_lookup_duration_seconds Time to answer a lookup that was not in "
        "shared memory or the published ranges, by where the answer came from.\n"
        "# TYPE repsheet_bot_verifier_lookup_duration_seconds histogram\n");
    {
        static const ngx_msec_t   bounds[BV_BUCKETS] = BV_BUCKET_BOUNDS_MS;
        static const char        *names[2] = { "redis", "dns" };
        ngx_atomic_uint_t         cumulative;
        ngx_uint_t                w, k;

        for (w = 0; w < 2; w++) {
            cumulative = 0;
            for (k = 0; k < BV_BUCKETS; k++) {
                cumulative += c->duration_buckets[w][k];
                b->last = ngx_sprintf(b->last,
                    "repsheet_bot_verifier_lookup_duration_seconds_bucket{source=\"%s\",le=\"%M.%03M\"} %uA\n",
                    names[w], bounds[k] / 1000, bounds[k] % 1000, cumulative);
            }
            b->last = ngx_sprintf(b->last,
                "repsheet_bot_verifier_lookup_duration_seconds_bucket{source=\"%s\",le=\"+Inf\"} %uA\n"
                "repsheet_bot_verifier_lookup_duration_seconds_sum{source=\"%s\"} %uA.%03uA\n"
                "repsheet_bot_verifier_lookup_duration_seconds_count{source=\"%s\"} %uA\n",
                names[w], c->duration_count[w],
                names[w], c->duration_sum_ms[w] / 1000, c->duration_sum_ms[w] % 1000,
                names[w], c->duration_count[w]);
        }
    }

    return out;
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

    mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_repsheet_bot_verifier_module);
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
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid repsheet_bot_verifier_ttl \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
        mcf->ttl[i] = t;   /* 1: verified, 2: failed, 3: unknown */
    }
    return NGX_CONF_OK;
}


/* repsheet_bot_verifier_action block|mark [ttl] */
static char *
ngx_http_bot_verifier_action(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    bv_main_conf_t  *mcf = conf;
    ngx_str_t       *value = cf->args->elts;
    time_t           t;

    if (ngx_strcmp(value[1].data, "block") == 0) {
        mcf->action = RS_STATUS_BLOCK;
    } else if (ngx_strcmp(value[1].data, "mark") == 0) {
        mcf->action = RS_STATUS_MARK;
    } else {
        return "must be \"block [ttl]\" or \"mark [ttl]\"";
    }

    if (cf->args->nelts == 3) {
        t = ngx_parse_time(&value[2], 1);
        if (t == (time_t) NGX_ERROR || t <= 0 || t > 315360000) {
            return "has an invalid ttl";
        }
        mcf->action_ttl = t;
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
    mcf->cache_timeout = NGX_CONF_UNSET_MSEC;
    for (i = 0; i < 4; i++) {
        mcf->ttl[i] = NGX_CONF_UNSET;
    }
    mcf->action = RS_STATUS_BLOCK;
    mcf->action_ttl = 3600;
    return mcf;
}


static char *
ngx_http_bot_verifier_init_main_conf(ngx_conf_t *cf, void *conf)
{
    bv_main_conf_t                 *mcf = conf;
    ngx_http_repsheet_main_conf_t  *rmcf;
    bv_cache_t                     *cache;
    ngx_str_t                       name = ngx_string("repsheet_bot_verifier");
    time_t                          defaults[4] = { 0, 86400, 3600, 60 };
    ngx_uint_t                      i;

    for (i = 1; i < 4; i++) {
        if (mcf->ttl[i] == NGX_CONF_UNSET) {
            mcf->ttl[i] = defaults[i];
        }
    }
    mcf->ttl[BV_NONE] = 0;

    ngx_conf_init_size_value(mcf->zone_size, 16 * 1024 * 1024);
    ngx_conf_init_msec_value(mcf->cache_timeout, 100);

    if (bv_providers_load_ranges(cf, mcf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    if (!mcf->used) {
        return NGX_CONF_OK;
    }

    /* Decisions are recorded in Repsheet, so it must be configured. */
    rmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_repsheet_module);
    if (!rmcf->redis.configured) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "repsheet_bot_verifier requires repsheet_redis");
        return NGX_CONF_ERROR;
    }
    rmcf->detectors = 1;

    if (mcf->zone_size < 8 * ngx_pagesize) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "repsheet_bot_verifier_zone_size is too small");
        return NGX_CONF_ERROR;
    }

    cache = ngx_pcalloc(cf->pool, sizeof(bv_cache_t));
    if (cache == NULL) {
        return NGX_CONF_ERROR;
    }

    mcf->zone = ngx_shared_memory_add(cf, &name, mcf->zone_size, &ngx_http_repsheet_bot_verifier_module);
    if (mcf->zone == NULL) {
        return NGX_CONF_ERROR;
    }
    if (mcf->zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "duplicate repsheet_bot_verifier zone");
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
    return lcf;
}


static char *
ngx_http_bot_verifier_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    bv_loc_conf_t             *prev = parent, *conf = child;
    ngx_http_core_loc_conf_t  *clcf;

    ngx_conf_merge_uint_value(conf->mode, prev->mode, BV_OFF);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 5000);

    if (conf->mode != BV_OFF) {
        /* The core module is merged first, so this location's resolver is final. */
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        if (clcf->resolver == NULL || clcf->resolver->connections.nelts == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "repsheet_bot_verifier needs a DNS resolver: add a \"resolver\" directive");
            return NGX_CONF_ERROR;
        }
    }
    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_bot_verifier_init_process(ngx_cycle_t *cycle)
{
    bv_main_conf_t *mcf;

    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE) {
        return NGX_OK;
    }

    mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_repsheet_bot_verifier_module);
    if (mcf == NULL || mcf->zone == NULL) {
        return NGX_OK;
    }
    bv_mcf = mcf;
    return bv_verify_init_process(cycle);
}


static void
ngx_http_bot_verifier_exit_process(ngx_cycle_t *cycle)
{
    if (bv_mcf == NULL) {
        return;
    }
    bv_verify_exit_process(cycle);
}

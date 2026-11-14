/*
 * Verification of one claimed crawler address, without blocking the worker.
 *
 *   shared-memory cache -> published ranges -> Redis cache (bounded wait)
 *     -> reverse DNS (name must be under one of the provider's domains)
 *     -> forward DNS (must return the client address)
 *
 * Requests that need a lookup are suspended (the handler returns NGX_AGAIN,
 * like limit_req's delay) and resumed when the result is known. Requests in
 * the same worker for the same address and provider share one lookup. A
 * lookup outlives its requests if they go away, so the result is still cached.
 */
#include "ngx_http_repsheet_bv.h"
#include "ngx_http_repsheet_redis.h"

#define BV_KEY_PREFIX "{repsheet}:bot_verifier:"

typedef struct {
    ngx_queue_t           link;         /* in bv_inflight */
    bv_addr_t             addr;
    ngx_sockaddr_t        sockaddr;
    socklen_t             socklen;
    bv_provider_t        *provider;
    ngx_queue_t           waiters;      /* bv_ctx_t.wait */
    ngx_resolver_t       *resolver;
    ngx_msec_t            timeout;
    ngx_resolver_ctx_t   *rctx;
    ngx_http_repsheet_pending_t  *pending;
    ngx_event_t           timer;        /* bounded wait for Redis */
    ngx_event_t           next;         /* posted: start the forward lookup */
    ngx_str_t             host;
    u_char                host_buf[256];
    ngx_log_t            *log;
    ngx_msec_t            started;
} bv_lookup_t;

static ngx_queue_t  bv_inflight;
static ngx_uint_t   bv_inflight_count;
static ngx_flag_t   bv_initialized;

static void bv_start_dns(bv_lookup_t *lk);


/* ------------------------------------------------------------------------ */
/* helpers                                                                   */
/* ------------------------------------------------------------------------ */

/*
 * How a cached verdict applies to a request claiming `provider`: an address
 * verified as one crawler fails a claim to be another; results recorded for a
 * different claim say nothing about this one.
 */
static ngx_flag_t
bv_cached_applies(bv_verdict_t *cached, ngx_uint_t provider, bv_verdict_t *out)
{
    if (cached->provider == provider) {
        *out = *cached;
        return 1;
    }
    if (cached->result == BV_VERIFIED) {
        out->result = BV_FAILED;
        out->provider = provider;
        return 1;
    }
    return 0;
}


/* "{repsheet}:bot_verifier:<address>" */
static ngx_str_t
bv_redis_key(bv_addr_t *addr, u_char *buf, size_t len)
{
    ngx_str_t  key;
    u_char    *p = ngx_cpymem(buf, BV_KEY_PREFIX, sizeof(BV_KEY_PREFIX) - 1);

    key.data = buf;
    key.len = (p - buf) + bv_addr_format(addr, p, len - (p - buf));
    return key;
}


/* Share a result with the other nginx servers: "<result>:<provider>". */
static void
bv_redis_put(bv_addr_t *addr, bv_verdict_t *v, time_t ttl)
{
    bv_provider_t  *p = bv_main_conf()->providers.elts;
    u_char          kbuf[96], vbuf[96];
    ngx_str_t       key = bv_redis_key(addr, kbuf, sizeof(kbuf)), value;

    value.data = vbuf;
    value.len = ngx_snprintf(vbuf, sizeof(vbuf), "%s:%V", bv_result_name(v->result), &p[v->provider].name)
                - vbuf;
    ngx_http_repsheet_client_set(&key, &value, ttl);
}


/* Parse a shared result; 0 if it is malformed or names an unknown provider. */
static ngx_flag_t
bv_redis_parse(ngx_str_t *value, bv_verdict_t *out)
{
    bv_main_conf_t  *mcf = bv_main_conf();
    bv_provider_t   *p = mcf->providers.elts;
    u_char          *colon;
    ngx_uint_t       i;
    size_t           rlen;
    const char      *n;

    colon = ngx_strlchr(value->data, value->data + value->len, ':');
    if (colon == NULL) {
        return 0;
    }
    rlen = colon - value->data;
    out->result = BV_NONE;
    for (i = BV_VERIFIED; i <= BV_UNKNOWN; i++) {
        n = bv_result_name(i);
        if (rlen == ngx_strlen(n) && ngx_strncmp(value->data, n, rlen) == 0) {
            out->result = i;
        }
    }
    if (out->result == BV_NONE) {
        return 0;
    }
    for (i = 0; i < mcf->providers.nelts; i++) {
        if (p[i].name.len == value->len - rlen - 1
            && ngx_strncmp(p[i].name.data, colon + 1, p[i].name.len) == 0)
        {
            out->provider = i;
            return 1;
        }
    }
    return 0;
}


static void
bv_resume(ngx_http_request_t *r)
{
    ngx_connection_t *c = r->connection;

    r->read_event_handler = ngx_http_block_reading;
    r->write_event_handler = ngx_http_core_run_phases;
    ngx_http_core_run_phases(r);
    ngx_http_run_posted_requests(c);
}


/* Request pool cleanup; also how the context is found again after an internal redirect. */
void
bv_ctx_cleanup(void *data)
{
    bv_ctx_t *ctx = data;

    if (ctx->waiting) {
        ngx_queue_remove(&ctx->wait);
        ctx->waiting = 0;
    }
}


static void
bv_record_duration(bv_source_e source, ngx_msec_t ms)
{
    static const ngx_msec_t  bounds[BV_BUCKETS] = BV_BUCKET_BOUNDS_MS;
    bv_counters_t           *c = &bv_cache()->sh->counters;
    ngx_uint_t               which, i;

    if (source == BV_SRC_REDIS) {
        which = BV_TIMED_REDIS;
    } else if (source == BV_SRC_DNS) {
        which = BV_TIMED_DNS;
    } else {
        return;
    }

    /* Buckets are not cumulative here; the metrics handler sums them. */
    for (i = 0; i < BV_BUCKETS && ms > bounds[i]; i++) { /* void */ }
    if (i < BV_BUCKETS) {
        (void) ngx_atomic_fetch_add(&c->duration_buckets[which][i], 1);
    }
    (void) ngx_atomic_fetch_add(&c->duration_sum_ms[which], ms);
    (void) ngx_atomic_fetch_add(&c->duration_count[which], 1);
}


static void
bv_finish(bv_lookup_t *lk, bv_result_e result, bv_source_e source, const char *fmt, ngx_str_t *arg)
{
    bv_main_conf_t      *mcf = bv_main_conf();
    bv_verdict_t         v = { result, lk->provider->index };
    bv_ctx_t            *ctx;
    ngx_queue_t         *q;
    u_char               reason[BV_REASON_MAX], addr[NGX_INET6_ADDRSTRLEN], *e;
    ngx_str_t            reason_str, addr_str;
    ngx_msec_t           elapsed = ngx_current_msec - lk->started;

    bv_record_duration(source, elapsed);

    if (lk->timer.timer_set) {
        ngx_del_timer(&lk->timer);
    }
    if (lk->next.posted) {
        ngx_delete_posted_event(&lk->next);
    }
    if (lk->pending) {
        ngx_http_repsheet_client_cancel(lk->pending);
        lk->pending = NULL;
    }

    ngx_queue_remove(&lk->link);
    bv_inflight_count--;

    bv_cache_put(bv_cache(), &lk->addr, &v, mcf->ttl[result]);

    if (source == BV_SRC_DNS || source == BV_SRC_RANGES) {
        e = ngx_snprintf(reason, sizeof(reason), "claimed %V: ", &lk->provider->name);
        e = arg ? ngx_snprintf(e, reason + sizeof(reason) - e, fmt, arg)
                : ngx_snprintf(e, reason + sizeof(reason) - e, fmt);
        reason_str.data = reason;
        reason_str.len = e - reason;
        addr_str.data = addr;
        addr_str.len = bv_addr_format(&lk->addr, addr, sizeof(addr));

        if (result == BV_FAILED) {
            ngx_log_error(NGX_LOG_WARN, lk->log, 0, "bot_verifier: %V failed verification, %V (%Mms)",
                          &addr_str, &reason_str, elapsed);
        } else if (result == BV_UNKNOWN) {
            ngx_log_error(NGX_LOG_INFO, lk->log, 0, "bot_verifier: %V could not be verified, %V (%Mms)",
                          &addr_str, &reason_str, elapsed);
        } else {
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, lk->log, 0, "bot_verifier: %V verified, %V (%Mms)", &addr_str,
                           &reason_str, elapsed);
        }

        if (result != BV_UNKNOWN) {
            bv_redis_put(&lk->addr, &v, mcf->ttl[result]);
        }
    } else {
        reason_str.len = 0;
        reason_str.data = reason;
    }

    while (!ngx_queue_empty(&lk->waiters)) {
        q = ngx_queue_head(&lk->waiters);
        ngx_queue_remove(q);
        ctx = ngx_queue_data(q, bv_ctx_t, wait);
        ctx->waiting = 0;
        ctx->verdict = v;
        ctx->source = source;
        ctx->waited = ngx_current_msec - ctx->started;
        if (result == BV_FAILED && reason_str.len) {
            /* Kept for the decision this request may record. */
            ctx->reason.data = ngx_pnalloc(ctx->request->pool, reason_str.len);
            if (ctx->reason.data) {
                ngx_memcpy(ctx->reason.data, reason_str.data, reason_str.len);
                ctx->reason.len = reason_str.len;
            }
        }
        if (!ctx->starting) {
            bv_resume(ctx->request);
        }
    }

    ngx_free(lk);
}


/* ------------------------------------------------------------------------ */
/* DNS                                                                       */
/* ------------------------------------------------------------------------ */

static void
bv_dns_error(bv_lookup_t *lk, ngx_int_t state, const char *what)
{
    (void) ngx_atomic_fetch_add(&bv_cache()->sh->counters.dns_errors, 1);
    lk->host.data = (u_char *) ngx_resolver_strerror(state);
    lk->host.len = ngx_strlen(lk->host.data);
    bv_finish(lk, BV_UNKNOWN, BV_SRC_DNS, what, &lk->host);
}


static void
bv_on_forward(ngx_resolver_ctx_t *rctx)
{
    bv_lookup_t  *lk = rctx->data;
    ngx_int_t     state = rctx->state;
    ngx_uint_t    i;
    ngx_flag_t    match = 0;

    if (state == 0) {
        for (i = 0; i < rctx->naddrs; i++) {
            if (ngx_cmp_sockaddr(rctx->addrs[i].sockaddr, rctx->addrs[i].socklen, &lk->sockaddr.sockaddr,
                                 lk->socklen, 0) == NGX_OK)
            {
                match = 1;
                break;
            }
        }
    }

    ngx_resolve_name_done(rctx);
    lk->rctx = NULL;

    if (state == NGX_RESOLVE_NXDOMAIN) {
        bv_finish(lk, BV_FAILED, BV_SRC_DNS, "%V does not resolve", &lk->host);
    } else if (state) {
        bv_dns_error(lk, state, "forward lookup failed: %V");
    } else if (match) {
        bv_finish(lk, BV_VERIFIED, BV_SRC_DNS, "%V", &lk->host);
    } else {
        bv_finish(lk, BV_FAILED, BV_SRC_DNS, "%V does not resolve to the client address", &lk->host);
    }
}


static void
bv_start_forward(ngx_event_t *ev)
{
    bv_lookup_t         *lk = ev->data;
    ngx_resolver_ctx_t  *rctx;

    rctx = ngx_resolve_start(lk->resolver, NULL);
    if (rctx == NULL || rctx == NGX_NO_RESOLVER) {
        bv_finish(lk, BV_UNKNOWN, BV_SRC_DNS, "no resolver", NULL);
        return;
    }

    rctx->name = lk->host;
    rctx->handler = bv_on_forward;
    rctx->data = lk;
    rctx->timeout = lk->timeout;
    lk->rctx = rctx;
    (void) ngx_atomic_fetch_add(&bv_cache()->sh->counters.dns_lookups, 1);

    if (ngx_resolve_name(rctx) != NGX_OK) {
        /* ngx_resolve_name frees the context on failure. */
        lk->rctx = NULL;
        bv_finish(lk, BV_UNKNOWN, BV_SRC_DNS, "forward lookup could not start", NULL);
    }
}


static void
bv_on_reverse(ngx_resolver_ctx_t *rctx)
{
    bv_lookup_t  *lk = rctx->data;
    ngx_int_t     state = rctx->state;
    ngx_flag_t    ok = 0;

    if (state == 0) {
        ok = bv_domain_matches(lk->provider, &rctx->name);
        lk->host.len = ngx_min(rctx->name.len, sizeof(lk->host_buf));
        lk->host.data = lk->host_buf;
        ngx_memcpy(lk->host_buf, rctx->name.data, lk->host.len);
        /* The resolver may return a trailing dot. */
        if (lk->host.len && lk->host.data[lk->host.len - 1] == '.') {
            lk->host.len--;
        }
    }

    ngx_resolve_addr_done(rctx);
    lk->rctx = NULL;

    if (state == NGX_RESOLVE_NXDOMAIN) {
        bv_finish(lk, BV_FAILED, BV_SRC_DNS, "no reverse DNS", NULL);
    } else if (state) {
        bv_dns_error(lk, state, "reverse lookup failed: %V");
    } else if (!ok) {
        bv_finish(lk, BV_FAILED, BV_SRC_DNS, "reverse DNS %V is not one of its domains", &lk->host);
    } else {
        /* As in ngx_mail_smtp_handler: start the next query outside this handler. */
        ngx_post_event(&lk->next, &ngx_posted_events);
    }
}


static void
bv_start_dns(bv_lookup_t *lk)
{
    ngx_resolver_ctx_t *rctx;

    if (lk->resolver == NULL) {
        bv_finish(lk, BV_UNKNOWN, BV_SRC_DNS, "no resolver", NULL);
        return;
    }

    rctx = ngx_resolve_start(lk->resolver, NULL);
    if (rctx == NULL || rctx == NGX_NO_RESOLVER) {
        bv_finish(lk, BV_UNKNOWN, BV_SRC_DNS, "no resolver", NULL);
        return;
    }

    rctx->addr.sockaddr = &lk->sockaddr.sockaddr;
    rctx->addr.socklen = lk->socklen;
    rctx->handler = bv_on_reverse;
    rctx->data = lk;
    rctx->timeout = lk->timeout;
    lk->rctx = rctx;
    (void) ngx_atomic_fetch_add(&bv_cache()->sh->counters.dns_lookups, 1);

    if (ngx_resolve_addr(rctx) != NGX_OK) {
        /* ngx_resolve_addr frees the context on failure. */
        lk->rctx = NULL;
        bv_finish(lk, BV_UNKNOWN, BV_SRC_DNS, "reverse lookup could not start", NULL);
    }
}


/* ------------------------------------------------------------------------ */
/* Redis tier                                                                */
/* ------------------------------------------------------------------------ */

static void
bv_on_redis(void *data, ngx_str_t *value)
{
    bv_lookup_t   *lk = data;
    bv_verdict_t   v, cached;

    lk->pending = NULL;
    if (lk->timer.timer_set) {
        ngx_del_timer(&lk->timer);
    }

    if (value && bv_redis_parse(value, &cached) && bv_cached_applies(&cached, lk->provider->index, &v)) {
        bv_finish(lk, v.result, BV_SRC_REDIS, "", NULL);
        return;
    }
    bv_start_dns(lk);
}


static void
bv_redis_timeout(ngx_event_t *ev)
{
    bv_lookup_t *lk = ev->data;

    if (lk->pending) {
        ngx_http_repsheet_client_cancel(lk->pending);
        lk->pending = NULL;
    }
    bv_start_dns(lk);
}


/* ------------------------------------------------------------------------ */
/* entry point                                                               */
/* ------------------------------------------------------------------------ */

static void
bv_make_sockaddr(bv_addr_t *addr, ngx_sockaddr_t *sa, socklen_t *len)
{
    ngx_memzero(sa, sizeof(ngx_sockaddr_t));
    if (addr->family == AF_INET) {
        sa->sockaddr_in.sin_family = AF_INET;
        ngx_memcpy(&sa->sockaddr_in.sin_addr, addr->addr, 4);
        *len = sizeof(struct sockaddr_in);
#if (NGX_HAVE_INET6)
    } else {
        sa->sockaddr_in6.sin6_family = AF_INET6;
        ngx_memcpy(&sa->sockaddr_in6.sin6_addr, addr->addr, 16);
        *len = sizeof(struct sockaddr_in6);
#endif
    }
}


/*
 * Returns NGX_OK with ctx->verdict set, or NGX_AGAIN if the request has been
 * suspended and will be resumed when the result is known.
 */
ngx_int_t
bv_verify(ngx_http_request_t *r, bv_ctx_t *ctx, bv_provider_t *provider, bv_addr_t *addr, struct sockaddr *sa,
          socklen_t socklen)
{
    bv_main_conf_t            *mcf = bv_main_conf();
    bv_loc_conf_t             *lcf;
    ngx_http_core_loc_conf_t  *clcf;
    bv_verdict_t               cached;
    bv_lookup_t               *lk;
    ngx_queue_t               *q;

    ctx->verdict.provider = provider->index;
    ctx->addr = *addr;

    /* 1. shared memory */
    if (bv_cache_get(bv_cache(), addr, &cached) && bv_cached_applies(&cached, provider->index, &ctx->verdict)) {
        ctx->source = BV_SRC_ZONE;
        return NGX_OK;
    }

    /* 2. published ranges */
    if (provider->ranges && ngx_cidr_match(sa, provider->ranges) == NGX_OK) {
        ctx->verdict.result = BV_VERIFIED;
        ctx->source = BV_SRC_RANGES;
        bv_cache_put(bv_cache(), addr, &ctx->verdict, mcf->ttl[BV_VERIFIED]);
        return NGX_OK;
    }

    if (provider->domains->nelts == 0) {
        /* Ranges are the only evidence for this provider. */
        ctx->verdict.result = provider->ranges ? BV_FAILED : BV_UNKNOWN;
        ctx->source = BV_SRC_RANGES;
        bv_cache_put(bv_cache(), addr, &ctx->verdict, mcf->ttl[ctx->verdict.result]);
        if (ctx->verdict.result == BV_FAILED) {
            u_char     a[NGX_INET6_ADDRSTRLEN];
            ngx_str_t  as = { bv_addr_format(addr, a, sizeof(a)), a };
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "bot_verifier: %V failed verification, claimed %V: not in its published ranges",
                          &as, &provider->name);
            ctx->reason.data = ngx_pnalloc(r->pool, BV_REASON_MAX);
            if (ctx->reason.data) {
                ctx->reason.len = ngx_snprintf(ctx->reason.data, BV_REASON_MAX,
                                               "claimed %V: not in its published ranges", &provider->name)
                                  - ctx->reason.data;
            }
        }
        return NGX_OK;
    }

    ctx->request = r;
    ctx->started = ngx_current_msec;

    /* 3. join a lookup in progress */
    for (q = ngx_queue_head(&bv_inflight); q != ngx_queue_sentinel(&bv_inflight); q = ngx_queue_next(q)) {
        lk = ngx_queue_data(q, bv_lookup_t, link);
        if (lk->provider == provider && lk->addr.family == addr->family
            && ngx_memcmp(lk->addr.addr, addr->addr, 16) == 0)
        {
            ngx_queue_insert_tail(&lk->waiters, &ctx->wait);
            ctx->waiting = 1;
            return NGX_AGAIN;
        }
    }

    if (bv_inflight_count >= BV_MAX_INFLIGHT) {
        ctx->verdict.result = BV_UNKNOWN;
        ctx->source = BV_SRC_NONE;
        return NGX_OK;
    }

    /* 4. new lookup */
    lk = ngx_calloc(sizeof(bv_lookup_t), ngx_cycle->log);
    if (lk == NULL) {
        return NGX_ERROR;
    }

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_repsheet_bot_verifier_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    lk->addr = *addr;
    bv_make_sockaddr(addr, &lk->sockaddr, &lk->socklen);
    lk->provider = provider;
    lk->resolver = clcf->resolver;
    lk->timeout = lcf->timeout;
    lk->log = ngx_cycle->log;
    lk->started = ngx_current_msec;
    ngx_queue_init(&lk->waiters);
    lk->timer.handler = bv_redis_timeout;
    lk->timer.data = lk;
    lk->timer.log = lk->log;
    lk->next.handler = bv_start_forward;
    lk->next.data = lk;
    lk->next.log = lk->log;

    ngx_queue_insert_tail(&bv_inflight, &lk->link);
    bv_inflight_count++;

    ngx_queue_insert_tail(&lk->waiters, &ctx->wait);
    ctx->waiting = 1;

    /* The lookup can finish before these calls return (resolver cache hit). */
    ctx->starting = 1;
    {
        u_char     kbuf[96];
        ngx_str_t  key = bv_redis_key(addr, kbuf, sizeof(kbuf));
        lk->pending = ngx_http_repsheet_client_get(&key, bv_on_redis, lk);
    }
    if (lk->pending) {
        ngx_add_timer(&lk->timer, mcf->cache_timeout);
    } else {
        bv_start_dns(lk);
    }
    ctx->starting = 0;

    return ctx->waiting ? NGX_AGAIN : NGX_OK;
}


ngx_int_t
bv_verify_init_process(ngx_cycle_t *cycle)
{
    ngx_queue_init(&bv_inflight);
    bv_inflight_count = 0;
    bv_initialized = 1;
    return NGX_OK;
}


void
bv_verify_exit_process(ngx_cycle_t *cycle)
{
    ngx_queue_t  *q;
    bv_lookup_t  *lk;

    if (!bv_initialized) {
        return;
    }

    /* Requests are gone by now; release any lookups that are still running. */
    while (!ngx_queue_empty(&bv_inflight)) {
        q = ngx_queue_head(&bv_inflight);
        lk = ngx_queue_data(q, bv_lookup_t, link);
        ngx_queue_remove(q);
        if (lk->timer.timer_set) {
            ngx_del_timer(&lk->timer);
        }
        if (lk->next.posted) {
            ngx_delete_posted_event(&lk->next);
        }
        if (lk->pending) {
            ngx_http_repsheet_client_cancel(lk->pending);
        }
        if (lk->rctx) {
            if (lk->rctx->handler == bv_on_reverse) {
                ngx_resolve_addr_done(lk->rctx);
            } else {
                ngx_resolve_name_done(lk->rctx);
            }
        }
        ngx_free(lk);
    }
    bv_inflight_count = 0;
}

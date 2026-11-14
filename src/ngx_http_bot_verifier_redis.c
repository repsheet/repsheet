/*
 * Optional Valkey/Redis tier: a result cache shared by every nginx server,
 * and reporting of failed verifications to Repsheet.
 *
 * Every worker keeps one non-blocking hiredis connection driven by the nginx
 * event loop. Requests wait for a cache read at most bot_verifier_redis_timeout;
 * writes and reports are fire-and-forget. While Redis is unavailable the
 * module works from the shared-memory cache and DNS alone.
 */
#include "ngx_http_bot_verifier.h"

#include <hiredis/hiredis.h>
#include <hiredis/async.h>

#define BV_KEY_PREFIX "{bot_verifier}:"
#define BV_MAX_PENDING 10000
#define BV_MAX_BACKOFF 30000
#define BV_TICK 1000

typedef struct {
    ngx_connection_t   *conn;
    redisAsyncContext  *ac;
} bv_adapter_t;

struct bv_redis_pending_s {
    bv_redis_get_pt  handler;
    void            *data;      /* NULL once cancelled */
};

static struct {
    bv_main_conf_t     *conf;
    ngx_log_t          *log;
    redisAsyncContext  *ac;
    ngx_flag_t          ready;
    ngx_event_t         timer;
    ngx_msec_t          backoff;
    ngx_msec_t          last_reply;
    ngx_uint_t          outstanding;
    ngx_flag_t          report_error_logged;
} rd;


/* ------------------------------------------------------------------------ */
/* hiredis <-> nginx event loop                                              */
/* ------------------------------------------------------------------------ */

static void
bv_adapter_read(ngx_event_t *ev)
{
    ngx_connection_t *c = ev->data;
    redisAsyncHandleRead(c->data);
}


static void
bv_adapter_write(ngx_event_t *ev)
{
    ngx_connection_t *c = ev->data;
    redisAsyncHandleWrite(c->data);
}


static void
bv_adapter_add_read(void *privdata)
{
    bv_adapter_t *a = privdata;
    if (!a->conn->read->active) {
        ngx_add_event(a->conn->read, NGX_READ_EVENT, NGX_LEVEL_EVENT);
    }
}


static void
bv_adapter_del_read(void *privdata)
{
    bv_adapter_t *a = privdata;
    if (a->conn->read->active) {
        ngx_del_event(a->conn->read, NGX_READ_EVENT, 0);
    }
}


static void
bv_adapter_add_write(void *privdata)
{
    bv_adapter_t *a = privdata;
    if (!a->conn->write->active) {
        ngx_add_event(a->conn->write, NGX_WRITE_EVENT, NGX_LEVEL_EVENT);
    }
}


static void
bv_adapter_del_write(void *privdata)
{
    bv_adapter_t *a = privdata;
    if (a->conn->write->active) {
        ngx_del_event(a->conn->write, NGX_WRITE_EVENT, 0);
    }
}


static void
bv_adapter_cleanup(void *privdata)
{
    bv_adapter_t *a = privdata;

    bv_adapter_del_read(a);
    bv_adapter_del_write(a);
    if (a->conn->read->posted) {
        ngx_delete_posted_event(a->conn->read);
    }
    if (a->conn->write->posted) {
        ngx_delete_posted_event(a->conn->write);
    }
    a->conn->fd = (ngx_socket_t) -1;
    ngx_free_connection(a->conn);
    ngx_free(a);
}


static ngx_int_t
bv_adapter_attach(redisAsyncContext *ac, ngx_log_t *log)
{
    bv_adapter_t      *a;
    ngx_connection_t  *c;

    a = ngx_alloc(sizeof(bv_adapter_t), log);
    if (a == NULL) {
        return NGX_ERROR;
    }

    c = ngx_get_connection(ac->c.fd, log);
    if (c == NULL) {
        ngx_free(a);
        return NGX_ERROR;
    }

    c->data = ac;
    c->read->handler = bv_adapter_read;
    c->write->handler = bv_adapter_write;
    c->read->log = log;
    c->write->log = log;

    a->conn = c;
    a->ac = ac;

    ac->ev.data = a;
    ac->ev.addRead = bv_adapter_add_read;
    ac->ev.delRead = bv_adapter_del_read;
    ac->ev.addWrite = bv_adapter_add_write;
    ac->ev.delWrite = bv_adapter_del_write;
    ac->ev.cleanup = bv_adapter_cleanup;
    return NGX_OK;
}


/* ------------------------------------------------------------------------ */
/* connection                                                                */
/* ------------------------------------------------------------------------ */

static void
bv_redis_failed(const char *what, redisReply *reply)
{
    (void) ngx_atomic_fetch_add(&bv_cache()->sh->counters.redis_errors, 1);
    if (reply && reply->type == REDIS_REPLY_ERROR) {
        ngx_log_error(NGX_LOG_ERR, rd.log, 0, "bot_verifier: redis %s failed: %s", what, reply->str);
    } else {
        ngx_log_error(NGX_LOG_ERR, rd.log, 0, "bot_verifier: redis %s failed", what);
    }
}


static void
bv_redis_drop(void)
{
    /* Safe inside callbacks: hiredis defers the free. Pending callbacks get NULL. */
    if (rd.ac) {
        redisAsyncDisconnect(rd.ac);
    }
}


static void
bv_on_connect(const redisAsyncContext *ac, int status)
{
    if (status != REDIS_OK) {
        ngx_log_error(NGX_LOG_ERR, rd.log, 0, "bot_verifier: could not connect to redis: %s", ac->errstr);
        (void) ngx_atomic_fetch_add(&bv_cache()->sh->counters.redis_errors, 1);
        /* hiredis frees the context after this; the disconnect callback is not called. */
        if (ac == rd.ac) {
            rd.ac = NULL;
            rd.ready = 0;
            rd.outstanding = 0;
        }
    }
}


static void
bv_on_disconnect(const redisAsyncContext *ac, int status)
{
    if (ac == rd.ac) {
        if (status != REDIS_OK && !ngx_exiting && !ngx_quit && !ngx_terminate) {
            ngx_log_error(NGX_LOG_WARN, rd.log, 0, "bot_verifier: redis connection lost: %s",
                          ac->errstr[0] ? ac->errstr : "closed");
        }
        rd.ac = NULL;
        rd.ready = 0;
        rd.outstanding = 0;
    }
}


static void
bv_on_ping(redisAsyncContext *ac, void *r, void *privdata)
{
    redisReply *reply = r;

    if (ac != rd.ac || reply == NULL) {
        return;
    }
    if (reply->type == REDIS_REPLY_ERROR) {
        bv_redis_failed("AUTH/PING", reply);
        bv_redis_drop();
        return;
    }
    rd.ready = 1;
    rd.backoff = 0;
    rd.last_reply = ngx_current_msec;
}


static void
bv_redis_connect(void)
{
    bv_main_conf_t     *conf = rd.conf;
    redisAsyncContext  *ac;
    redisOptions        options = {0};
    struct timeval      tv = { 1, 0 };
    u_char              host[NGX_MAXHOSTNAMELEN + 1];
    u_char              path[NGX_MAX_PATH + 1];

    if (conf->redis_unix.len) {
        ngx_cpystrn(path, conf->redis_unix.data, ngx_min(conf->redis_unix.len + 1, sizeof(path)));
        REDIS_OPTIONS_SET_UNIX(&options, (char *) path);
    } else {
        ngx_cpystrn(host, conf->redis_host.data, ngx_min(conf->redis_host.len + 1, sizeof(host)));
        REDIS_OPTIONS_SET_TCP(&options, (char *) host, (int) conf->redis_port);
    }
    options.connect_timeout = &tv;

    ac = redisAsyncConnectWithOptions(&options);
    if (ac == NULL) {
        return;
    }
    if (ac->err) {
        ngx_log_error(NGX_LOG_ERR, rd.log, 0, "bot_verifier: could not connect to redis: %s", ac->errstr);
        redisAsyncFree(ac);
        return;
    }
    if (bv_adapter_attach(ac, rd.log) != NGX_OK) {
        redisAsyncFree(ac);
        return;
    }

    redisAsyncSetConnectCallback(ac, bv_on_connect);
    redisAsyncSetDisconnectCallback(ac, bv_on_disconnect);
    rd.ac = ac;
    rd.ready = 0;
    rd.outstanding = 0;
    rd.last_reply = ngx_current_msec;

    if (conf->redis_password.len) {
        if (conf->redis_user.len) {
            redisAsyncCommand(ac, NULL, NULL, "AUTH %b %b", conf->redis_user.data, conf->redis_user.len,
                              conf->redis_password.data, conf->redis_password.len);
        } else {
            redisAsyncCommand(ac, NULL, NULL, "AUTH %b", conf->redis_password.data, conf->redis_password.len);
        }
    }
    /* Errors from AUTH make every later command fail too, so PING is enough. */
    redisAsyncCommand(ac, bv_on_ping, NULL, "PING");
}


static void
bv_redis_tick(ngx_event_t *ev)
{
    if (ngx_exiting || ngx_quit || ngx_terminate) {
        return;
    }

    if (rd.ac == NULL) {
        bv_redis_connect();
        if (rd.ac == NULL) {
            rd.backoff = rd.backoff ? ngx_min(rd.backoff * 2, BV_MAX_BACKOFF) : BV_TICK;
            ngx_add_timer(&rd.timer, rd.backoff);
            return;
        }
    } else if (rd.outstanding && ngx_current_msec - rd.last_reply > ngx_max(10 * rd.conf->redis_timeout, 2000)) {
        ngx_log_error(NGX_LOG_ERR, rd.log, 0, "bot_verifier: redis stopped answering, reconnecting");
        (void) ngx_atomic_fetch_add(&bv_cache()->sh->counters.redis_errors, 1);
        bv_redis_drop();
    } else if (!rd.ready && ngx_current_msec - rd.last_reply > 5000) {
        ngx_log_error(NGX_LOG_ERR, rd.log, 0, "bot_verifier: redis did not become ready, reconnecting");
        bv_redis_drop();
    }

    ngx_add_timer(&rd.timer, BV_TICK);
}


ngx_int_t
bv_redis_init_process(ngx_cycle_t *cycle, bv_main_conf_t *mcf)
{
    ngx_memzero(&rd, sizeof(rd));
    if (!mcf->redis) {
        return NGX_OK;
    }

    rd.conf = mcf;
    rd.log = cycle->log;
    rd.timer.handler = bv_redis_tick;
    rd.timer.log = cycle->log;
    rd.timer.data = &rd;
    rd.timer.cancelable = 1;

    bv_redis_connect();
    ngx_add_timer(&rd.timer, BV_TICK);
    return NGX_OK;
}


void
bv_redis_exit_process(void)
{
    redisAsyncContext *ac = rd.ac;

    if (rd.conf == NULL) {
        return;
    }
    if (rd.timer.timer_set) {
        ngx_del_timer(&rd.timer);
    }
    rd.ac = NULL;
    rd.ready = 0;
    if (ac) {
        redisAsyncFree(ac);
    }
}


ngx_flag_t
bv_redis_ready(void)
{
    return rd.ac != NULL && rd.ready && rd.outstanding < BV_MAX_PENDING;
}


/* ------------------------------------------------------------------------ */
/* commands                                                                  */
/* ------------------------------------------------------------------------ */

static size_t
bv_key(bv_addr_t *addr, u_char *buf, size_t len)
{
    u_char *p = ngx_cpymem(buf, BV_KEY_PREFIX, sizeof(BV_KEY_PREFIX) - 1);
    return (p - buf) + bv_addr_format(addr, p, len - (p - buf));
}


static void
bv_on_get(redisAsyncContext *ac, void *r, void *privdata)
{
    bv_redis_pending_t  *pending = privdata;
    redisReply          *reply = r;
    bv_verdict_t         v = { BV_NONE, 0 };
    bv_main_conf_t      *mcf = rd.conf;
    bv_provider_t       *p;
    ngx_flag_t           found = 0;
    ngx_uint_t           i;
    char                *colon;

    if (ac == rd.ac && rd.outstanding) {
        rd.outstanding--;
        rd.last_reply = ngx_current_msec;
    }

    if (reply && reply->type == REDIS_REPLY_STRING && (colon = memchr(reply->str, ':', reply->len))) {
        ngx_str_t result = { (size_t) (colon - reply->str), (u_char *) reply->str };
        ngx_str_t name = { reply->len - result.len - 1, (u_char *) colon + 1 };

        v.result = BV_NONE;
        for (i = BV_VERIFIED; i <= BV_UNKNOWN; i++) {
            const char *n = bv_result_name(i);
            if (result.len == ngx_strlen(n) && ngx_strncmp(result.data, n, result.len) == 0) {
                v.result = i;
            }
        }
        p = mcf->providers.elts;
        for (i = 0; v.result != BV_NONE && i < mcf->providers.nelts; i++) {
            if (p[i].name.len == name.len && ngx_strncmp(p[i].name.data, name.data, name.len) == 0) {
                v.provider = i;
                found = 1;
                break;
            }
        }
    } else if (reply && reply->type == REDIS_REPLY_ERROR) {
        bv_redis_failed("GET", reply);
    }

    if (pending->data) {
        pending->handler(pending->data, found, &v);
    }
    ngx_free(pending);
}


bv_redis_pending_t *
bv_redis_get(bv_addr_t *addr, bv_redis_get_pt handler, void *data)
{
    bv_redis_pending_t  *pending;
    u_char               key[128];
    size_t               len;

    if (!bv_redis_ready()) {
        return NULL;
    }

    pending = ngx_alloc(sizeof(bv_redis_pending_t), rd.log);
    if (pending == NULL) {
        return NULL;
    }
    pending->handler = handler;
    pending->data = data;

    len = bv_key(addr, key, sizeof(key));
    if (redisAsyncCommand(rd.ac, bv_on_get, pending, "GET %b", key, len) != REDIS_OK) {
        ngx_free(pending);
        return NULL;
    }
    rd.outstanding++;
    return pending;
}


void
bv_redis_cancel(bv_redis_pending_t *pending)
{
    /* The reply (or disconnect) still arrives and frees it. */
    pending->data = NULL;
}


static void
bv_on_write(redisAsyncContext *ac, void *r, void *privdata)
{
    redisReply *reply = r;

    if (ac == rd.ac && rd.outstanding) {
        rd.outstanding--;
        rd.last_reply = ngx_current_msec;
    }
    if (reply && reply->type == REDIS_REPLY_ERROR) {
        bv_redis_failed("SET", reply);
    }
}


void
bv_redis_put(bv_addr_t *addr, bv_verdict_t *v, time_t ttl)
{
    bv_provider_t  *p;
    u_char          key[128], value[128], *e;
    size_t          klen;

    if (!bv_redis_ready() || ttl <= 0) {
        return;
    }
    p = rd.conf->providers.elts;
    klen = bv_key(addr, key, sizeof(key));
    e = ngx_snprintf(value, sizeof(value), "%s:%V", bv_result_name(v->result), &p[v->provider].name);

    if (redisAsyncCommand(rd.ac, bv_on_write, NULL, "SET %b %b EX %d", key, klen, value, (size_t) (e - value),
                          (int) ttl) == REDIS_OK)
    {
        rd.outstanding++;
    }
}


static void
bv_on_report(redisAsyncContext *ac, void *r, void *privdata)
{
    redisReply *reply = r;

    if (ac == rd.ac && rd.outstanding) {
        rd.outstanding--;
        rd.last_reply = ngx_current_msec;
    }
    if (reply && reply->type == REDIS_REPLY_ERROR) {
        (void) ngx_atomic_fetch_add(&bv_cache()->sh->counters.redis_errors, 1);
        if (!rd.report_error_logged) {
            /* Usually: the Repsheet module is not loaded. Say so once per worker. */
            ngx_log_error(NGX_LOG_ERR, rd.log, 0,
                          "bot_verifier: reporting to repsheet failed: %s (is the repsheet module loaded?)",
                          reply->str);
            rd.report_error_logged = 1;
        }
    } else if (reply) {
        (void) ngx_atomic_fetch_add(&bv_cache()->sh->counters.reports, 1);
    }
}


void
bv_redis_report(bv_addr_t *addr, ngx_str_t *reason)
{
    u_char  actor[64], *e;

    if (!bv_redis_ready() || !rd.conf->repsheet) {
        return;
    }

    e = ngx_cpymem(actor, "ip:", 3);
    e += bv_addr_format(addr, e, sizeof(actor) - 3);

    if (redisAsyncCommand(rd.ac, bv_on_report, NULL, "%s %b REASON %b TTL %d BY bot_verifier",
                          rd.conf->repsheet_block ? "REPSHEET.BLOCK" : "REPSHEET.MARK", actor,
                          (size_t) (e - actor), reason->data, reason->len, (int) rd.conf->repsheet_ttl)
        == REDIS_OK)
    {
        rd.outstanding++;
    }
}

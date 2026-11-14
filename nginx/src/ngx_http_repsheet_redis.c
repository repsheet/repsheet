/*
 * Valkey/Redis plumbing shared by the sync loop and the active detectors:
 *
 *   - the hiredis <-> nginx event loop adapter;
 *   - connecting with the repsheet_redis / repsheet_redis_auth settings;
 *   - a per-worker client for detectors: cache reads with a bounded wait
 *     (the caller's timer), fire-and-forget writes, and recording decisions.
 *
 * The detector client runs in every worker, but only when a detector is
 * enabled. While Redis is unavailable, detectors work from local state and
 * recorded decisions still apply to this nginx right away.
 */
#include "ngx_http_repsheet_redis.h"

#define CLIENT_MAX_PENDING 10000
#define CLIENT_MAX_BACKOFF 30000
#define CLIENT_TICK 1000

typedef struct {
    ngx_connection_t   *conn;
    redisAsyncContext  *ac;
} adapter_t;

struct ngx_http_repsheet_pending_s {
    ngx_http_repsheet_get_pt  handler;
    void                     *data;      /* NULL once cancelled */
};

static struct {
    ngx_http_repsheet_main_conf_t  *conf;
    ngx_log_t                      *log;
    redisAsyncContext              *ac;
    ngx_flag_t                      ready;
    ngx_event_t                     timer;
    ngx_msec_t                      backoff;
    ngx_msec_t                      last_reply;
    ngx_uint_t                      outstanding;
    ngx_flag_t                      record_error_logged;
    ngx_flag_t                      closing;    /* exiting: do not call back */
} client;


/* ------------------------------------------------------------------------ */
/* hiredis <-> nginx event loop                                              */
/* ------------------------------------------------------------------------ */

static void
adapter_read(ngx_event_t *ev)
{
    ngx_connection_t *c = ev->data;
    redisAsyncHandleRead(c->data);
}


static void
adapter_write(ngx_event_t *ev)
{
    ngx_connection_t *c = ev->data;
    redisAsyncHandleWrite(c->data);
}


static void
adapter_add_read(void *privdata)
{
    adapter_t *a = privdata;
    if (!a->conn->read->active) {
        ngx_add_event(a->conn->read, NGX_READ_EVENT, NGX_LEVEL_EVENT);
    }
}


static void
adapter_del_read(void *privdata)
{
    adapter_t *a = privdata;
    if (a->conn->read->active) {
        ngx_del_event(a->conn->read, NGX_READ_EVENT, 0);
    }
}


static void
adapter_add_write(void *privdata)
{
    adapter_t *a = privdata;
    if (!a->conn->write->active) {
        ngx_add_event(a->conn->write, NGX_WRITE_EVENT, NGX_LEVEL_EVENT);
    }
}


static void
adapter_del_write(void *privdata)
{
    adapter_t *a = privdata;
    if (a->conn->write->active) {
        ngx_del_event(a->conn->write, NGX_WRITE_EVENT, 0);
    }
}


/* Called by hiredis before it closes the socket. */
static void
adapter_cleanup(void *privdata)
{
    adapter_t *a = privdata;

    adapter_del_read(a);
    adapter_del_write(a);
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


ngx_int_t
ngx_http_repsheet_redis_attach(redisAsyncContext *ac, ngx_log_t *log)
{
    adapter_t         *a;
    ngx_connection_t  *c;

    a = ngx_alloc(sizeof(adapter_t), log);
    if (a == NULL) {
        return NGX_ERROR;
    }

    c = ngx_get_connection(ac->c.fd, log);
    if (c == NULL) {
        ngx_free(a);
        return NGX_ERROR;
    }

    c->data = ac;
    c->read->handler = adapter_read;
    c->write->handler = adapter_write;
    c->read->log = log;
    c->write->log = log;

    a->conn = c;
    a->ac = ac;

    ac->ev.data = a;
    ac->ev.addRead = adapter_add_read;
    ac->ev.delRead = adapter_del_read;
    ac->ev.addWrite = adapter_add_write;
    ac->ev.delWrite = adapter_del_write;
    ac->ev.cleanup = adapter_cleanup;
    return NGX_OK;
}


redisAsyncContext *
ngx_http_repsheet_redis_connect(ngx_http_repsheet_main_conf_t *conf, ngx_log_t *log,
    redisConnectCallback *on_connect, redisDisconnectCallback *on_disconnect, redisCallbackFn *on_auth)
{
    redisAsyncContext  *ac;
    redisOptions        options = {0};
    struct timeval      tv = { 1, 0 };
    u_char              host[NGX_MAXHOSTNAMELEN + 1];
    u_char              path[NGX_MAX_PATH + 1];

    if (conf->redis.unix_path.len) {
        ngx_cpystrn(path, conf->redis.unix_path.data, ngx_min(conf->redis.unix_path.len + 1, sizeof(path)));
        REDIS_OPTIONS_SET_UNIX(&options, (char *) path);
    } else {
        ngx_cpystrn(host, conf->redis.host.data, ngx_min(conf->redis.host.len + 1, sizeof(host)));
        REDIS_OPTIONS_SET_TCP(&options, (char *) host, (int) conf->redis.port);
    }
    options.connect_timeout = &tv;

    ac = redisAsyncConnectWithOptions(&options);
    if (ac == NULL) {
        return NULL;
    }
    if (ac->err) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "repsheet: could not connect to redis: %s", ac->errstr);
        redisAsyncFree(ac);
        return NULL;
    }
    if (ngx_http_repsheet_redis_attach(ac, log) != NGX_OK) {
        redisAsyncFree(ac);
        return NULL;
    }

    redisAsyncSetConnectCallback(ac, on_connect);
    redisAsyncSetDisconnectCallback(ac, on_disconnect);

    if (conf->redis.password.len) {
        if (conf->redis.user.len) {
            redisAsyncCommand(ac, on_auth, NULL, "AUTH %b %b", conf->redis.user.data, conf->redis.user.len,
                              conf->redis.password.data, conf->redis.password.len);
        } else {
            redisAsyncCommand(ac, on_auth, NULL, "AUTH %b", conf->redis.password.data,
                              conf->redis.password.len);
        }
    }
    return ac;
}


/* ------------------------------------------------------------------------ */
/* detector client                                                           */
/* ------------------------------------------------------------------------ */

static ngx_http_repsheet_counters_t *
client_counters(void)
{
    return &((ngx_http_repsheet_store_t *) client.conf->zone->data)->sh->counters;
}


static void
client_failed(const char *what, redisReply *reply)
{
    (void) ngx_atomic_fetch_add(&client_counters()->detector_redis_errors, 1);
    if (reply && reply->type == REDIS_REPLY_ERROR) {
        ngx_log_error(NGX_LOG_ERR, client.log, 0, "repsheet: detector %s failed: %s", what, reply->str);
    } else {
        ngx_log_error(NGX_LOG_ERR, client.log, 0, "repsheet: detector %s failed", what);
    }
}


static void
client_drop(void)
{
    /* Safe inside callbacks: hiredis defers the free. Pending callbacks get NULL. */
    if (client.ac) {
        redisAsyncDisconnect(client.ac);
    }
}


static void
client_replied(const redisAsyncContext *ac)
{
    if (ac == client.ac && client.outstanding) {
        client.outstanding--;
        client.last_reply = ngx_current_msec;
    }
}


static void
client_on_connect(const redisAsyncContext *ac, int status)
{
    if (status != REDIS_OK) {
        ngx_log_error(NGX_LOG_ERR, client.log, 0, "repsheet: detector client could not connect to redis: %s",
                      ac->errstr);
        (void) ngx_atomic_fetch_add(&client_counters()->detector_redis_errors, 1);
        /* hiredis frees the context after this; the disconnect callback is not called. */
        if (ac == client.ac) {
            client.ac = NULL;
            client.ready = 0;
            client.outstanding = 0;
        }
    }
}


static void
client_on_disconnect(const redisAsyncContext *ac, int status)
{
    if (ac == client.ac) {
        if (status != REDIS_OK && !ngx_exiting && !ngx_quit && !ngx_terminate) {
            ngx_log_error(NGX_LOG_WARN, client.log, 0, "repsheet: detector client lost redis: %s",
                          ac->errstr[0] ? ac->errstr : "closed");
        }
        client.ac = NULL;
        client.ready = 0;
        client.outstanding = 0;
    }
}


static void
client_on_ping(redisAsyncContext *ac, void *r, void *privdata)
{
    redisReply *reply = r;

    if (ac != client.ac || reply == NULL) {
        return;
    }
    if (reply->type == REDIS_REPLY_ERROR) {
        client_failed("AUTH/PING", reply);
        client_drop();
        return;
    }
    client.ready = 1;
    client.backoff = 0;
    client.last_reply = ngx_current_msec;
}


static void
client_connect(void)
{
    client.ac = ngx_http_repsheet_redis_connect(client.conf, client.log, client_on_connect,
                                                client_on_disconnect, NULL);
    client.ready = 0;
    client.outstanding = 0;
    client.last_reply = ngx_current_msec;
    if (client.ac) {
        /* An AUTH error makes every later command fail too, so PING is enough. */
        redisAsyncCommand(client.ac, client_on_ping, NULL, "PING");
    }
}


static void
client_tick(ngx_event_t *ev)
{
    if (ngx_exiting || ngx_quit || ngx_terminate) {
        return;
    }

    if (client.ac == NULL) {
        client_connect();
        if (client.ac == NULL) {
            client.backoff = client.backoff ? ngx_min(client.backoff * 2, CLIENT_MAX_BACKOFF) : CLIENT_TICK;
            ngx_add_timer(&client.timer, client.backoff);
            return;
        }
    } else if (client.outstanding
               && ngx_current_msec - client.last_reply > ngx_max(10 * client.conf->timeout, 2000))
    {
        ngx_log_error(NGX_LOG_ERR, client.log, 0, "repsheet: detector client: redis stopped answering");
        (void) ngx_atomic_fetch_add(&client_counters()->detector_redis_errors, 1);
        client_drop();
    } else if (!client.ready && ngx_current_msec - client.last_reply > 5000) {
        ngx_log_error(NGX_LOG_ERR, client.log, 0, "repsheet: detector client: redis did not become ready");
        client_drop();
    }

    ngx_add_timer(&client.timer, CLIENT_TICK);
}


ngx_int_t
ngx_http_repsheet_client_init_process(ngx_cycle_t *cycle)
{
    ngx_http_repsheet_main_conf_t *conf;

    ngx_memzero(&client, sizeof(client));

    conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_repsheet_module);
    if (conf == NULL || !conf->detectors || conf->zone == NULL || !conf->redis.configured) {
        return NGX_OK;
    }

    client.conf = conf;
    client.log = cycle->log;
    client.timer.handler = client_tick;
    client.timer.log = cycle->log;
    client.timer.data = &client;
    client.timer.cancelable = 1;

    client_connect();
    ngx_add_timer(&client.timer, CLIENT_TICK);
    return NGX_OK;
}


void
ngx_http_repsheet_client_exit_process(void)
{
    redisAsyncContext *ac = client.ac;

    if (client.conf == NULL) {
        return;
    }
    if (client.timer.timer_set) {
        ngx_del_timer(&client.timer);
    }
    client.ac = NULL;
    client.ready = 0;
    client.closing = 1;
    if (ac) {
        redisAsyncFree(ac);
    }
}


ngx_flag_t
ngx_http_repsheet_client_ready(void)
{
    return client.ac != NULL && client.ready && client.outstanding < CLIENT_MAX_PENDING;
}


static void
client_on_get(redisAsyncContext *ac, void *r, void *privdata)
{
    ngx_http_repsheet_pending_t  *pending = privdata;
    redisReply                   *reply = r;
    ngx_str_t                     value, *v = NULL;

    client_replied(ac);

    if (reply && reply->type == REDIS_REPLY_STRING) {
        value.data = (u_char *) reply->str;
        value.len = reply->len;
        v = &value;
    } else if (reply && reply->type == REDIS_REPLY_ERROR) {
        client_failed("GET", reply);
    }

    if (pending->data && !client.closing) {
        pending->handler(pending->data, v);
    }
    ngx_free(pending);
}


ngx_http_repsheet_pending_t *
ngx_http_repsheet_client_get(ngx_str_t *key, ngx_http_repsheet_get_pt handler, void *data)
{
    ngx_http_repsheet_pending_t *pending;

    if (!ngx_http_repsheet_client_ready()) {
        return NULL;
    }

    pending = ngx_alloc(sizeof(ngx_http_repsheet_pending_t), client.log);
    if (pending == NULL) {
        return NULL;
    }
    pending->handler = handler;
    pending->data = data;

    if (redisAsyncCommand(client.ac, client_on_get, pending, "GET %b", key->data, key->len) != REDIS_OK) {
        ngx_free(pending);
        return NULL;
    }
    client.outstanding++;
    return pending;
}


void
ngx_http_repsheet_client_cancel(ngx_http_repsheet_pending_t *pending)
{
    /* The reply (or the disconnect) still arrives and frees it. */
    pending->data = NULL;
}


static void
client_on_set(redisAsyncContext *ac, void *r, void *privdata)
{
    redisReply *reply = r;

    client_replied(ac);
    if (reply && reply->type == REDIS_REPLY_ERROR) {
        client_failed("SET", reply);
    }
}


void
ngx_http_repsheet_client_set(ngx_str_t *key, ngx_str_t *value, time_t ttl)
{
    if (!ngx_http_repsheet_client_ready() || ttl <= 0) {
        return;
    }
    if (redisAsyncCommand(client.ac, client_on_set, NULL, "SET %b %b EX %d", key->data, key->len,
                          value->data, value->len, (int) ttl) == REDIS_OK)
    {
        client.outstanding++;
    }
}


/* ------------------------------------------------------------------------ */
/* recording decisions                                                       */
/* ------------------------------------------------------------------------ */

static void
client_on_record(redisAsyncContext *ac, void *r, void *privdata)
{
    redisReply *reply = r;

    client_replied(ac);
    if (reply && reply->type == REDIS_REPLY_ERROR) {
        (void) ngx_atomic_fetch_add(&client_counters()->detector_redis_errors, 1);
        if (!client.record_error_logged) {
            /* Typically a read-only replica in repsheet_redis. Say so once per worker. */
            ngx_log_error(NGX_LOG_ERR, client.log, 0,
                          "repsheet: recording a detector decision failed: %s "
                          "(detectors need repsheet_redis to point at a writable primary)", reply->str);
            client.record_error_logged = 1;
        }
    }
}


/*
 * Record a detector's decision: apply it to this nginx's store right away,
 * so every worker enforces it, and write it to Valkey/Redis so every nginx
 * does once it syncs. The decision expires after `ttl` seconds.
 */
ngx_int_t
ngx_http_repsheet_record(ngx_str_t *actor, rs_status_t status, ngx_str_t *reason, time_t ttl, const char *by,
    ngx_log_t *log)
{
    ngx_http_repsheet_main_conf_t  *mcf;
    ngx_http_repsheet_store_t      *store;
    int64_t                         expires;
    const char                     *command;

    mcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_repsheet_module);
    if (mcf == NULL || mcf->zone == NULL || ttl <= 0) {
        return NGX_ERROR;
    }
    store = mcf->zone->data;

    switch (status) {
    case RS_STATUS_BLOCK: command = "REPSHEET.BLOCK"; break;
    case RS_STATUS_MARK:  command = "REPSHEET.MARK";  break;
    case RS_STATUS_ALLOW: command = "REPSHEET.ALLOW"; break;
    default: return NGX_ERROR;
    }

    expires = ngx_http_repsheet_now_ms() + (int64_t) ttl * 1000;
    if (ngx_http_repsheet_store_set(store, actor, status, reason, expires, log) != NGX_OK) {
        return NGX_ERROR;
    }
    (void) ngx_atomic_fetch_add(&store->sh->counters.detector_decisions, 1);

    if (client.conf == NULL || !ngx_http_repsheet_client_ready()) {
        /* Enforced here until it expires; other nginx servers do not learn of it. */
        (void) ngx_atomic_fetch_add(&store->sh->counters.detector_redis_errors, 1);
        ngx_log_error(NGX_LOG_WARN, log, 0, "repsheet: redis unavailable, decision for \"%V\" by %s "
                      "applies to this nginx only", actor, by);
        return NGX_OK;
    }

    if (redisAsyncCommand(client.ac, client_on_record, NULL, "%s %b REASON %b TTL %d BY %s", command,
                          actor->data, actor->len, reason->data, reason->len, (int) ttl, by) == REDIS_OK)
    {
        client.outstanding++;
    }
    return NGX_OK;
}

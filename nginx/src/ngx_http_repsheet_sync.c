/*
 * Keeps the shared memory store in sync with Valkey/Redis.
 *
 * Exactly one worker (worker 0) runs the sync loop, using non-blocking
 * hiredis connections driven by the nginx event loop:
 *
 *   - a command connection that loads a snapshot when it has no state,
 *     then polls REPSHEET.CHANGES every repsheet_sync_interval;
 *   - a subscriber connection on {repsheet}:notify that triggers an
 *     immediate poll when a decision changes, so updates land in
 *     milliseconds while polling guarantees nothing is lost.
 *
 * The snapshot is read in pages (REPSHEET.SNAPSHOT CURSOR ...), so a large
 * store neither blocks Valkey nor times out. Pages are not consistent with
 * each other, so the loop remembers the change log position of the first
 * page and, once the last page is in, replays REPSHEET.CHANGES from there.
 * Until then the store keeps serving the decisions it had; entries not seen
 * in the snapshot are removed at the end.
 *
 * Requests never wait on Redis. If Redis is unavailable the store keeps
 * serving the last known decisions and the loop reconnects with backoff.
 */
#include "ngx_http_repsheet_redis.h"

#define CHANGES_PAGE 1000
#define SNAPSHOT_PAGE 1000
#define SWEEP_EVERY 100         /* ms between slices of the background sweep */
#define SWEEP_PASS 10000        /* ms for a full pass over the store */
#define SWEEP_MIN_SLICE 1000    /* entries per slice, at least */
#define MAX_BACKOFF 30000

typedef struct {
    ngx_http_repsheet_main_conf_t  *conf;
    ngx_http_repsheet_store_t      *store;
    ngx_log_t                      *log;
    ngx_event_t                     timer;

    redisAsyncContext              *cmd;
    redisAsyncContext              *sub;
    ngx_flag_t                      cmd_ready;
    ngx_flag_t                      busy;
    ngx_msec_t                      started;    /* connect or command start */
    ngx_flag_t                      have_state;
    ngx_flag_t                      more;
    ngx_msec_t                      backoff;
    ngx_event_t                     sweeper;

    /* A paged snapshot in progress. */
    ngx_flag_t                      paging;
    char                            cursor[24];
    u_char                          page_epoch[17];
    int64_t                         page_seq;     /* change log position of the first page */
    uint64_t                        generation;
    size_t                          loaded;
} sync_t;

static sync_t  sync_state;


/* ------------------------------------------------------------------------ */
/* helpers                                                                   */
/* ------------------------------------------------------------------------ */

static void schedule(ngx_msec_t delay);
static void disconnect(const char *why);


static ngx_flag_t
is_owner(void)
{
    return sync_state.store->sh->owner == ngx_pid && !ngx_exiting && !ngx_quit && !ngx_terminate;
}


static ngx_flag_t
reply_str(redisReply *r, ngx_str_t *out)
{
    if (r == NULL || (r->type != REDIS_REPLY_STRING && r->type != REDIS_REPLY_STATUS)) {
        return 0;
    }
    out->data = (u_char *) r->str;
    out->len = r->len;
    return 1;
}


static ngx_flag_t
reply_int(redisReply *r, int64_t *out)
{
    if (r == NULL) {
        return 0;
    }
    if (r->type == REDIS_REPLY_INTEGER) {
        *out = r->integer;
        return 1;
    }
    if (r->type == REDIS_REPLY_STRING) {
        char *end;
        if (r->len == 0) {
            *out = 0;
            return 1;
        }
        *out = strtoll(r->str, &end, 10);
        return end == r->str + r->len;
    }
    return 0;
}


static void
sync_failed(const char *what, redisReply *reply)
{
    ngx_http_repsheet_shctx_t *sh = sync_state.store->sh;

    (void) ngx_atomic_fetch_add(&sh->counters.sync_errors, 1);

    if (reply && reply->type == REDIS_REPLY_ERROR) {
        ngx_log_error(NGX_LOG_ERR, sync_state.log, 0, "repsheet: %s failed: %s", what, reply->str);
    } else {
        ngx_log_error(NGX_LOG_ERR, sync_state.log, 0, "repsheet: %s returned an unexpected reply", what);
    }

    disconnect(what);
}


static void
mark_synced(void)
{
    ngx_http_repsheet_shctx_t *sh = sync_state.store->sh;

    sh->synced = 1;
    sh->last_sync = ngx_http_repsheet_now_ms();
    sync_state.backoff = 0;
}


/* ------------------------------------------------------------------------ */
/* snapshot / changes                                                        */
/* ------------------------------------------------------------------------ */

static void
on_snapshot(redisAsyncContext *ac, void *r, void *privdata)
{
    redisReply                 *reply = r, *entries, *e;
    ngx_http_repsheet_shctx_t  *sh;
    ngx_str_t                   epoch, cursor, actor, status_str, reason;
    rs_status_t                 status;
    int64_t                     seq, expires;
    size_t                      i;

    sync_state.busy = 0;
    if (reply == NULL || !is_owner()) {
        return;
    }

    sh = sync_state.store->sh;

    /* [epoch, seq, next-cursor, [[actor, status, reason, expires], ...]] */
    if (reply->type != REDIS_REPLY_ARRAY || reply->elements != 4
        || !reply_str(reply->element[0], &epoch) || epoch.len >= sizeof(sync_state.page_epoch)
        || !reply_int(reply->element[1], &seq)
        || !reply_str(reply->element[2], &cursor) || cursor.len >= sizeof(sync_state.cursor)
        || reply->element[3]->type != REDIS_REPLY_ARRAY)
    {
        sync_state.paging = 0;
        sync_failed("REPSHEET.SNAPSHOT", reply);
        return;
    }

    if (sync_state.loaded == 0 && sync_state.cursor[0] == '0' && sync_state.cursor[1] == '\0') {
        /* First page: where the change log replay will start. */
        ngx_memcpy(sync_state.page_epoch, epoch.data, epoch.len);
        sync_state.page_epoch[epoch.len] = '\0';
        sync_state.page_seq = seq;

    } else if (ngx_strlen(sync_state.page_epoch) != epoch.len
               || ngx_strncmp(sync_state.page_epoch, epoch.data, epoch.len) != 0)
    {
        /* Flushed or replaced while paging: start over. */
        ngx_log_error(NGX_LOG_NOTICE, sync_state.log, 0,
                      "repsheet: dataset changed during the snapshot, starting again");
        sync_state.paging = 0;
        schedule(0);
        return;
    }

    entries = reply->element[3];
    for (i = 0; i < entries->elements; i++) {
        e = entries->element[i];
        if (e->type != REDIS_REPLY_ARRAY || e->elements != 4
            || !reply_str(e->element[0], &actor)
            || !reply_str(e->element[1], &status_str)
            || !reply_str(e->element[2], &reason)
            || !reply_int(e->element[3], &expires)
            || rs_status_parse((char *) status_str.data, status_str.len, &status) != 0)
        {
            continue;
        }
        ngx_http_repsheet_store_set(sync_state.store, &actor, status, &reason, expires,
                                    sync_state.log);
        sync_state.loaded++;
    }

    ngx_memcpy(sync_state.cursor, cursor.data, cursor.len);
    sync_state.cursor[cursor.len] = '\0';
    sync_state.backoff = 0;

    if (!(cursor.len == 1 && cursor.data[0] == '0')) {
        schedule(0);   /* next page */
        return;
    }

    /* Last page: drop what the snapshot did not contain, then replay changes. */
    ngx_http_repsheet_store_end_snapshot(sync_state.store, sync_state.generation);

    ngx_memcpy(sh->epoch, sync_state.page_epoch, sizeof(sh->epoch));
    sh->seq = sync_state.page_seq;
    sync_state.have_state = 1;
    sync_state.paging = 0;
    (void) ngx_atomic_fetch_add(&sh->counters.snapshots, 1);
    mark_synced();

    ngx_log_error(NGX_LOG_NOTICE, sync_state.log, 0,
                  "repsheet: loaded snapshot with %uz decisions (epoch %s, seq %L)",
                  sync_state.loaded, sh->epoch, sh->seq);

    schedule(0);
}


static void
apply_change(redisReply *c)
{
    ngx_str_t    op, actor, status_str, reason;
    rs_status_t  status;
    int64_t      expires;

    if (c->type != REDIS_REPLY_ARRAY || c->elements != 6
        || !reply_str(c->element[1], &op)
        || !reply_str(c->element[2], &actor)
        || !reply_str(c->element[3], &status_str)
        || !reply_str(c->element[4], &reason)
        || !reply_int(c->element[5], &expires))
    {
        return;
    }

    if (op.len == 3 && ngx_strncmp(op.data, "del", 3) == 0) {
        ngx_http_repsheet_store_delete(sync_state.store, &actor);
        return;
    }

    if (rs_status_parse((char *) status_str.data, status_str.len, &status) == 0) {
        ngx_http_repsheet_store_set(sync_state.store, &actor, status, &reason, expires,
                                    sync_state.log);
    }
}


static void
on_changes(redisAsyncContext *ac, void *r, void *privdata)
{
    redisReply                 *reply = r, *changes;
    ngx_http_repsheet_shctx_t  *sh;
    ngx_str_t                   result, epoch;
    int64_t                     cursor;
    size_t                      i;

    sync_state.busy = 0;
    if (reply == NULL || !is_owner()) {
        return;
    }

    sh = sync_state.store->sh;

    if (reply->type != REDIS_REPLY_ARRAY || reply->elements < 1
        || !reply_str(reply->element[0], &result))
    {
        sync_failed("REPSHEET.CHANGES", reply);
        return;
    }

    if (result.len == 6 && ngx_strncmp(result.data, "RESYNC", 6) == 0) {
        ngx_log_error(NGX_LOG_NOTICE, sync_state.log, 0,
                      "repsheet: change log does not cover seq %L, taking a new snapshot",
                      sh->seq);
        sync_state.have_state = 0;
        schedule(0);
        return;
    }

    if (reply->elements != 4
        || !reply_str(reply->element[1], &epoch) || epoch.len >= sizeof(sh->epoch)
        || !reply_int(reply->element[2], &cursor)
        || reply->element[3]->type != REDIS_REPLY_ARRAY)
    {
        sync_failed("REPSHEET.CHANGES", reply);
        return;
    }

    changes = reply->element[3];
    for (i = 0; i < changes->elements; i++) {
        apply_change(changes->element[i]);
    }

    ngx_memcpy(sh->epoch, epoch.data, epoch.len);
    sh->epoch[epoch.len] = '\0';
    sh->seq = cursor;
    (void) ngx_atomic_fetch_add(&sh->counters.changes, changes->elements);
    mark_synced();

    /* A full page, or a notification during this poll: read again now. */
    if (sync_state.more || changes->elements == CHANGES_PAGE) {
        sync_state.more = 0;
        schedule(0);
    }
}


static void
poll_redis(void)
{
    ngx_http_repsheet_shctx_t  *sh = sync_state.store->sh;
    int                         rc;

    if (!sync_state.have_state) {
        if (!sync_state.paging) {
            sync_state.paging = 1;
            sync_state.loaded = 0;
            sync_state.cursor[0] = '0';
            sync_state.cursor[1] = '\0';
            sync_state.generation = ngx_http_repsheet_store_begin_snapshot(sync_state.store);
        }
        rc = redisAsyncCommand(sync_state.cmd, on_snapshot, NULL, "REPSHEET.SNAPSHOT CURSOR %s COUNT %d",
                               sync_state.cursor, SNAPSHOT_PAGE);
    } else {
        rc = redisAsyncCommand(sync_state.cmd, on_changes, NULL, "REPSHEET.CHANGES %s %lld COUNT %d",
                               (char *) sh->epoch, (long long) sh->seq, CHANGES_PAGE);
    }

    if (rc == REDIS_OK) {
        sync_state.busy = 1;
        sync_state.started = ngx_current_msec;
    }
}


/* ------------------------------------------------------------------------ */
/* connections                                                               */
/* ------------------------------------------------------------------------ */

static void
on_notify(redisAsyncContext *ac, void *r, void *privdata)
{
    redisReply *reply = r;

    if (reply == NULL || !is_owner()) {
        return;
    }

    if (reply->type == REDIS_REPLY_ARRAY && reply->elements == 3
        && reply->element[0]->type == REDIS_REPLY_STRING
        && ngx_strcmp(reply->element[0]->str, "message") == 0
        && sync_state.cmd_ready)
    {
        if (sync_state.busy) {
            /* Poll again as soon as the one in flight finishes. */
            sync_state.more = 1;
        } else {
            schedule(0);
        }
    }
}


static void
on_auth(redisAsyncContext *ac, void *r, void *privdata)
{
    redisReply *reply = r;

    if (reply == NULL) {
        return;
    }

    if (reply->type == REDIS_REPLY_ERROR) {
        ngx_log_error(NGX_LOG_ERR, sync_state.log, 0, "repsheet: AUTH failed: %s", reply->str);
        disconnect("AUTH");
    }
}


static void
on_ready(redisAsyncContext *ac, void *r, void *privdata)
{
    redisReply *reply = r;

    if (reply == NULL || !is_owner()) {
        return;
    }

    if (reply->type == REDIS_REPLY_ERROR) {
        sync_failed("REPSHEET.VERSION (is the repsheet module loaded?)", reply);
        return;
    }

    ngx_log_error(NGX_LOG_NOTICE, sync_state.log, 0, "repsheet: connected, module version %s",
                  reply->type == REDIS_REPLY_STATUS ? reply->str : "unknown");

    sync_state.cmd_ready = 1;
    sync_state.busy = 0;
    schedule(0);
}


static void
on_disconnect(const redisAsyncContext *ac, int status)
{
    if (status != REDIS_OK && is_owner()) {
        ngx_log_error(NGX_LOG_ERR, sync_state.log, 0, "repsheet: redis connection lost: %s",
                      ac->errstr[0] ? ac->errstr : "closed");
    }

    if (ac == sync_state.cmd) {
        sync_state.cmd = NULL;
        sync_state.cmd_ready = 0;
        sync_state.busy = 0;
    } else if (ac == sync_state.sub) {
        sync_state.sub = NULL;
    }
}


static void
on_connect(const redisAsyncContext *ac, int status)
{
    if (status != REDIS_OK) {
        ngx_log_error(NGX_LOG_ERR, sync_state.log, 0, "repsheet: could not connect to redis: %s",
                      ac->errstr);
        /* hiredis frees the context after this callback; on_disconnect is not called. */
        if (ac == sync_state.cmd) {
            sync_state.cmd = NULL;
            sync_state.cmd_ready = 0;
            sync_state.busy = 0;
        } else if (ac == sync_state.sub) {
            sync_state.sub = NULL;
        }
    }
}


static redisAsyncContext *
connect_one(void)
{
    return ngx_http_repsheet_redis_connect(sync_state.conf, sync_state.log, on_connect, on_disconnect,
                                           on_auth);
}


static void
connect_redis(void)
{
    sync_state.started = ngx_current_msec;

    if (sync_state.cmd == NULL) {
        sync_state.cmd = connect_one();
        if (sync_state.cmd) {
            sync_state.busy = 1;
            redisAsyncCommand(sync_state.cmd, on_ready, NULL, "REPSHEET.VERSION");
        }
    }

    if (sync_state.sub == NULL) {
        sync_state.sub = connect_one();
        if (sync_state.sub) {
            redisAsyncCommand(sync_state.sub, on_notify, NULL, "SUBSCRIBE {repsheet}:notify");
        }
    }
}


static void
disconnect(const char *why)
{
    sync_state.paging = 0;

    /* Safe from inside reply callbacks: hiredis defers the free. */
    if (sync_state.cmd) {
        redisAsyncDisconnect(sync_state.cmd);
    }
    if (sync_state.sub) {
        redisAsyncDisconnect(sync_state.sub);
    }

    sync_state.backoff = sync_state.backoff ? ngx_min(sync_state.backoff * 2, MAX_BACKOFF)
                                            : sync_state.conf->interval;
    schedule(sync_state.backoff);
}


static void
free_connections(void)
{
    /* Only outside hiredis callbacks. */
    if (sync_state.cmd) {
        redisAsyncFree(sync_state.cmd);
    }
    if (sync_state.sub) {
        redisAsyncFree(sync_state.sub);
    }
    sync_state.cmd = NULL;
    sync_state.sub = NULL;
    sync_state.cmd_ready = 0;
    sync_state.busy = 0;
    sync_state.paging = 0;    /* a new connection starts the snapshot over */
}


/* ------------------------------------------------------------------------ */
/* main loop                                                                 */
/* ------------------------------------------------------------------------ */

static void
schedule(ngx_msec_t delay)
{
    if (!is_owner()) {
        return;
    }
    ngx_add_timer(&sync_state.timer, delay);
}


static void
tick(ngx_event_t *ev)
{
    ngx_msec_t delay = sync_state.backoff ? sync_state.backoff : sync_state.conf->interval;

    if (!is_owner()) {
        free_connections();
        return;
    }

    if (sync_state.cmd == NULL || sync_state.sub == NULL) {
        if (sync_state.cmd || sync_state.sub) {
            /* Half connected: start over with both. */
            free_connections();
        }
        connect_redis();
        if (sync_state.cmd == NULL) {
            sync_state.backoff = sync_state.backoff ? ngx_min(sync_state.backoff * 2, MAX_BACKOFF)
                                                    : sync_state.conf->interval;
            delay = sync_state.backoff;
        }
        schedule(ngx_min(delay, sync_state.conf->timeout));
        return;
    }

    if (sync_state.busy) {
        if (ngx_current_msec - sync_state.started >= sync_state.conf->timeout) {
            ngx_log_error(NGX_LOG_ERR, sync_state.log, 0,
                          "repsheet: redis did not answer within %Mms, reconnecting",
                          sync_state.conf->timeout);
            (void) ngx_atomic_fetch_add(&sync_state.store->sh->counters.sync_errors, 1);
            free_connections();
            sync_state.backoff = sync_state.backoff ? ngx_min(sync_state.backoff * 2, MAX_BACKOFF)
                                                    : sync_state.conf->interval;
            schedule(sync_state.backoff);
            return;
        }
        schedule(ngx_min(delay, sync_state.conf->timeout));
        return;
    }

    if (sync_state.cmd_ready) {
        poll_redis();
    }

    schedule(ngx_min(delay, sync_state.conf->timeout));
}


/*
 * Housekeeping in slices: a pass over the whole store about every
 * SWEEP_PASS ms, never holding the store's write lock for more than one
 * slice (~70 us at a million decisions). After a snapshot, slices run back
 * to back, leaving the event loop a turn in between.
 */
static void
sweep_tick(ngx_event_t *ev)
{
    ngx_http_repsheet_store_t  *store = sync_state.store;
    ngx_uint_t                  slice;

    if (!is_owner()) {
        return;
    }

    slice = ngx_max(SWEEP_MIN_SLICE, store->sh->count / (SWEEP_PASS / SWEEP_EVERY) + 1);
    (void) ngx_http_repsheet_store_sweep_step(store, slice);

    ngx_add_timer(&sync_state.sweeper,
                  ngx_http_repsheet_store_sweep_pending(store) ? 1 : SWEEP_EVERY);
}


ngx_int_t
ngx_http_repsheet_sync_init_process(ngx_cycle_t *cycle)
{
    ngx_http_repsheet_main_conf_t  *conf;
    ngx_http_repsheet_shctx_t      *sh;

    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE) {
        return NGX_OK;
    }

    if (ngx_worker != 0) {
        return NGX_OK;
    }

    conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_repsheet_module);
    if (conf == NULL || !conf->redis.configured || conf->zone == NULL) {
        return NGX_OK;
    }

    ngx_memzero(&sync_state, sizeof(sync_t));
    sync_state.conf = conf;
    sync_state.store = conf->zone->data;
    sync_state.log = cycle->log;
    sync_state.sweeper.handler = sweep_tick;
    sync_state.sweeper.log = cycle->log;
    sync_state.sweeper.data = &sync_state;
    sync_state.sweeper.cancelable = 1;

    /* Take over from a worker of a previous configuration generation. After a
     * reload the store and its sync position survive, so continue from there. */
    sh = sync_state.store->sh;
    sh->owner = ngx_pid;
    sync_state.have_state = sh->synced;

    sync_state.timer.handler = tick;
    sync_state.timer.log = cycle->log;
    sync_state.timer.data = &sync_state;
    sync_state.timer.cancelable = 1;

    ngx_add_timer(&sync_state.timer, 0);
    ngx_add_timer(&sync_state.sweeper, SWEEP_EVERY);
    return NGX_OK;
}


void
ngx_http_repsheet_sync_exit_process(ngx_cycle_t *cycle)
{
    if (sync_state.store == NULL) {
        return;
    }

    if (sync_state.timer.timer_set) {
        ngx_del_timer(&sync_state.timer);
    }
    if (sync_state.sweeper.timer_set) {
        ngx_del_timer(&sync_state.sweeper);
    }

    free_connections();
}

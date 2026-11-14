/*
 * Valkey/Redis plumbing shared by the sync loop and the active detectors.
 */
#ifndef NGX_HTTP_REPSHEET_REDIS_H
#define NGX_HTTP_REPSHEET_REDIS_H

#include "ngx_http_repsheet_module.h"

#include <hiredis/hiredis.h>
#include <hiredis/async.h>

/* Drive a hiredis async context from the nginx event loop. */
ngx_int_t ngx_http_repsheet_redis_attach(redisAsyncContext *ac, ngx_log_t *log);

/* Connect with the repsheet_redis settings (options + AUTH). NULL on failure. */
redisAsyncContext *ngx_http_repsheet_redis_connect(ngx_http_repsheet_main_conf_t *conf, ngx_log_t *log,
    redisConnectCallback *on_connect, redisDisconnectCallback *on_disconnect,
    redisCallbackFn *on_auth);

/*
 * Per-worker client used by active detectors: a cache read with a bounded
 * wait, fire-and-forget writes, and recording decisions. Started only when a
 * detector asks for it (ngx_http_repsheet_main_conf_t.detectors).
 */
typedef struct ngx_http_repsheet_pending_s ngx_http_repsheet_pending_t;

/* value is NULL when the key is missing, Redis failed or went away. */
typedef void (*ngx_http_repsheet_get_pt)(void *data, ngx_str_t *value);

ngx_int_t ngx_http_repsheet_client_init_process(ngx_cycle_t *cycle);
void ngx_http_repsheet_client_exit_process(void);
ngx_flag_t ngx_http_repsheet_client_ready(void);
ngx_http_repsheet_pending_t *ngx_http_repsheet_client_get(ngx_str_t *key, ngx_http_repsheet_get_pt handler,
    void *data);
void ngx_http_repsheet_client_cancel(ngx_http_repsheet_pending_t *pending);
void ngx_http_repsheet_client_set(ngx_str_t *key, ngx_str_t *value, time_t ttl);

#endif

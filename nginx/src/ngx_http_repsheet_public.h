/*
 * The part of the Repsheet nginx module's configuration other modules may
 * read, so they can reuse repsheet_redis / repsheet_redis_auth instead of
 * asking for the same settings again (ngx_bot_verifier does).
 *
 * It is the first member of the module's main configuration. Find the module
 * by name ("ngx_http_repsheet_module") in cycle->modules, take its main conf
 * and check `magic` and `version` before reading anything else. Copy this
 * struct rather than including this file if you build separately. Fields may
 * only be appended; anything else bumps the version.
 */
#ifndef NGX_HTTP_REPSHEET_PUBLIC_H
#define NGX_HTTP_REPSHEET_PUBLIC_H

#include <ngx_config.h>
#include <ngx_core.h>

#define NGX_HTTP_REPSHEET_PUBLIC_MAGIC 0x52505348 /* "RPSH" */
#define NGX_HTTP_REPSHEET_PUBLIC_VERSION 1

typedef struct {
    uint32_t     magic;
    uint32_t     version;
    ngx_flag_t   configured;    /* repsheet_redis was given */
    ngx_str_t    host;          /* empty with a unix socket; no brackets for IPv6 */
    ngx_uint_t   port;
    ngx_str_t    unix_path;
    ngx_str_t    user;          /* repsheet_redis_auth, may be empty */
    ngx_str_t    password;
} ngx_http_repsheet_redis_conf_t;

#endif

/*
 * Crawler providers: how to recognize a claim (User-Agent) and how to check
 * it (reverse DNS domains, published IP ranges).
 */
#include "ngx_http_bot_verifier.h"

typedef struct {
    const char  *name;
    const char  *user_agent;
    const char  *domains[4];
} bv_builtin_t;

/*
 * Domains from the providers' verification guides (November 2026). Baidu and
 * Yahoo are from consistent secondary sources; their own pages were not
 * reachable. DuckDuckBot has no reverse DNS and is verified by ranges only.
 */
static const bv_builtin_t bv_builtins[] = {
    { "google",
      "googlebot|google-inspectiontool|googleother|storebot-google|adsbot-google"
      "|mediapartners-google|feedfetcher-google|apis-google|google-site-verification",
      { "googlebot.com", "google.com", "googleusercontent.com", NULL } },
    { "bing", "bingbot|bingpreview|msnbot|adidxbot", { "search.msn.com", NULL } },
    { "apple", "applebot", { "applebot.apple.com", NULL } },
    { "yandex", "yandex\\w*bot|yandex(images|video|media|metrika|webmaster|favicons|direct)\\b",
      { "yandex.ru", "yandex.net", "yandex.com", NULL } },
    { "baidu", "baiduspider", { "baidu.com", "baidu.jp", NULL } },
    { "yahoo", "yahoo! slurp", { "crawl.yahoo.net", NULL } },
    { "duckduckgo", "duckduckbot", { NULL } },
};


static ngx_int_t
bv_compile_user_agent(ngx_conf_t *cf, bv_provider_t *p, ngx_str_t *pattern)
{
    ngx_regex_compile_t  rc;
    u_char               errstr[NGX_MAX_CONF_ERRSTR];

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
    rc.pattern = *pattern;
    rc.pool = cf->pool;
    rc.options = NGX_REGEX_CASELESS;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "bot_verifier: invalid user_agent for \"%V\": %V",
                           &p->name, &rc.err);
        return NGX_ERROR;
    }

    p->user_agent = rc.regex;
    p->user_agent_src = *pattern;
    return NGX_OK;
}


static bv_provider_t *
bv_provider_find(bv_main_conf_t *mcf, ngx_str_t *name)
{
    bv_provider_t  *p = mcf->providers.elts;
    ngx_uint_t      i;

    for (i = 0; i < mcf->providers.nelts; i++) {
        if (p[i].name.len == name->len && ngx_strncasecmp(p[i].name.data, name->data, name->len) == 0) {
            return &p[i];
        }
    }
    return NULL;
}


static bv_provider_t *
bv_provider_add(ngx_conf_t *cf, bv_main_conf_t *mcf, ngx_str_t *name)
{
    bv_provider_t  *p;

    if (mcf->providers.nelts >= BV_MAX_PROVIDERS) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "bot_verifier: too many providers");
        return NULL;
    }

    p = ngx_array_push(&mcf->providers);
    if (p == NULL) {
        return NULL;
    }

    ngx_memzero(p, sizeof(bv_provider_t));
    p->name = *name;
    p->index = mcf->providers.nelts - 1;
    p->domains = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
    p->range_files = ngx_array_create(cf->pool, 2, sizeof(ngx_str_t));
    if (p->domains == NULL || p->range_files == NULL) {
        return NULL;
    }
    return p;
}


static ngx_int_t
bv_add_domain(ngx_conf_t *cf, bv_provider_t *p, ngx_str_t *value)
{
    ngx_str_t  *d;
    u_char     *s = value->data;
    size_t      len = value->len;
    ngx_uint_t  i;

    while (len && *s == '.') {
        s++;
        len--;
    }
    while (len && s[len - 1] == '.') {
        len--;
    }
    if (len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "bot_verifier: empty domain for \"%V\"", &p->name);
        return NGX_ERROR;
    }

    d = ngx_array_push(p->domains);
    if (d == NULL) {
        return NGX_ERROR;
    }
    d->data = ngx_pnalloc(cf->pool, len);
    if (d->data == NULL) {
        return NGX_ERROR;
    }
    for (i = 0; i < len; i++) {
        d->data[i] = ngx_tolower(s[i]);
    }
    d->len = len;
    return NGX_OK;
}


char *
bv_providers_add_builtin(ngx_conf_t *cf, bv_main_conf_t *mcf)
{
    const bv_builtin_t  *b;
    bv_provider_t       *p;
    ngx_str_t            name, pattern, domain;
    ngx_uint_t           i, j;

    for (i = 0; i < sizeof(bv_builtins) / sizeof(bv_builtins[0]); i++) {
        b = &bv_builtins[i];
        name.data = (u_char *) b->name;
        name.len = ngx_strlen(b->name);
        p = bv_provider_add(cf, mcf, &name);
        if (p == NULL) {
            return NGX_CONF_ERROR;
        }
        pattern.data = (u_char *) b->user_agent;
        pattern.len = ngx_strlen(b->user_agent);
        if (bv_compile_user_agent(cf, p, &pattern) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
        for (j = 0; b->domains[j]; j++) {
            domain.data = (u_char *) b->domains[j];
            domain.len = ngx_strlen(b->domains[j]);
            if (bv_add_domain(cf, p, &domain) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }
    return NGX_CONF_OK;
}


/* ------------------------------------------------------------------------ */
/* bot_verifier_provider <name> { user_agent ...; domain ...; ranges ...; }  */
/* ------------------------------------------------------------------------ */

static char *
bv_provider_line(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    bv_provider_t  *p = conf;
    ngx_str_t      *value = cf->args->elts, *f;
    ngx_uint_t      i, n = cf->args->nelts;

    if (value[0].len == 10 && ngx_strncmp(value[0].data, "user_agent", 10) == 0 && n == 2) {
        if (p->user_agent_src.len) {
            return "has a duplicate \"user_agent\"";
        }
        return bv_compile_user_agent(cf, p, &value[1]) == NGX_OK ? NGX_CONF_OK : NGX_CONF_ERROR;
    }

    if (value[0].len == 6 && ngx_strncmp(value[0].data, "domain", 6) == 0 && n >= 2) {
        for (i = 1; i < n; i++) {
            if (bv_add_domain(cf, p, &value[i]) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
        return NGX_CONF_OK;
    }

    if (value[0].len == 6 && ngx_strncmp(value[0].data, "ranges", 6) == 0 && n >= 2) {
        for (i = 1; i < n; i++) {
            f = ngx_array_push(p->range_files);
            if (f == NULL || ngx_conf_full_name(cf->cycle, &value[i], 1) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
            *f = value[i];
        }
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "bot_verifier_provider: expected \"user_agent <regex>\", \"domain <name>...\" "
                       "or \"ranges <file>...\", got \"%V\"", &value[0]);
    return NGX_CONF_ERROR;
}


char *
bv_provider_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    bv_main_conf_t  *mcf = conf;
    bv_provider_t   *p;
    ngx_str_t       *value = cf->args->elts;
    ngx_conf_t       save;
    char            *rv;
    ngx_uint_t       i;

    for (i = 0; i < value[1].len; i++) {
        u_char c = value[1].data[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) {
            return "name may only contain [a-z0-9_-]";
        }
    }

    p = bv_provider_find(mcf, &value[1]);
    if (p) {
        /* Redefining a provider (built-in or not) replaces it. */
        p->user_agent = NULL;
        ngx_str_null(&p->user_agent_src);
        p->domains->nelts = 0;
        p->range_files->nelts = 0;
    } else {
        p = bv_provider_add(cf, mcf, &value[1]);
        if (p == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    save = *cf;
    cf->handler = bv_provider_line;
    cf->handler_conf = (char *) p;
    rv = ngx_conf_parse(cf, NULL);
    *cf = save;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (p->user_agent == NULL) {
        return "requires \"user_agent\"";
    }
    if (p->domains->nelts == 0 && p->range_files->nelts == 0) {
        return "requires \"domain\" or \"ranges\"";
    }
    return NGX_CONF_OK;
}


/* bot_verifier_ranges <provider> <file>... : add range files to a provider. */
char *
bv_ranges_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    bv_main_conf_t  *mcf = conf;
    bv_provider_t   *p;
    ngx_str_t       *value = cf->args->elts, *f;
    ngx_uint_t       i;

    p = bv_provider_find(mcf, &value[1]);
    if (p == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "bot_verifier_ranges: unknown provider \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    for (i = 2; i < cf->args->nelts; i++) {
        f = ngx_array_push(p->range_files);
        if (f == NULL || ngx_conf_full_name(cf->cycle, &value[i], 1) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
        *f = value[i];
    }
    return NGX_CONF_OK;
}


/* ------------------------------------------------------------------------ */
/* range files                                                               */
/* ------------------------------------------------------------------------ */

static ngx_int_t
bv_add_cidr(ngx_conf_t *cf, bv_provider_t *p, ngx_str_t *file, ngx_uint_t line, u_char *s, size_t len)
{
    ngx_cidr_t  *cidr;
    ngx_str_t    text = { len, s };
    ngx_int_t    rc;

    cidr = ngx_array_push(p->ranges);
    if (cidr == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_ptocidr(&text, cidr);
    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "bot_verifier: invalid range \"%V\" in %V:%ui", &text, file,
                           line);
        return NGX_ERROR;
    }
    /* NGX_DONE: host bits were set and have been masked; accept it. */
    return NGX_OK;
}


/*
 * Two formats:
 *   - the providers' JSON ({"prefixes":[{"ipv4Prefix":"..."},{"ipv6Prefix":"..."}]})
 *   - plain text, one address or network per line, "#" comments.
 */
static ngx_int_t
bv_load_ranges_file(ngx_conf_t *cf, bv_provider_t *p, ngx_str_t *name)
{
    ngx_file_t       file;
    ngx_file_info_t  fi;
    u_char          *buf, *s, *end, *q, *e;
    size_t           size;
    ssize_t          n;
    ngx_uint_t       line = 1, before = p->ranges->nelts;
    ngx_int_t        rc = NGX_ERROR;

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = *name;
    file.log = cf->log;
    file.fd = ngx_open_file(name->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno, "bot_verifier: cannot open ranges file \"%V\"", name);
        return NGX_ERROR;
    }

    if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno, "bot_verifier: cannot stat \"%V\"", name);
        goto done;
    }
    size = (size_t) ngx_file_size(&fi);
    if (size > 16 * 1024 * 1024) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "bot_verifier: ranges file \"%V\" is too large", name);
        goto done;
    }

    buf = ngx_pnalloc(cf->temp_pool, size + 1);
    if (buf == NULL) {
        goto done;
    }
    n = ngx_read_file(&file, buf, size, 0);
    if (n != (ssize_t) size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno, "bot_verifier: cannot read \"%V\"", name);
        goto done;
    }
    buf[size] = '\0';
    end = buf + size;

    if (ngx_strlcasestrn(buf, end, (u_char *) "prefix\"", 7 - 1) != NULL) {
        /* JSON: take the string value after every "ipv4Prefix"/"ipv6Prefix" key. */
        for (s = buf; s < end; s = e) {
            q = ngx_strlcasestrn(s, end, (u_char *) "prefix\"", 7 - 1);
            if (q == NULL) {
                break;
            }
            e = q + 7;
            if (q - buf < 4 || (ngx_strncmp(q - 4, "ipv4", 4) && ngx_strncmp(q - 4, "ipv6", 4))) {
                continue;
            }
            while (e < end && (*e == ' ' || *e == '\t' || *e == '\r' || *e == '\n' || *e == ':')) {
                e++;
            }
            if (e >= end || *e != '"') {
                continue;
            }
            q = ++e;
            while (e < end && *e != '"') {
                e++;
            }
            if (bv_add_cidr(cf, p, name, 0, q, e - q) != NGX_OK) {
                goto done;
            }
        }
    } else {
        for (s = buf; s < end; s = e + 1, line++) {
            e = ngx_strlchr(s, end, '\n');
            if (e == NULL) {
                e = end;
            }
            q = ngx_strlchr(s, e, '#');
            q = q ? q : e;
            while (s < q && (*s == ' ' || *s == '\t' || *s == '\r')) {
                s++;
            }
            while (q > s && (q[-1] == ' ' || q[-1] == '\t' || q[-1] == '\r')) {
                q--;
            }
            if (q > s && bv_add_cidr(cf, p, name, line, s, q - s) != NGX_OK) {
                goto done;
            }
        }
    }

    if (p->ranges->nelts == before) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "bot_verifier: no ranges found in \"%V\"", name);
        goto done;
    }
    rc = NGX_OK;

done:
    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno, ngx_close_file_n " \"%V\" failed", name);
    }
    return rc;
}


char *
bv_providers_load_ranges(ngx_conf_t *cf, bv_main_conf_t *mcf)
{
    bv_provider_t  *p = mcf->providers.elts;
    ngx_str_t      *f;
    ngx_uint_t      i, j;

    for (i = 0; i < mcf->providers.nelts; i++) {
        if (p[i].range_files->nelts == 0) {
            continue;
        }
        p[i].ranges = ngx_array_create(cf->pool, 64, sizeof(ngx_cidr_t));
        if (p[i].ranges == NULL) {
            return NGX_CONF_ERROR;
        }
        f = p[i].range_files->elts;
        for (j = 0; j < p[i].range_files->nelts; j++) {
            if (bv_load_ranges_file(cf, &p[i], &f[j]) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }
    return NGX_CONF_OK;
}


/* ------------------------------------------------------------------------ */
/* matching                                                                  */
/* ------------------------------------------------------------------------ */

bv_provider_t *
bv_provider_for_user_agent(bv_main_conf_t *mcf, ngx_str_t *ua)
{
    bv_provider_t  *p = mcf->providers.elts;
    ngx_uint_t      i;

    for (i = 0; i < mcf->providers.nelts; i++) {
        if (p[i].user_agent && ngx_regex_exec(p[i].user_agent, ua, NULL, 0) >= 0) {
            return &p[i];
        }
    }
    return NULL;
}


/*
 * True if `host` (as returned by reverse DNS) is one of the provider's domains
 * or a subdomain of one: "crawl-1-2-3-4.googlebot.com" matches "googlebot.com",
 * "evilgooglebot.com" and "googlebot.com.evil.net" do not. Only RFC 1034
 * characters are accepted.
 */
ngx_flag_t
bv_domain_matches(bv_provider_t *p, ngx_str_t *host)
{
    ngx_str_t  *d = p->domains->elts;
    size_t      len = host->len;
    u_char     *h = host->data, c;
    ngx_uint_t  i;

    if (len && h[len - 1] == '.') {
        len--;
    }
    if (len == 0 || len > 253) {
        return 0;
    }
    for (i = 0; i < len; i++) {
        c = h[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
              || c == '.'))
        {
            return 0;
        }
    }

    for (i = 0; i < p->domains->nelts; i++) {
        if (len < d[i].len) {
            continue;
        }
        if (ngx_strncasecmp(h + len - d[i].len, d[i].data, d[i].len) != 0) {
            continue;
        }
        if (len == d[i].len || h[len - d[i].len - 1] == '.') {
            return 1;
        }
    }
    return 0;
}

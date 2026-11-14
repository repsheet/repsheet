# ngx_bot_verifier

An nginx module that checks whether clients claiming to be search engine
crawlers really are.

Sites relax their defenses for Googlebot, Bingbot and friends: rate limits,
challenges and bot rules should not get in the way of indexing. The
`User-Agent` header is not proof, though, and "Googlebot" is one of the most
common disguises for scrapers and attackers. The search engines document how
to tell the real ones apart, and this module does it for every request that
makes the claim:

1. If the provider publishes its crawlers' IP ranges and the client is in
   them, it is verified.
2. Otherwise a **reverse DNS** lookup of the client address must return a
   name under one of the provider's domains (`crawl-66-249-66-1.googlebot.com`),
   and a **forward lookup** of that name must return the client address.

Requests that claim to be a crawler and fail are blocked (403 by default).
Everyone else is untouched: requests that do not claim to be a crawler are
never looked up.

```
$ curl -A "Mozilla/5.0 (compatible; Googlebot/2.1)" -i https://example.com/
HTTP/1.1 403 Forbidden

error.log: bot_verifier: 203.0.113.9 failed verification, claimed google: no reverse DNS
```

Lookups use nginx's own asynchronous resolver, so a slow DNS server never
stalls other requests. Results are cached in shared memory and, optionally,
in Valkey/Redis so a fleet of nginx servers verifies each address once.

## Quick start (Docker)

```sh
make docker-up        # nginx with the module on :8081, plus Valkey
curl -A "Mozilla/5.0 (compatible; Googlebot/2.1)" -i localhost:8081/   # 403
curl -s localhost:8081/metrics
make docker-down
```

## Configuration

```nginx
load_module modules/ngx_http_bot_verifier_module.so;   # if built as a dynamic module

http {
    resolver 1.1.1.1 8.8.8.8 valid=300s;    # required: used for the lookups
    resolver_timeout 5s;

    bot_verifier on;

    # Optional: published ranges verify most Google, Bing, Apple and
    # DuckDuckGo crawlers without DNS (see "Published ranges" below).
    bot_verifier_ranges google /etc/nginx/bot_ranges/google-common-crawlers.json;
    bot_verifier_ranges bing   /etc/nginx/bot_ranges/bingbot.json;

    # Optional: share results between servers, report fakes to Repsheet.
    # With the Repsheet nginx module loaded, repsheet_redis is used for both;
    # otherwise set bot_verifier_redis.
    repsheet_redis 10.0.0.5:6379;
    bot_verifier_repsheet mark 1h;

    # Behind a load balancer, let realip decide the client address.
    set_real_ip_from 10.0.0.0/8;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;

    server {
        location / {
            proxy_set_header X-Verified-Crawler $bot_verifier_provider;
            proxy_pass http://app;
        }
        location = /metrics {
            bot_verifier off;
            bot_verifier_metrics;
            allow 10.0.0.0/8;
            deny all;
        }
    }
}
```

| Directive | Context | Default | |
|-----------|---------|---------|---|
| `bot_verifier on \| off \| monitor` | http, server, location | `off` | `monitor` verifies and logs, but never blocks. |
| `bot_verifier_timeout <time>` | http, server, location | `5s` | Timeout for each DNS query. |
| `bot_verifier_block_status <code>` | http, server, location | `403` | 400–599. |
| `bot_verifier_ttl <verified> [<failed> [<unknown>]]` | http | `24h 1h 1m` | How long results are cached. |
| `bot_verifier_zone_size <size>` | http | `16m` | Shared memory for cached results (128 bytes each). When full, the least recently used results are dropped. |
| `bot_verifier_provider <name> { ... }` | http | | Add a provider, or replace a built-in one. See below. |
| `bot_verifier_ranges <provider> <file>...` | http | | Published IP ranges for a provider. |
| `bot_verifier_redis <address> \| off` | http | `repsheet_redis` | `host:port`, `[v6]:port` or `unix:/path`. Without it, the `repsheet_redis` and `repsheet_redis_auth` settings of the Repsheet nginx module are used if that module is loaded. `off` uses no Redis at all. |
| `bot_verifier_redis_auth [user] <password>` | http | none | With `bot_verifier_redis`. |
| `bot_verifier_redis_timeout <time>` | http | `100ms` | How long a request waits for the Redis cache before going to DNS. |
| `bot_verifier_repsheet off \| mark [ttl] \| block [ttl]` | http | `off` | Report failed verifications to [Repsheet](https://github.com/repsheet/repsheet). Needs `repsheet_redis` or `bot_verifier_redis`. TTL defaults to `1h`. |
| `bot_verifier_metrics` | location | | Prometheus metrics. |

nginx refuses to start if `bot_verifier` is on where no `resolver` is
configured.

Variables: `$bot_verifier_result` (`verified`, `failed`, `unknown`, or empty
when the request made no claim) and `$bot_verifier_provider` (the claimed
provider). Use them in logs, `map`s, `limit_req` keys, or to tell the
application which crawler it is serving.

### Results

| Result | When | Request |
|--------|------|---------|
| `verified` | In the published ranges, or reverse and forward DNS agree | allowed |
| `failed` | No reverse DNS, a name outside the provider's domains, a name that does not resolve back, or outside the ranges of a ranges-only provider | blocked |
| `unknown` | DNS error or timeout, or no way to check (a ranges-only provider without ranges) | allowed |

`unknown` fails open on purpose: a DNS outage should not de-index your site.
It is cached briefly (`1m`), so the next request tries again.

A cached result only applies to the provider it was found for. An address
verified as Googlebot that later claims to be Bingbot fails; an address that
failed as Googlebot is not blocked when it makes no claim, so one fake
User-Agent behind a shared NAT does not block everyone else behind it.

## Providers

| Name | User-Agent (case-insensitive regex) | Domains |
|------|-------------------------------------|---------|
| `google` | `googlebot\|google-inspectiontool\|googleother\|storebot-google\|adsbot-google\|mediapartners-google\|feedfetcher-google\|apis-google\|google-site-verification` | googlebot.com, google.com, googleusercontent.com |
| `bing` | `bingbot\|bingpreview\|msnbot\|adidxbot` | search.msn.com |
| `apple` | `applebot` | applebot.apple.com |
| `yandex` | `yandex\w*bot\|yandex(images\|video\|media\|metrika\|webmaster\|favicons\|direct)\b` | yandex.ru, yandex.net, yandex.com |
| `baidu` | `baiduspider` | baidu.com, baidu.jp |
| `yahoo` | `yahoo! slurp` | crawl.yahoo.net |
| `duckduckgo` | `duckduckbot` | none: verified by its published ranges only |

Domains come from each provider's verification guide (November 2026). For
Baidu and Yahoo the providers' own pages could not be checked; their domains
come from consistent secondary sources. A name matches a domain if it equals
it or ends in `.` plus the domain, so `evilgooglebot.com` and
`googlebot.com.evil.net` do not match `googlebot.com`.

Add your own, or replace a built-in one by reusing its name:

```nginx
bot_verifier_provider examplebot {
    user_agent "ExampleBot/\d";
    domain crawler.example.org;
    ranges /etc/nginx/bot_ranges/examplebot.txt;   # optional
}
```

### Published ranges

Google, Bing, Apple and DuckDuckGo publish their crawlers' address ranges.
Checking them needs no DNS at all, and for DuckDuckBot it is the only way.
`script/fetch-ranges [dir]` downloads them:

```sh
script/fetch-ranges /etc/nginx/bot_ranges && nginx -s reload
```

Run it from cron to keep the lists current. Files are read when nginx starts
or reloads. Both the providers' JSON (`ipv4Prefix`/`ipv6Prefix`) and plain
text (one address or network per line, `#` comments) are accepted. An address
outside a provider's ranges still gets the DNS check if the provider has
domains, because the lists can lag behind.

## Redis and Repsheet

When nginx also runs the [Repsheet](https://github.com/repsheet/repsheet)
module, there is nothing extra to configure: the bot verifier uses the Redis
that `repsheet_redis` and `repsheet_redis_auth` point at (Repsheet's module
publishes those settings for other modules; older Repsheet versions that do
not are detected and a warning says to set `bot_verifier_redis`). Set
`bot_verifier_redis` to use a different server, or `bot_verifier_redis off`
to keep results local.

With Redis configured, results are also stored as
`{bot_verifier}:<address>` = `verified:google` (with the same TTLs) and read
by every server before it does any DNS. A request waits at most
`bot_verifier_redis_timeout` for that read. If Redis is down or slow the
module carries on with shared memory and DNS, and reconnects in the
background. `unknown` results are not shared.

With `bot_verifier_repsheet mark` (or `block`), every address that fails a
fresh verification is reported to Repsheet:

```
REPSHEET.MARK ip:203.0.113.9 REASON "bot_verifier: claimed google: no reverse DNS" TTL 3600 BY bot_verifier
```

Repsheet then acts on it across all of your nginx servers, for every request
from that address (marked actors can be rate limited, blocked ones are
rejected). That needs the Repsheet module loaded in the same Valkey/Redis;
if it is missing the error is logged once per worker.

## Metrics

| Metric | |
|--------|---|
| `bot_verifier_requests_total{result}` | Requests that claimed to be a crawler. |
| `bot_verifier_blocked_total` | Requests rejected (excludes monitor mode). |
| `bot_verifier_answers_total{source}` | Where results came from: `zone`, `ranges`, `redis`, `dns`, `none` (too many lookups in flight). |
| `bot_verifier_dns_queries_total`, `bot_verifier_dns_errors_total` | DNS activity. |
| `bot_verifier_redis_errors_total`, `bot_verifier_repsheet_reports_total` | Redis activity. |
| `bot_verifier_cache_entries`, `bot_verifier_cache_evictions_total` | The shared-memory cache. |
| `bot_verifier_zone_size_bytes`, `bot_verifier_zone_free_bytes` | Shared memory. |

## Things to know

* **Client address.** The module uses the connection address after the
  realip module. It never reads `X-Forwarded-For` itself; any client can set
  that. Configure `set_real_ip_from` for proxies you trust.
* **Phase.** It runs at the end of the preaccess phase, so a block cannot be
  overridden by `satisfy any`, and like `deny` it does not see responses
  produced earlier by `return`.
* **Resolver.** Lookups use nginx's `resolver`, which caches answers for
  their DNS TTL (or `valid=`). Point it at a resolver you trust.
* **Load.** At most 1024 lookups run at once per worker; beyond that requests
  get `unknown`. Concurrent requests for the same address share one lookup.

## Building

The module needs hiredis ≥ 1.0 and nginx sources. Build it statically or as a
dynamic module:

```sh
./configure --add-module=/path/to/ngx_bot_verifier ...          # static
./configure --add-dynamic-module=/path/to/ngx_bot_verifier ...  # dynamic
```

To build against a packaged nginx, configure the same nginx version with
`--with-compat` and run `make modules`; the `Dockerfile` does exactly this.

For development (the tests need [uv](https://docs.astral.sh/uv/)):

```sh
make bootstrap   # fetch + build pinned hiredis, Valkey, the Repsheet module and nginx into .deps/
make test        # pytest against real nginx, a fake DNS server and Valkey
make sanitize    # the same with ASan/UBSan
make nginx       # rebuild nginx after changing the module
```

`script/bootstrap` takes `NGINX_VERSION`, `VALKEY_VERSION`,
`HIREDIS_VERSION`, `REPSHEET_REF`, `DYNAMIC=1`, `SANITIZE=1` and
`WITH_REPSHEET=0`. By default the development nginx also includes the
Repsheet nginx module, so the tests cover the shared settings;
`WITH_REPSHEET=0` builds the bot verifier alone. CI covers nginx 1.30
(stable) and 1.31 (mainline), static and dynamic builds, a standalone build,
and a sanitizer run.

## History

Written in 2017 as part of [Repsheet](https://github.com/repsheet/repsheet).
Version 1.0 is a rewrite; see [CHANGELOG.md](CHANGELOG.md) for what changed.

## License

Apache 2.0.

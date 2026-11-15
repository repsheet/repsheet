# Configuration

```nginx
http {
    repsheet_redis 10.0.0.5:6379;      # or unix:/run/valkey.sock, [::1]:6379
    repsheet on;

    # Actors beyond the client address (optional)
    repsheet_actor session $cookie_session;
    repsheet_actor api_key $http_x_api_key;

    # Behind a load balancer: let realip decide the client address
    set_real_ip_from 10.0.0.0/8;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;

    server {
        location / {
            proxy_set_header X-Repsheet $repsheet_status;
            proxy_pass http://app;
        }
        location /login {
            repsheet_block_status 429;
            proxy_pass http://app;
        }
        location = /metrics {
            repsheet off;
            repsheet_metrics;
            allow 10.0.0.0/8;
            deny all;
        }
    }
}
```

| Directive | Context | Default | |
|-----------|---------|---------|---|
| `repsheet on \| off \| monitor` | http, server, location | `off` | `monitor` evaluates and logs `would block` but never blocks. |
| `repsheet_redis <address>` | http | none | Required. `host:port`, `[v6]:port` or `unix:/path`. Hostnames are resolved by the worker when it connects; prefer addresses. |
| `repsheet_redis_auth [user] <password>` | http | none | `AUTH` on connect. |
| `repsheet_redis_timeout <time>` | http | `1s` | Reconnect if Redis does not answer in time. |
| `repsheet_sync_interval <time>` | http | `1s` | Polling interval. Changes usually arrive sooner through pubsub. |
| `repsheet_zone_size <size>` | http | `32m` | Shared memory for decisions. About 110 bytes per decision plus its reason (94k decisions used ~10 MB). |
| `repsheet_actor <type> <value>` | http, server, location | none | Also check `<type>:<value>`. An empty value is skipped. Type `ip` treats the value as an address. A location that sets any `repsheet_actor` replaces the inherited list. |
| `repsheet_block_status <code>` | http, server, location | `403` | 400–599. |
| `repsheet_metrics` | location | | Prometheus metrics. |

Variables: `$repsheet_status` (`allow`, `block`, `mark` or empty),
`$repsheet_reason`, `$repsheet_actor`. They work in locations where
`repsheet` is `off` too.

## Things to know

* **Client address.** Repsheet uses the connection address, after `realip`
  has run. It does not read `X-Forwarded-For` itself, because any client can
  set that header. Configure `set_real_ip_from` for proxies you trust.
* **Phase.** Repsheet runs at the end of the preaccess phase. Like `deny`
  and `limit_req`, it does not see responses produced earlier by `return` or
  `rewrite ... last` redirects. A block cannot be overridden by `satisfy any`.
* **Clocks.** TTLs are absolute times taken from the Redis server's clock.
  nginx hosts should be NTP-synced.
* **Zone full.** If the zone runs out of memory, new decisions are dropped
  and logged, and `repsheet_zone_alloc_failures_total` increases. Size the
  zone from `repsheet_zone_free_bytes`.

## Metrics

| Metric | |
|--------|---|
| `repsheet_requests_total{decision}` | Requests evaluated (`none`, `mark`, `block`, `allow`). Requests rejected earlier in the preaccess phase (e.g. by `limit_req`) are not counted. |
| `repsheet_blocked_total` | Requests rejected (excludes monitor mode). |
| `repsheet_decisions` | Decisions in shared memory. |
| `repsheet_sync_up` | 1 if the last successful sync is recent. |
| `repsheet_sync_last_success_timestamp_seconds`, `repsheet_sync_seq` | Sync position. |
| `repsheet_sync_snapshots_total`, `repsheet_sync_changes_total`, `repsheet_sync_errors_total` | Sync activity. |
| `repsheet_zone_size_bytes`, `repsheet_zone_free_bytes`, `repsheet_zone_alloc_failures_total` | Shared memory. |
| `repsheet_detector_decisions_total`, `repsheet_detector_redis_errors_total` | Decisions recorded by active detectors, and failed detector reads/writes. |
| `repsheet_bot_verifier_*` | With the bot verifier on; see [below](#bot-verifier). |

## Bot verifier

An [active detector](../detectors/README.md) for clients that claim to be a search engine crawler.
Sites relax their defenses for Googlebot, Bingbot and friends, and
"Googlebot" is one of the most common disguises for scrapers. The search
engines document how to tell the real ones apart, and the bot verifier does
it for every request whose `User-Agent` makes the claim:

1. If the provider publishes its crawlers' IP ranges and the client is in
   them, it is verified.
2. Otherwise a **reverse DNS** lookup of the client address must return a
   name under one of the provider's domains (`crawl-66-249-66-1.googlebot.com`),
   and a **forward lookup** of that name must return the client address.

A failed verification becomes a Repsheet decision for the address: `block`
for an hour by default, `BY bot_verifier`, with the reason
(`bot_verifier: claimed google: no reverse DNS`). It applies to this nginx
at once and to every nginx after the next sync, for all requests from that
address. Requests that make no claim are never looked up.

```nginx
http {
    repsheet_redis 10.0.0.5:6379;
    repsheet on;

    resolver 1.1.1.1 8.8.8.8 valid=300s;    # required: used for the lookups
    resolver_timeout 5s;
    repsheet_bot_verifier on;
    # repsheet_bot_verifier_action mark 1h;  # gentler than block
    repsheet_bot_verifier_ranges google /etc/nginx/bot_ranges/google-common-crawlers.json;
    repsheet_bot_verifier_ranges bing   /etc/nginx/bot_ranges/bingbot.json;
}
```

Lookups use nginx's own asynchronous resolver, so a slow DNS server never
stalls other requests; concurrent requests for the same address share one
lookup. Results are cached in shared memory and in Valkey
(`{repsheet}:bot_verifier:<address>`), so a fleet verifies each address once.

| Directive | Context | Default | |
|-----------|---------|---------|---|
| `repsheet_bot_verifier on \| off \| monitor` | http, server, location | `off` | `monitor` verifies and logs but records nothing. Runs only where `repsheet` is `on` or `monitor`. |
| `repsheet_bot_verifier_action block \| mark [ttl]` | http | `block 1h` | The decision recorded for a failed verification. |
| `repsheet_bot_verifier_timeout <time>` | http, server, location | `5s` | Timeout for each DNS query. |
| `repsheet_bot_verifier_ttl <verified> [<failed> [<unknown>]]` | http | `24h 1h 1m` | How long verification results are cached (separate from the decision's TTL). |
| `repsheet_bot_verifier_cache_timeout <time>` | http | `100ms` | How long a request waits for the shared Valkey cache before going to DNS. |
| `repsheet_bot_verifier_zone_size <size>` | http | `16m` | Shared memory for cached results (128 bytes each, LRU). |
| `repsheet_bot_verifier_provider <name> { ... }` | http | built-in set | Add a provider or replace a built-in one: `user_agent <regex>; domain <name>...; ranges <file>...;` |
| `repsheet_bot_verifier_ranges <provider> <file>...` | http | | Published IP ranges (the providers' JSON or plain text). `script/fetch-ranges` downloads them. |

It needs `repsheet_redis` (decisions are recorded there; point it at a
writable primary) and a `resolver`. nginx refuses to start without them.

Built-in providers: Google (googlebot.com, google.com,
googleusercontent.com), Bing (search.msn.com), Apple (applebot.apple.com),
Yandex (yandex.ru, .net, .com), Baidu (baidu.com, baidu.jp), Yahoo
(crawl.yahoo.net) and DuckDuckGo (published ranges only). A name matches a
domain if it equals it or ends in `.` plus the domain, so
`evilgooglebot.com` and `googlebot.com.evil.net` do not match
`googlebot.com`. Baidu and Yahoo domains come from consistent secondary
sources; the providers' own pages could not be checked.

| Result | When | Effect |
|--------|------|--------|
| `verified` | In the published ranges, or reverse and forward DNS agree | none |
| `failed` | No reverse DNS, a name outside the provider's domains, a name that does not resolve back, or outside the ranges of a ranges-only provider | decision recorded |
| `unknown` | DNS error or timeout | none (fails open; retried after `1m`) |

A verified crawler is not written as an `allow`: an allow would override
every block. An address verified as one crawler that claims to be another
fails. With `block`, one fake crawler User-Agent behind a shared NAT blocks
that address for the decision's TTL; `mark` with `limit_req` is the gentler
choice.

Variables: `$repsheet_bot_verifier_result` (`verified`, `failed`,
`unknown`, or empty), `$repsheet_bot_verifier_provider`, and
`$repsheet_bot_verifier_time` (seconds the request waited for verification;
`0.000` when cached). Metrics: `repsheet_bot_verifier_requests_total{result}`,
`_answers_total{source}`, `_decisions_total`, `_dns_queries_total`,
`_dns_errors_total`, `_lookup_duration_seconds{source}` (histogram),
`_cache_entries`, `_cache_evictions_total`, `_zone_size_bytes`,
`_zone_free_bytes`.

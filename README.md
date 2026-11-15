# Repsheet

Repsheet enforces reputation decisions at the edge. An actor (an IP
address, a network, a session, an API key) is **blocked**, **allowed**, or
**marked**, and nginx acts on that decision on every request, in memory,
without a network round trip.

Decisions come from **detectors** and from people:

* **Active detectors** run inside nginx, in real time. The first is the
  [bot verifier](#bot-verifier), which catches clients pretending to be
  search engine crawlers.
* **Passive detectors** run out of band, on logs or other signals, and write
  decisions into Valkey. Anything that can send a Redis command can be one:
  your SIEM, a WAF, a script, a log pipeline.
* **People**, through the [admin UI](#admin-ui) or `valkey-cli`.

See [detectors/](detectors/README.md) for how the two kinds work and the
contract for writing a passive detector.

```
 analysis / SIEM / WAF / scripts / humans
                 │  REPSHEET.BLOCK 203.0.113.0/24 REASON "credential stuffing" TTL 3600
                 ▼
        ┌──────────────────┐   snapshot + ordered change log + pubsub
        │ Valkey or Redis  │ ─────────────────────────────────────────┐
        │ + repsheet.so    │                                          │
        └──────────────────┘                                          ▼
                                                    ┌───────────────────────────────┐
   client ──────────────────────────────────────▶   │ nginx + repsheet module       │
                                                    │ decisions in shared memory    │
                                                    └───────────────────────────────┘
```

* **block**: nginx rejects the request (403 by default).
* **allow**: the actor is trusted, which overrides any block or mark.
* **mark**: the request goes through, and `$repsheet_status`,
  `$repsheet_reason` and `$repsheet_actor` let you pass the signal to the
  application, log it, or feed it into `limit_req`.

## How it works

The repository contains three components:

| Directory | What it is |
|-----------|------------|
| `redis/`  | A module for Valkey (≥ 7.2) and Redis (≥ 7.2). It is the source of truth: it validates and canonicalizes actors, stores decisions with optional TTLs, and keeps an ordered change log. |
| `nginx/`  | An nginx module. It holds a full copy of the decisions in shared memory, evaluates every request against it, and runs the active detectors (`nginx/src/bot_verifier/`). |
| `admin/`  | `repsheet-admin`, a web UI for viewing and managing decisions (Rust). |
| `common/` | Actor parsing and canonicalization shared by all three. |
| `detectors/` | How detectors work; the passive detector contract. |
| `bench/`  | `repsheet-bench`, which measures Repsheet's per-request overhead (Rust). |

The nginx module never queries Redis while handling a request. One worker
keeps the shared memory store in sync:

1. On start it loads everything with `REPSHEET.SNAPSHOT`, a thousand decisions
   at a time so a large store never blocks Valkey, and keeps serving what it
   had until the last page is in.
2. It then follows `REPSHEET.CHANGES` from the last sequence number it applied.
   A pubsub notification wakes it up as soon as a decision changes, and it
   also polls every `repsheet_sync_interval` in case a notification is missed.
3. If it falls behind the change log, or the dataset is flushed or replaced,
   the module answers `RESYNC` and nginx takes a new snapshot.

If Redis is slow or unreachable, requests are still served from the last
known decisions and the sync loop reconnects with backoff. Decisions survive
`nginx -s reload` without a new snapshot.

Network decisions are matched without a trie. The store counts how many
entries exist at each prefix length, and a lookup masks the client address
to each prefix length in use, checks a small per-length filter, and only
looks the network up when the filter says it might be there. When several decisions
apply, **allow** beats **block**, which beats **mark**. Between decisions of
equal status, the most specific one wins.

## Quick start (Docker)

```sh
make docker-up                                  # or: docker compose -f examples/docker-compose.yml up --build -d
curl -i localhost:8080/                         # 200

# Find the address nginx sees for you (the Docker gateway), then block it.
docker compose -f examples/docker-compose.yml logs nginx | tail -1
docker compose -f examples/docker-compose.yml exec valkey \
    valkey-cli REPSHEET.BLOCK 172.16.0.0/12 REASON demo
curl -i localhost:8080/                         # 403
curl -s localhost:8080/metrics
```

The admin UI is on http://localhost:8090. Grafana on http://localhost:3000
shows the Repsheet dashboard (decisions, requests by decision, sync health,
zone usage, and the bot verifier's claims, answer sources and lookup
latency), fed by Prometheus on http://localhost:9090 scraping `/metrics`
every 5 seconds. `make docker-logs` follows the logs and `make docker-down`
stops everything.

The Prometheus scrape config and the dashboard are in `examples/monitoring/`
(`grafana/dashboards/repsheet.json` can be imported into any Grafana with a
Prometheus data source).

`examples/` also shows how to pass marks to an upstream and how to rate limit
marked actors.

## Managing decisions

Actors are written as `<type>:<value>`. A bare address or network is an `ip`
actor. Addresses are canonicalized: host bits are masked, IPv4-mapped IPv6
becomes IPv4, and `/32` and `/128` are dropped. So `10.1.2.3/8`,
`ip:10.0.0.0/8` and `::ffff:10.0.0.0/104` are all the same actor.

```
REPSHEET.BLOCK <actor> [REASON <text>] [TTL <seconds>] [BY <who>]
REPSHEET.ALLOW <actor> [REASON <text>] [TTL <seconds>] [BY <who>]
REPSHEET.MARK  <actor> [REASON <text>] [TTL <seconds>] [BY <who>]
REPSHEET.CLEAR <actor> [BY <who>]               -> 1 if a decision was removed
REPSHEET.GET   <actor>                          -> map or nil (exact actor only)
REPSHEET.CHECK <actor> [<actor> ...]            -> [status, reason, matched actor]
REPSHEET.SNAPSHOT                               -> [epoch, seq, [[actor, status, reason, expires]...]]
REPSHEET.SNAPSHOT CURSOR <c> [COUNT n]          -> [epoch, seq, next-cursor, [...]] one page
REPSHEET.CHANGES <epoch> <seq> [COUNT n]        -> ["OK", epoch, seq, [...]] or ["RESYNC"]
REPSHEET.VERSION
```

```
> REPSHEET.BLOCK 2001:db8:42::/48 REASON "abuse report #4411" TTL 86400 BY alice
OK
> REPSHEET.MARK session:9f2c41 REASON "impossible travel"
OK
> REPSHEET.CHECK 2001:db8:42:7::1 session:9f2c41
1) block
2) "abuse report #4411"
3) "ip:2001:db8:42::/48"
```

`REPSHEET.SNAPSHOT` without `CURSOR` returns everything at once and keeps
Valkey busy meanwhile (about a second per million decisions). With `CURSOR`
it returns one page (start at `0`, stop when the next cursor is `0`). Pages
are not consistent with each other: remember the `seq` of the first page and
replay `REPSHEET.CHANGES` from it after the last one, as nginx and the admin
UI do.

`BY` records who made the change, on the decision and in the change log; it is
optional, at most 256 bytes, and has no effect on enforcement. A new decision
for an actor replaces the previous one. `REPSHEET.CHECK`
evaluates a set of actors exactly the way nginx does, which makes it useful
for applications and for debugging.

Limits: actors are at most 512 bytes, reasons at most 1024 bytes, and types
match `[a-z0-9_-]{1,32}`. A TTL may be up to ten years.

### Data layout

All keys share the `{repsheet}` hash tag.

| Key | Type | Contents |
|-----|------|----------|
| `{repsheet}:actor:<actor>` | hash | `status`, `reason`, `created`, `expires` (ms, 0 = never), `by`; TTL set to match |
| `{repsheet}:index` | set | every actor with a decision |
| `{repsheet}:meta` | hash | `epoch` (random, created on the first write), `seq` |
| `{repsheet}:changes` | stream | one entry per change (`op`, `actor`, `status`, `reason`, `expires`, `by`, `at` in ms), ID `<seq>-0`, capped at `changelog-max` |
| `{repsheet}:notify` | pubsub | `<epoch>:<seq>` after every change |

The change stream is also a convenient feed for other consumers (`XREAD`).
Load the module with `--loadmodule repsheet.so changelog-max 100000` to
change the cap. All commands work on replicas except the writes, so nginx can
sync from a replica. Redis Cluster is not supported.

## nginx configuration

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
| `repsheet_redis <address>` | http | none | Required. `host:port`, `[v6]:port` or `unix:/path`. Hostnames are resolved by the worker when it connects; prefer addresses. [ngx_bot_verifier](https://github.com/repsheet/ngx_bot_verifier) reuses this and `repsheet_redis_auth` when loaded alongside. |
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

Things to know:

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

### Metrics

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
| `repsheet_bot_verifier_*` | With the bot verifier on; see below. |

## Bot verifier

An active detector for clients that claim to be a search engine crawler.
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

## Admin UI

`repsheet-admin` is a small web UI on top of the same commands:

* **Dashboard**: counts by status and actor type, decisions expiring soon,
  recent changes, backend health.
* **Decisions**: every decision, filtered by status, type or text.
* **Actor lookup**: what nginx would do for an address or actor and which
  decision causes it (for example the `/24` an address falls in), the
  decision stored for it, and its history.
* **Changes**: block, allow, mark or clear, with a reason and an expiry.
  Every change is recorded with its author.
* **Activity**: the change log, newest first.

```sh
make run-admin REDIS=redis://10.0.0.5:6379      # builds it, then runs it
# open http://127.0.0.1:8090
```

To try it locally without an existing server, run `make run-valkey` (Valkey
from `.deps/` with the module loaded, data in memory only) in one terminal
and `make run-admin` in another. Extra options go in `ADMIN_ARGS`, for example
`make run-admin ADMIN_ARGS="--read-only"`. The binary itself is
`admin/target/release/repsheet-admin`.

It keeps its own in-memory copy of the decisions, synced the same way as
nginx, so lists stay fast with hundreds of thousands of decisions.

**There is no login.** Anyone who can reach the UI can change decisions. By
default it listens on `127.0.0.1:8090` only. To give others access, put it
behind a proxy that authenticates users (oauth2-proxy, an SSO gateway, nginx
with `auth_request`) and pass the user name along:

```nginx
location / {
    auth_request /oauth2/auth;
    auth_request_set $user $upstream_http_x_auth_request_user;
    proxy_set_header X-Forwarded-User $user;
    proxy_set_header Host $host;    # needed for the same-origin check
    proxy_pass http://127.0.0.1:8090;
}
```

```sh
repsheet-admin --user-header X-Forwarded-User --allowed-host admin.example.com
```

Without `--user-header`, changes are recorded as `repsheet-admin`
(`--default-by` changes that). Only use `--user-header` when the proxy is the
only way to reach the UI, since the header is trusted as sent.

The UI also defends against attacks through the user's own browser: form
submissions must come from the UI's own pages (`Origin`/`Referer` check), and
requests for unknown host names are refused, which stops DNS rebinding. Add
the names you use with `--allowed-host`. `--read-only` shows everything and
refuses changes.

| Option | Environment | Default |
|--------|-------------|---------|
| `--redis <url>` | `REPSHEET_REDIS` | `redis://127.0.0.1:6379` (also `redis://user:pass@host/`, `unix:///path`) |
| `--listen <addr>` | `REPSHEET_ADMIN_LISTEN` | `127.0.0.1:8090` |
| `--allowed-host <name>` | `REPSHEET_ADMIN_ALLOWED_HOSTS` (comma-separated) | IP addresses and `localhost` only |
| `--user-header <name>` | `REPSHEET_ADMIN_USER_HEADER` | none |
| `--default-by <who>` | `REPSHEET_ADMIN_DEFAULT_BY` | `repsheet-admin` |
| `--read-only` | `REPSHEET_ADMIN_READ_ONLY` | off |
| `--sync-interval <s>` | `REPSHEET_ADMIN_SYNC_INTERVAL` | `1` |

`/healthz` returns 200 once the UI is in sync with Valkey/Redis.

## Performance

`bench/` holds `repsheet-bench`, which measures what Repsheet adds to the cost
of serving a request. Each scenario runs two nginx servers with identical
configuration except that one has no Repsheet at all, sends both the same
requests in alternating runs, and compares the nginx worker's **CPU time per
request** (from `/proc/<pid>/schedstat`), along with throughput and client
latency. An "aa" scenario runs the baseline against itself to show the noise
floor.

```sh
make bench                                   # full suite (~13 min), results in bench/results/
make bench BENCH_ARGS="-s store-1m -s actors"
make bench BENCH_ARGS="--compare bench/results/<earlier>.json"
make bench-quick                             # every scenario, briefly: checks it all works
bench/target/release/repsheet-bench list     # what each scenario does
```

It uses an optimized nginx (`script/bootstrap bench`: `-O2`, no debug
logging) with one worker pinned to CPU 0 and the load generator on the other
CPUs. Requests are 64 keep-alive connections fetching a 6-byte file, which
makes Repsheet's share as large as it can be; real requests cost more, so the
same microseconds are a smaller fraction.

Results below are from one full run of each mode on a 16-CPU Linux laptop
(nginx 1.30.6, Valkey 9.1.3), November 2026. Expect different absolute
numbers on other hardware; the differences between the columns are what
matter.

### CPU per request (as fast as possible)

`make bench`. Median of three 10-second runs per side; noise floor ±2.3%.

| Scenario | nginx alone | with Repsheet | added | throughput alone → with |
|----------|------------:|--------------:|------:|------------------------:|
| empty store | 3.50 µs | 3.59 µs | +0.09 µs (noise) | 231k → 226k req/s |
| 10k decisions | 3.51 µs | 3.73 µs | +0.22 µs | 229k → 220k |
| 100k decisions | 3.51 µs | 3.92 µs | +0.41 µs | 231k → 211k |
| 1M decisions | 3.54 µs | 4.03 µs | +0.49 µs | 228k → 204k |
| 100k decisions, 1,000 changes/s syncing | 3.49 µs | 3.95 µs | +0.46 µs | 232k → 209k |
| cookie and header actors, 100k decisions | 3.58 µs | 4.36 µs | +0.78 µs | 226k → 189k |
| decisions at every IPv4 and IPv6 prefix length | 3.64 µs | 4.76 µs | +1.12 µs | 223k → 175k |
| bot verifier, browser traffic | 3.56 µs | 3.91 µs | +0.34 µs | 228k → 211k |
| bot verifier, Googlebot from its ranges | 3.53 µs | 3.90 µs | +0.37 µs | 230k → 211k |

### Latency (fixed load)

`make bench BENCH_ARGS="--rate 50000"`: 50,000 requests/s, well below
capacity, measured from when each request was due. Microseconds, nginx alone
/ with Repsheet, median of three runs.

| Scenario | p50 | p75 | p95 | p99 | p99.99 |
|----------|----:|----:|----:|----:|-------:|
| empty store | 18 / 18 | 22 / 22 | 29 / 29 | 40 / 39 | 1672 / 1016 |
| 10k decisions | 18 / 18 | 22 / 22 | 29 / 29 | 39 / 40 | 859 / 1283 |
| 100k decisions | 18 / 18 | 22 / 22 | 29 / 29 | 40 / 40 | 1160 / 967 |
| 1M decisions | 18 / 18 | 22 / 22 | 29 / 29 | 58 / 43 | 1965 / 1966 |
| 100k decisions, 1,000 changes/s syncing | 18 / 18 | 22 / 22 | 29 / 29 | 40 / 41 | 1787 / 966 |
| cookie and header actors, 100k decisions | 18 / 18 | 22 / 22 | 29 / 29 | 40 / 41 | 2167 / 1290 |
| decisions at every IPv4 and IPv6 prefix length | 18 / 19 | 22 / 23 | 29 / 30 | 41 / 41 | 1611 / 1133 |
| bot verifier, browser traffic | 18 / 18 | 22 / 22 | 29 / 29 | 40 / 40 | 1518 / 1098 |
| bot verifier, Googlebot from its ranges | 18 / 18 | 22 / 22 | 29 / 29 | 54 / 41 | 2025 / 1841 |

The p99.99 column (about 1-2 ms on both sides, with single runs up to 10 ms
either way) is scheduling noise on the test machine, not Repsheet: the A/A
scenario, which compares nginx alone against itself, varies just as much.

### What this means

* **Repsheet adds well under a microsecond of CPU per request** in every
  realistic case, and nothing measurable to latency from p50 to p99.
* **Lookups grow slowly with the store**: about half a microsecond at a
  million decisions. Sync churn adds nothing beyond that.
* **Each prefix length in use costs about 15 ns**: a per-length filter
  answers most lookups without touching the store. Most deployments use a
  handful of lengths; the worst case above uses all 138.
* **The bot verifier's User-Agent check** is one JIT-compiled match per
  request (about 130 ns for a browser User-Agent).
* **Large stores sync in pages**: nginx loads 1M decisions in about 2
  seconds, a thousand at a time, and no page keeps Valkey busy for more than
  about 2 ms.
* **Housekeeping runs in slices** (freeing expired decisions, removing what a
  new snapshot no longer contains, refreshing the prefix filters): about
  10,000 entries every 100 ms at a million decisions, so the store's lock is
  never held for long.

### Found and fixed with this benchmark

| Problem | Before | After |
|---------|--------|-------|
| Snapshot of 1M decisions in one reply | blocked Valkey 1 s; exceeded the timeout, so nginx never synced | paged: 2 ms per page, synced in ~2 s |
| Bot verifier, browser traffic | +2.10 µs per request (7 interpreted patterns, twice after internal redirects) | +0.34 µs |
| Decisions at every prefix length | +11.69 µs per request | +1.12 µs |
| Expiry sweep at 1M decisions | p99.99 7.3 ms (whole store walked under the write lock) | at the noise floor |

## Building

Requirements: a C compiler, make, hiredis ≥ 1.0 (for nginx), and nginx
sources. The admin UI needs a Rust toolchain (1.88 or later). The tests need
[uv](https://docs.astral.sh/uv/).

```sh
make bootstrap   # fetch + build pinned hiredis, Valkey and nginx into .deps/
make             # build redis/repsheet.so, nginx with the module, and repsheet-admin
make test        # pytest suite against real Valkey, nginx and the admin UI
make sanitize    # the same suite with ASan/UBSan on the module, Valkey and nginx
make bench       # performance benchmarks (see "Performance")

make run-valkey  # Valkey with the module on 127.0.0.1:6379 (VALKEY_PORT=...)
make run-admin   # the admin UI on 127.0.0.1:8090 (REDIS=..., ADMIN_ARGS=...)
make docker-up   # Valkey + nginx + admin UI in Docker; docker-logs, docker-down
```

The nginx module builds statically (`--add-module=/path/to/repsheet/nginx`)
or as a dynamic module (`--add-dynamic-module=...`, then `load_module`). To
build against a packaged nginx, configure the same nginx version with
`--with-compat` and run `make modules`. The `Dockerfile` does exactly this.

`script/bootstrap` takes `NGINX_VERSION`, `VALKEY_VERSION`,
`HIREDIS_VERSION`, `DYNAMIC=1` and `SANITIZE=1`. To test against Redis
instead of Valkey, set `REPSHEET_SERVER=/path/to/redis-server`.

CI covers Valkey 9.1 and Redis 8.10, nginx 1.30 (stable) and 1.31
(mainline), static and dynamic builds, a sanitizer run, and the admin UI
(rustfmt, clippy, unit and integration tests).

## History

The nginx module dates back to 2014 (versions 1.0 to 5.1) and the Redis
module to 2016. Version 6 merges both into one repository and is a rewrite.
See [CHANGELOG.md](CHANGELOG.md) for what changed and how to migrate. The history of both original
repositories is preserved in this one.

## License

Apache 2.0. `redis/include/redismodule.h` is from Redis 7.2.4 (BSD 3-Clause).

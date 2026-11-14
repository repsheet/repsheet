# Repsheet

Repsheet enforces reputation decisions at the edge. You decide, somewhere
else and by whatever means you like, that an actor (an IP address, a
network, a session, an API key) should be **blocked**, **allowed**, or
**marked**. Repsheet makes nginx act on that decision on every request, in
memory, without a network round trip.

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

The repository contains two components:

| Directory | What it is |
|-----------|------------|
| `redis/`  | A module for Valkey (≥ 7.2) and Redis (≥ 7.2). It is the source of truth: it validates and canonicalizes actors, stores decisions with optional TTLs, and keeps an ordered change log. |
| `nginx/`  | An nginx module. It holds a full copy of the decisions in shared memory and evaluates every request against it. |
| `common/` | Actor parsing and canonicalization shared by both. |

The nginx module never queries Redis while handling a request. One worker
keeps the shared memory store in sync:

1. On start it loads everything with `REPSHEET.SNAPSHOT`.
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
to each prefix length in use, then does a hash lookup. When several decisions
apply, **allow** beats **block**, which beats **mark**. Between decisions of
equal status, the most specific one wins.

## Quick start (Docker)

```sh
docker compose -f examples/docker-compose.yml up --build
curl -i localhost:8080/                         # 200

# Find the address nginx sees for you (the Docker gateway), then block it.
docker compose -f examples/docker-compose.yml logs nginx | tail -1
docker compose -f examples/docker-compose.yml exec valkey \
    valkey-cli REPSHEET.BLOCK 172.16.0.0/12 REASON demo
curl -i localhost:8080/                         # 403
curl -s localhost:8080/metrics
```

`examples/` also shows how to pass marks to an upstream and how to rate limit
marked actors.

## Managing decisions

Actors are written as `<type>:<value>`. A bare address or network is an `ip`
actor. Addresses are canonicalized: host bits are masked, IPv4-mapped IPv6
becomes IPv4, and `/32` and `/128` are dropped. So `10.1.2.3/8`,
`ip:10.0.0.0/8` and `::ffff:10.0.0.0/104` are all the same actor.

```
REPSHEET.BLOCK <actor> [REASON <text>] [TTL <seconds>]
REPSHEET.ALLOW <actor> [REASON <text>] [TTL <seconds>]
REPSHEET.MARK  <actor> [REASON <text>] [TTL <seconds>]
REPSHEET.CLEAR <actor>                          -> 1 if a decision was removed
REPSHEET.GET   <actor>                          -> map or nil (exact actor only)
REPSHEET.CHECK <actor> [<actor> ...]            -> [status, reason, matched actor]
REPSHEET.SNAPSHOT                               -> [epoch, seq, [[actor, status, reason, expires]...]]
REPSHEET.CHANGES <epoch> <seq> [COUNT n]        -> ["OK", epoch, seq, [...]] or ["RESYNC"]
REPSHEET.VERSION
```

```
> REPSHEET.BLOCK 2001:db8:42::/48 REASON "abuse report #4411" TTL 86400
OK
> REPSHEET.MARK session:9f2c41 REASON "impossible travel"
OK
> REPSHEET.CHECK 2001:db8:42:7::1 session:9f2c41
1) block
2) "abuse report #4411"
3) "ip:2001:db8:42::/48"
```

A new decision for an actor replaces the previous one. `REPSHEET.CHECK`
evaluates a set of actors exactly the way nginx does, which makes it useful
for applications and for debugging.

Limits: actors are at most 512 bytes, reasons at most 1024 bytes, and types
match `[a-z0-9_-]{1,32}`. A TTL may be up to ten years.

### Data layout

All keys share the `{repsheet}` hash tag.

| Key | Type | Contents |
|-----|------|----------|
| `{repsheet}:actor:<actor>` | hash | `status`, `reason`, `created`, `expires` (ms, 0 = never); TTL set to match |
| `{repsheet}:index` | set | every actor with a decision |
| `{repsheet}:meta` | hash | `epoch` (random, created on the first write), `seq` |
| `{repsheet}:changes` | stream | one entry per change, ID `<seq>-0`, capped at `changelog-max` |
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

## Building

Requirements: a C compiler, make, hiredis ≥ 1.0 (for nginx), and nginx
sources. The tests need [uv](https://docs.astral.sh/uv/).

```sh
make bootstrap   # fetch + build pinned hiredis, Valkey and nginx into .deps/
make             # build redis/repsheet.so and nginx with the module
make test        # pytest suite against real Valkey and nginx
make sanitize    # the same suite with ASan/UBSan on the module, Valkey and nginx
```

The nginx module builds statically (`--add-module=/path/to/repsheet/nginx`)
or as a dynamic module (`--add-dynamic-module=...`, then `load_module`). To
build against a packaged nginx, configure the same nginx version with
`--with-compat` and run `make modules`. The `Dockerfile` does exactly this.

`script/bootstrap` takes `NGINX_VERSION`, `VALKEY_VERSION`,
`HIREDIS_VERSION`, `DYNAMIC=1` and `SANITIZE=1`. To test against Redis
instead of Valkey, set `REPSHEET_SERVER=/path/to/redis-server`.

CI covers Valkey 9.1 and Redis 8.10, nginx 1.30 (stable) and 1.31
(mainline), static and dynamic builds, and a sanitizer run.

## History

The nginx module dates back to 2014 (versions 1.0 to 4.2) and the Redis
module to 2016. Version 5 merges both into one repository and is a rewrite. See [CHANGELOG.md](CHANGELOG.md)
for what changed and how to migrate. The history of both original
repositories is preserved in this one.

## License

Apache 2.0. `redis/include/redismodule.h` is from Redis 7.2.4 (BSD 3-Clause).

# Changelog

## 1.0.0 (unreleased)

A rewrite. Configuration is not compatible with 0.0.x (see below).

### Security fixes
- The client address came from the leftmost `X-Forwarded-For` entry, so any
  client could choose it: claim a real Google address to be verified, or name
  someone else's address to get it blocked (and, with Repsheet enabled,
  blacklisted). The address now comes from the connection after nginx's
  realip module.
- IPv6 client addresses overflowed a 16-byte stack buffer.
- Domain checks compared prefixes of a regex capture: lookalike names such as
  `yahoo.com.xx` passed, while real Baidu (`*.crawl.baidu.com`) and Yahoo
  (`*.crawl.yahoo.net`) crawlers always failed. Names must now equal a
  provider domain or end in `.` plus it. Only the first forward address was
  compared; now any returned address may match.
- Requests that made no crawler claim returned `NGX_OK` from the access phase,
  which granted access under `satisfy any` and skipped other access checks.
- A missing `bot_verifier_redis_host` crashed the worker.

### Architecture
- DNS lookups use nginx's asynchronous resolver instead of blocking
  `getnameinfo`/`getaddrinfo` calls in the worker. Requests waiting on a
  lookup are suspended; concurrent requests for the same address share it.
- Results are cached in shared memory (LRU, per-result TTLs, survives
  reloads). Redis is optional, asynchronous and no longer consulted with a
  `PING` and `GET` on every request.
- Runs in the preaccess phase so `satisfy any` cannot override a block.
- A cached failure only blocks requests that claim to be a crawler.

### New
- Configurable providers (`bot_verifier_provider`) and an updated built-in
  list: Google, Bing, Apple, Yandex, Baidu, Yahoo, DuckDuckGo.
- Published IP ranges (`bot_verifier_ranges`, `script/fetch-ranges`), in the
  providers' JSON or plain text.
- IPv6.
- `bot_verifier monitor`, `bot_verifier_block_status`, `bot_verifier_ttl`,
  `bot_verifier_timeout`.
- `$bot_verifier_result`, `$bot_verifier_provider` and `$bot_verifier_time`
  (how long the request waited for verification).
- `bot_verifier_metrics` (Prometheus), including a histogram of lookup
  durations by source (#9). Failed and unknown lookups are logged with their
  duration.
- Reporting to Repsheet 6 (`REPSHEET.MARK`/`BLOCK ... BY bot_verifier`),
  replacing the removed `REPSHEET.BLACKLIST`.
- With the Repsheet nginx module loaded, its `repsheet_redis` and
  `repsheet_redis_auth` settings are used, so nothing is configured twice
  (#16). `bot_verifier_redis` overrides them; `bot_verifier_redis off`
  disables Redis.
- Tests with pytest against real nginx, a fake DNS server and Valkey; ASan
  and UBSan runs; GitHub Actions; Docker image and compose example.
- Apache 2.0 license.

### Upgrading from 0.0.x
| 0.0.x | 1.0 |
|-------|-----|
| `bot_verifier_redis_host` + `bot_verifier_redis_port` | `repsheet_redis` (with the Repsheet module) or `bot_verifier_redis host:port` (optional) |
| `bot_verifier_redis_connection_timeout`, `bot_verifier_redis_read_timeout` | `bot_verifier_redis_timeout` |
| `bot_verifier_redis_expiry` | `bot_verifier_ttl` |
| `bot_verifier_enable_repsheet on` | `bot_verifier_repsheet mark` or `block` |
| (none) | `resolver` is now required |
| Redis keys `<ip>:bvs` = `success`/`failure` | `{bot_verifier}:<ip>` = `verified:<provider>`/`failed:<provider>` |
| `X-Forwarded-For` trusted | configure `set_real_ip_from` / `real_ip_header` |

## 0.0.5 (2018-09-12) and earlier

Synchronous reverse/forward DNS verification of Google, Bing, Yahoo, Baidu
and Yandex crawlers, with results cached in Redis.

# Changelog

## 6.0.0 (unreleased)

A rewrite that merges `repsheet-nginx` and `redis_module` into one
repository. History from both is preserved.

### Architecture
- nginx no longer talks to Redis while handling requests. Decisions are
  mirrored into shared memory by one worker, using non-blocking hiredis on the
  nginx event loop: a snapshot on start, then an ordered change log followed by
  polling plus pubsub wake-ups, with automatic resync. Previously every request
  made two blocking round trips (`PING` + lookup).
- The Redis module is the source of truth, with a new data model (one hash per
  actor, an index, a change stream) under the `{repsheet}` hash tag.

### New
- Network decisions (`10.0.0.0/8`, `2001:db8::/48`) with most-specific
  matching, and IPv4-mapped IPv6 canonicalization.
- Custom actor types: `repsheet_actor session $cookie_session;`, and the
  matching `REPSHEET.BLOCK session:<value>`.
- `repsheet monitor`, `repsheet_block_status`, `$repsheet_status`,
  `$repsheet_reason`, `$repsheet_actor`.
- `repsheet_metrics` Prometheus endpoint.
- `REPSHEET.CLEAR`, `REPSHEET.GET`, `REPSHEET.CHECK`, `REPSHEET.SNAPSHOT`,
  `REPSHEET.CHANGES`; `REASON` and `TTL` options.
- Valkey (≥ 7.2) and Redis (≥ 7.2) support, Unix sockets, `AUTH`, and syncing
  from replicas.
- Detectors. **Active detectors** run inside the nginx module and record
  decisions in real time; **passive detectors** run out of band and write
  decisions with the REPSHEET.* commands (contract in `detectors/`).
- The bot verifier, the first active detector (formerly
  repsheet/ngx_bot_verifier, history merged): verifies clients that claim to
  be search engine crawlers by published IP ranges or reverse + forward DNS,
  using nginx's asynchronous resolver, and records a `block` (or `mark`)
  decision `BY bot_verifier` for those that fail. `repsheet_bot_verifier*`
  directives, `$repsheet_bot_verifier_*` variables and metrics.
- `repsheet-bench` (`make bench`): measures the CPU Repsheet adds per request
  against nginx without it, across store sizes, networks, actors, sync churn
  and the bot verifier.
- `repsheet-admin`, a web UI (Rust) to look up actors, list, add, change and
  clear decisions, and browse the change log. Replaces the archived
  `repsheet/visualizer`.
- `BY <who>` on `REPSHEET.ALLOW`/`BLOCK`/`MARK`/`CLEAR` records the author;
  change log entries carry `by` and `at` (time of change).
- Docker images and a compose example; GitHub Actions CI; ASan/UBSan runs.

### Fixed
- Blacklist bypass: the leftmost `X-Forwarded-For` entry was trusted, so any
  client could claim any address (including a whitelisted one). The client
  address now comes from the connection after nginx's `realip` module.
- `repsheet_proxy_headers off` was ignored.
- nginx worker crash freeing uninitialized pointers when Redis replied with an
  error (for example when the module was not loaded).
- Stack buffer overflow in the Redis module for reasons longer than 1024 bytes.
- Memory leaks in the Redis module on every command.
- Unchecked TTL parsing; read-only commands registered as writes.
- Build failures on GCC ≥ 10 (`-fno-common`) and nginx ≥ 1.23.

### Upgrading from 5.x
| 5.x | 6.0 |
|-----|-----|
| `REPSHEET.BLACKLIST ip reason [ttl]` | `REPSHEET.BLOCK ip REASON reason [TTL ttl]` |
| `REPSHEET.WHITELIST ...` | `REPSHEET.ALLOW ...` |
| `REPSHEET.MARK ip reason [ttl]` | `REPSHEET.MARK ip REASON reason [TTL ttl]` |
| `REPSHEET.STATUS ip` | `REPSHEET.CHECK ip` (statuses are now lowercase `allow`/`block`/`mark`/`none`) |
| `repsheet_redis_host` + `repsheet_redis_port` | `repsheet_redis host:port` |
| `repsheet_redis_connection_timeout`, `repsheet_redis_read_timeout` | `repsheet_redis_timeout` |
| `repsheet_proxy_headers*` | `set_real_ip_from` / `real_ip_header` (realip module) |
| `X-Repsheet` request header on marked actors | `proxy_set_header X-Repsheet $repsheet_reason;` |

Keys written by the old Redis module (`<ip>:repsheet:ip:<list>`) are not read. Re-create decisions
with the new commands, for example by scanning the old keys.

## Earlier releases (nginx module)

The 5.x releases were not recorded here. 5.0.0 (2018-11-30) moved lookups
to the Redis module's `REPSHEET.STATUS` command; 5.0.1 and 5.0.2 (December
2018) fixed the marked-actor header; 5.1.0 (2019-06-23) used the module's
updated status response.

2015-12-30  Aaron Bedra  <aaron@aaronbedra.com>

	* 4.2.0: Add alternate proxy header fallback

2015-12-09  Aaron Bedra  <aaron@aaronbedra.com>

	* 4.1.0: Add reason code to X-Repsheet header

2015-10-28  Aaron Bedra  <aaron@aaronbedra.com>

	* 4.0.1: Revert back to static headers

2015-10-05  Aaron Bedra  <aaron@aaronbedra.com>

	* 4.0.0: CIDR lookup caching

2015-05-06  Aaron Bedra  <aaron@aaronbedra.com>

	* 3.0.0: Read timeouts
	  - read_timeout is now an option
	  - XFF processing moved to librepsheet
	  - Keyspace in tests updated to match librepsheet

2014-11-25  Aaron Bedra  <aaron@aaronbedra.com>

	* 2.1.0: Bug fixes
	  - Defer processing if enabled is unset
	  - Allow enabled flag to be set in a location
	  - Make log messages consistent
	  - Fix header processing

2014-09-12  Aaron Bedra  <aaron@aaronbedra.com>

	* 2.0.0: Performance improvements. Now relies on librepsheet >= 3.0.0

2014-08-05  Aaron Bedra  <aaron@aaronbedra.com>

	* 1.2.0: Updates from librepsheet to use LIBREPSHEET_OK instead
	          of the removed OK variable.

2014-08-03  Aaron Bedra  <aaron@aaronbedra.com>

	* 1.1.0: Adds blacklist reason to logs

2014-07-24  Aaron Bedra  <aaron@aaronbedra.com>

	* 1.0.0: This is the first stable and production worthy release.


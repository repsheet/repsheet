# Detectors

Repsheet enforces decisions; detectors make them. Every decision, whoever
made it, is the same thing: an actor, a status (`block`, `mark` or `allow`),
a reason, a TTL and an author (`BY`). nginx enforces it on every server once
it is in Valkey, the admin UI shows it, and the change log records it.

There are two kinds of detector.

## Active detectors

Active detectors run inside the nginx module, in real time, on the request
path. They see a request before nginx acts on it and can decide about it on
the spot.

* They run only for requests that are neither allowed nor already blocked,
  and only where `repsheet` is `on` or `monitor`.
* A detector's decision is applied to the local store at once (every worker
  of that nginx enforces it immediately) and written to Valkey with
  `REPSHEET.BLOCK`/`MARK ... BY <detector>`, so every other nginx enforces it
  after its next sync.
* The request that triggered it is judged by the new decision.
* They must never block the worker: anything slow (DNS, Redis) is
  asynchronous, and the request waits without holding up others.
* Each one can be turned on, off or to `monitor` (evaluate and log, record
  nothing) per location.

| Detector | Directive | What it decides |
|----------|-----------|-----------------|
| [bot verifier](../README.md#bot-verifier) | `repsheet_bot_verifier` | Clients claiming to be a search engine crawler that are not: block (or mark) the address. |

The code lives in `nginx/src/<detector>/` and is called from
`ngx_http_repsheet_handler()`. Shared pieces: `ngx_http_repsheet_record()`
records a decision, and the per-worker client in `ngx_http_repsheet_redis.c`
gives detectors a non-blocking Valkey connection.

## Passive detectors

Passive detectors run out of band: they read access logs, application
events, threat feeds or anything else, and write decisions into Valkey.
nginx enforces them through the sync it already does; the request path never
waits for them. See [passive/README.md](passive/README.md) for the contract.
None are built yet.

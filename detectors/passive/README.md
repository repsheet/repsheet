# Passive detectors

A passive detector is any program that reads signals outside the request
path (access logs, application events, threat intelligence, a SIEM) and
turns them into Repsheet decisions. It needs nothing from nginx: it talks to
the same Valkey/Redis (with the Repsheet module loaded) that nginx syncs
from.

## The contract

**Write decisions with the Repsheet commands.**

```
REPSHEET.BLOCK <actor> REASON <why> TTL <seconds> BY <detector>
REPSHEET.MARK  <actor> REASON <why> TTL <seconds> BY <detector>
```

* **Actor.** An address or network (`203.0.113.9`, `198.51.100.0/24`,
  `2001:db8::/48`) or `<type>:<value>` for anything nginx can see through
  `repsheet_actor` (`session:…`, `api_key:…`). The module canonicalizes it.
* **Always set a TTL.** Detectors are wrong sometimes; decisions should age
  out unless the detector keeps seeing the behavior and writes again.
* **`BY` is the detector's name** (`log-404-scanner`, `credential-stuffing`).
  It is stored with the decision and in the change log, and the admin UI
  shows it. Keep it short and stable.
* **`REASON` says what was seen**, briefly, for whoever reviews it later:
  `"312 404s in 60s"`, not `"bad"`.
* **Prefer `MARK` when unsure.** A mark lets the request through and tells
  nginx and the application (`$repsheet_status`, `$repsheet_reason`); pair it
  with `limit_req` to slow an actor down instead of shutting it out.
* **Do not write `ALLOW`** unless the detector is the source of truth for
  trusted actors. An allow overrides every block, including other
  detectors'.
* **Writing again is fine.** A new decision replaces the previous one for
  that actor and restarts its TTL. To lift one early, `REPSHEET.CLEAR <actor>
  BY <detector>`.
* **Write to the primary.** nginx may sync from replicas; replicas refuse
  writes.

**Reading.** `REPSHEET.CHECK <actor>` shows what nginx would do for an
actor, including network matches. `{repsheet}:changes` is a stream of every
change (with `by` and `at`) if a detector needs to react to others' decisions
or avoid repeating them.

## Layout

Put each passive detector in its own directory here
(`detectors/passive/<name>/`) with its own README, configuration and tests.
It may be written in any language; it only needs a Redis client.

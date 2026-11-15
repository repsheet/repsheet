# Managing decisions

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

## How decisions apply

When several decisions apply to a request, **allow** beats **block**, which
beats **mark**. Between decisions of equal status, the most specific one
wins. An address matches decisions for itself and for every network that
contains it, and a request is also checked against any other actors nginx
is configured to see (`repsheet_actor`, see [configuration](configuration.md)).

* **block**: nginx rejects the request (403 by default).
* **allow**: the actor is trusted, which overrides any block or mark.
* **mark**: the request goes through, and `$repsheet_status`,
  `$repsheet_reason` and `$repsheet_actor` let you pass the signal to the
  application, log it, or feed it into `limit_req`.

Network decisions are matched without a trie. The store counts how many
entries exist at each prefix length; a lookup masks the client address to
each prefix length in use, checks a small per-length filter, and only looks
the network up when the filter says it might be there.

## Data layout

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

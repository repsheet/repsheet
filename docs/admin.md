# Admin UI

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

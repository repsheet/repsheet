.PHONY: all bootstrap module nginx admin bench bench-quick version bump test test-module test-nginx test-admin sanitize clean distclean format \
        run-valkey run-admin docker-build docker-up docker-down docker-logs

all: module nginx admin

# Fetch and build pinned hiredis, Valkey and nginx into .deps/
bootstrap:
	script/bootstrap

module:
	$(MAKE) -C redis

nginx: module
	script/bootstrap nginx

# The web admin UI (needs a Rust toolchain).
admin:
	cargo build --release --manifest-path admin/Cargo.toml

test: module admin
	cd tests && uv run pytest

test-module: module
	cd tests && uv run pytest test_module.py

test-nginx: module
	cd tests && uv run pytest test_nginx.py

test-admin: module admin
	cargo test --manifest-path admin/Cargo.toml
	cd tests && uv run pytest test_admin.py

# Full suite with ASan/UBSan on the module, Valkey and nginx.
sanitize:
	$(MAKE) -C redis SANITIZE=1
	script/bootstrap asan
	# Restore the normal nginx build even when the tests fail.
	cd tests && SANITIZE=1 uv run pytest; status=$$?; \
	  cd .. && script/bootstrap nginx >/dev/null && exit $$status

# --------------------------------------------------------------------------
# Benchmarks: what Repsheet adds to the CPU cost of a request, scenario by
# scenario, against nginx without Repsheet. Needs a quiet machine.
#   make bench                           full suite, results in bench/results/
#   make bench BENCH_ARGS="-s store-1m"  one scenario (see: repsheet-bench list)
#   make bench BENCH_ARGS="--compare bench/results/<earlier>.json"
#   make bench BENCH_ARGS="--rate 50000"  latency percentiles below saturation
# --------------------------------------------------------------------------

BENCH_ARGS ?=
BENCH = bench/target/release/repsheet-bench

$(BENCH): $(wildcard bench/src/*.rs) bench/Cargo.toml
	cargo build --release --manifest-path bench/Cargo.toml

# Rebuilt whenever the module's sources change.
.deps/nginx-bench/sbin/nginx: $(wildcard nginx/config nginx/src/*.[ch] nginx/src/*/*.[ch] common/*.[ch])
	script/bootstrap bench

bench: module .deps/nginx-bench/sbin/nginx $(BENCH)
	$(BENCH) run --pin --json bench/results/$$(date -u +%Y%m%dT%H%M%SZ).json $(BENCH_ARGS)

# A fast pass over every scenario (short runs, one repeat): checks it all works.
bench-quick: module .deps/nginx-bench/sbin/nginx $(BENCH)
	$(BENCH) run --duration 2 --warmup 1 --repeat 1 $(BENCH_ARGS)

# --------------------------------------------------------------------------
# Running locally. Start Valkey in one terminal and the admin UI in another:
#   make run-valkey
#   make run-admin           # http://127.0.0.1:8090
# Point the UI elsewhere with REDIS=redis://host:port, pass more options with
# ADMIN_ARGS="--read-only --listen 127.0.0.1:9000".
# --------------------------------------------------------------------------

VALKEY      ?= .deps/prefix/bin/valkey-server
VALKEY_PORT ?= 6379
REDIS       ?= redis://127.0.0.1:$(VALKEY_PORT)
ADMIN_ARGS  ?=

# Valkey with the module loaded, in the foreground. Data is kept in memory only.
run-valkey: module
	@test -x $(VALKEY) || { echo "$(VALKEY) not found; run 'script/bootstrap deps' or set VALKEY=/path/to/valkey-server"; exit 1; }
	$(VALKEY) --port $(VALKEY_PORT) --bind 127.0.0.1 --save "" --appendonly no \
	  --loadmodule $(CURDIR)/redis/repsheet.so

run-admin: admin
	admin/target/release/repsheet-admin --redis $(REDIS) $(ADMIN_ARGS)

# --------------------------------------------------------------------------
# Docker: Valkey + nginx (:8080) + admin UI (:8090) from examples/.
# --------------------------------------------------------------------------

COMPOSE = docker compose -f examples/docker-compose.yml

docker-build:
	$(COMPOSE) build

docker-up:
	$(COMPOSE) up --build -d
	@echo "nginx:    http://localhost:8080"
	@echo "metrics:  http://localhost:8080/metrics"
	@echo "admin UI: http://localhost:8090"
	@echo "grafana:  http://localhost:3000  (Repsheet dashboard; admin/admin to edit)"
	@echo "prometheus: http://localhost:9090"

docker-down:
	$(COMPOSE) down

docker-logs:
	$(COMPOSE) logs -f

# --------------------------------------------------------------------------
# Versions and releases (see README "Releasing").
#   make version                 print the current version
#   make bump VERSION=6.1.0      set it everywhere; then commit and tag
# --------------------------------------------------------------------------

version:
	@sed -n 's/^#define REPSHEET_VERSION "\(.*\)"$$/\1/p' redis/src/repsheet.c

bump:
	@test -n "$(VERSION)" || { echo "usage: make bump VERSION=<major>.<minor>.<patch>"; exit 1; }
	script/bump-version $(VERSION)

format:
	clang-format -i common/*.c common/*.h redis/src/*.c
	cargo fmt --manifest-path admin/Cargo.toml

clean:
	$(MAKE) -C redis clean
	cargo clean --manifest-path admin/Cargo.toml
	cargo clean --manifest-path bench/Cargo.toml

distclean: clean
	script/bootstrap clean

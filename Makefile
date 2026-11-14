.PHONY: all bootstrap nginx test sanitize ranges clean distclean \
        docker-build docker-up docker-down docker-logs

all: nginx

# Fetch and build pinned hiredis, Valkey, the Repsheet module and nginx into .deps/
bootstrap:
	script/bootstrap

# Rebuild nginx with the module after changing the source.
nginx:
	script/bootstrap nginx

test:
	cd tests && uv run pytest

# The suite with ASan/UBSan on nginx, Valkey and the Repsheet module.
sanitize:
	script/bootstrap asan
	# Restore the normal nginx build even when the tests fail.
	cd tests && SANITIZE=1 uv run pytest; status=$$?; \
	  cd .. && script/bootstrap nginx >/dev/null && exit $$status

# Download the crawlers' published IP ranges into ranges/.
ranges:
	script/fetch-ranges ranges

# --------------------------------------------------------------------------
# Docker: nginx with the module (:8080) and Valkey, from examples/.
# --------------------------------------------------------------------------

COMPOSE = docker compose -f examples/docker-compose.yml

docker-build:
	$(COMPOSE) build

docker-up:
	$(COMPOSE) up --build -d
	@echo "nginx:   http://localhost:8081"
	@echo "metrics: http://localhost:8081/metrics"

docker-down:
	$(COMPOSE) down

docker-logs:
	$(COMPOSE) logs -f

clean:
	rm -rf tests/.pytest_cache

distclean: clean
	script/bootstrap clean

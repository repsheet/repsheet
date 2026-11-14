.PHONY: all bootstrap module nginx test test-module test-nginx sanitize clean distclean format

all: module nginx

# Fetch and build pinned hiredis, Valkey and nginx into .deps/
bootstrap:
	script/bootstrap

module:
	$(MAKE) -C redis

nginx: module
	script/bootstrap nginx

test: module
	cd tests && uv run pytest

test-module: module
	cd tests && uv run pytest test_module.py

test-nginx: module
	cd tests && uv run pytest test_nginx.py

# Full suite with ASan/UBSan on the module, Valkey and nginx.
sanitize:
	$(MAKE) -C redis SANITIZE=1
	script/bootstrap asan
	# Restore the normal nginx build even when the tests fail.
	cd tests && SANITIZE=1 uv run pytest; status=$$?; \
	  cd .. && script/bootstrap nginx >/dev/null && exit $$status

format:
	clang-format -i common/*.c common/*.h redis/src/*.c

clean:
	$(MAKE) -C redis clean

distclean: clean
	script/bootstrap clean

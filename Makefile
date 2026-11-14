.PHONY: all bootstrap module nginx admin test test-module test-nginx test-admin sanitize clean distclean format

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

format:
	clang-format -i common/*.c common/*.h redis/src/*.c
	cargo fmt --manifest-path admin/Cargo.toml

clean:
	$(MAKE) -C redis clean
	cargo clean --manifest-path admin/Cargo.toml

distclean: clean
	script/bootstrap clean

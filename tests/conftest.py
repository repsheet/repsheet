"""
Test fixtures: start a real Valkey (or Redis) server with the repsheet module
and, for the nginx tests, a real nginx built with the repsheet module.

Binaries are taken from .deps/ (built by script/bootstrap) unless overridden:
  REPSHEET_SERVER   path to valkey-server / redis-server
  REPSHEET_NGINX    path to an nginx binary built with the repsheet module
  REPSHEET_MODULE   path to the nginx dynamic module, if built with DYNAMIC=1
  REPSHEET_ADMIN    path to the repsheet-admin binary
"""

import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
import redis
import requests

ROOT = Path(__file__).resolve().parent.parent
DEPS = ROOT / ".deps"
MODULE = ROOT / "redis" / "repsheet.so"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(predicate, timeout=5.0, interval=0.02, message="condition"):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = predicate()
            if last:
                return last
        except Exception as e:  # noqa: BLE001 - keep polling until timeout
            last = e
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {message} (last: {last!r})")


def server_binary():
    env = os.environ.get("REPSHEET_SERVER")
    if env:
        return env
    if os.environ.get("SANITIZE") == "1":
        asan = DEPS / "asan" / "bin" / "valkey-server"
        if not asan.exists():
            pytest.exit("SANITIZE=1 needs script/bootstrap asan", 2)
        return str(asan)
    for name in ("valkey-server", "redis-server"):
        local = DEPS / "prefix" / "bin" / name
        if local.exists():
            return str(local)
        found = shutil.which(name)
        if found:
            return found
    pytest.exit("no valkey-server or redis-server found; run script/bootstrap", 2)


class Server:
    def __init__(self, tmp, module_args=(), port=None, module=True, extra=(), password=None):
        self.port = port or free_port()
        self.dir = tmp
        load = ["--loadmodule", str(MODULE), *module_args] if module else []
        args = [
            server_binary(),
            "--port", str(self.port),
            "--bind", "127.0.0.1",
            "--save", "",
            "--appendonly", "no",
            "--repl-diskless-sync-delay", "0",
            "--dir", str(tmp),
            *load, *extra,
        ]
        if password:
            args += ["--requirepass", password]
        self.log_path = tmp / "server.log"
        self.log = open(self.log_path, "a")
        env = dict(os.environ)
        if os.environ.get("SANITIZE") == "1":
            env["ASAN_OPTIONS"] = "detect_leaks=0"
            env["UBSAN_OPTIONS"] = "print_stacktrace=1"
        self.proc = subprocess.Popen(args, stdout=self.log, stderr=subprocess.STDOUT, env=env)
        self.client = redis.Redis(port=self.port, decode_responses=True, password=password)
        wait_for(self.client.ping, message="server to start")

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=10)
        self.log.close()
        problem = sanitizer_problem(self.log_path.read_text())
        assert problem is None, f"server log shows a crash or sanitizer report:\n{problem}"


@pytest.fixture(scope="session")
def server(tmp_path_factory):
    if not MODULE.exists():
        pytest.exit("redis/repsheet.so not built; run make", 2)
    s = Server(tmp_path_factory.mktemp("server"))
    yield s
    s.stop()


@pytest.fixture
def r(server):
    server.client.flushall()
    return server.client


# --------------------------------------------------------------------------
# nginx
# --------------------------------------------------------------------------


def nginx_binary():
    env = os.environ.get("REPSHEET_NGINX")
    if env:
        return env
    local = DEPS / "nginx" / "sbin" / "nginx"
    if local.exists():
        return str(local)
    pytest.skip("nginx with repsheet not built; run script/bootstrap")


UBSAN_SUPP = Path(__file__).with_name("ubsan.supp")


def sanitizer_problem(text):
    """Return the offending report if `text` shows a crash, an ASan error, or
    any UBSan report. Reports are not filtered by where they come from: UB in
    nginx or Valkey reached through our code is still our bug, and filtering
    by nearby text made the check depend on timing and symbolization."""
    for marker in ("AddressSanitizer", "runtime error:", "BUG REPORT"):
        if marker in text:
            i = text.index(marker)
            return text[max(0, i - 300): i + 6000]
    if "exited on signal" in text:
        return text[-4000:]
    return None


class Nginx:
    """An nginx instance rendered from a config body.

    `http` is inserted into the http{} block. `{port}`, `{redis}` and
    `{metrics_port}` are substituted.
    """

    def __init__(self, tmp, redis_port, http, workers=2):
        self.dir = Path(tempfile.mkdtemp(dir=tmp))
        (self.dir / "logs").mkdir()
        (self.dir / "html").mkdir()
        (self.dir / "html" / "index.html").write_text("hello\n")
        self.port = free_port()
        self.redis_port = redis_port
        load = ""
        if os.environ.get("REPSHEET_MODULE"):
            load = f"load_module {os.environ['REPSHEET_MODULE']};"
        body = http.replace("{port}", str(self.port)).replace("{redis}", f"127.0.0.1:{redis_port}")
        conf = f"""
{load}
worker_processes {workers};
daemon off;
master_process on;
pid {self.dir}/nginx.pid;
error_log {self.dir}/logs/error.log debug;
events {{ worker_connections 256; }}
http {{
    access_log {self.dir}/logs/access.log;
    client_body_temp_path {self.dir}/tmp;
    proxy_temp_path {self.dir}/tmp;
    fastcgi_temp_path {self.dir}/tmp;
    uwsgi_temp_path {self.dir}/tmp;
    scgi_temp_path {self.dir}/tmp;
    root {self.dir}/html;
{body}
}}
"""
        (self.dir / "nginx.conf").write_text(conf)
        cmd = [nginx_binary(), "-p", str(self.dir), "-c", str(self.dir / "nginx.conf")]
        env = dict(os.environ)
        # nginx intentionally does not free its configuration at exit, so leak
        # detection is off; ASan memory errors and UBSan reports still count.
        san = f"log_path={self.dir}/sanitizer:print_stacktrace=1"
        env["ASAN_OPTIONS"] = san + ":detect_leaks=0"
        env["UBSAN_OPTIONS"] = f"{san}:suppressions={UBSAN_SUPP}"
        check = subprocess.run([*cmd, "-t"], capture_output=True, text=True, env=env)
        if check.returncode != 0:
            raise RuntimeError(f"nginx config test failed:\n{check.stderr}")
        self.proc = subprocess.Popen(cmd, stderr=subprocess.DEVNULL, env=env)
        self.url = f"http://127.0.0.1:{self.port}"
        wait_for(lambda: requests.get(self.url + "/__ready", timeout=1) is not None,
                 message="nginx to start")

    def get(self, path="/", **kwargs):
        return requests.get(self.url + path, timeout=5, **kwargs)

    def error_log(self):
        return (self.dir / "logs" / "error.log").read_text()

    def reload(self):
        self.proc.send_signal(1)  # SIGHUP

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        texts = [p.read_text() for p in sorted(self.dir.glob("sanitizer*"))]
        texts.append(self.error_log())  # nginx sends stderr to its error log
        for text in texts:
            problem = sanitizer_problem(text)
            assert problem is None, f"sanitizer or crash report:\n{problem}"


@pytest.fixture
def nginx_factory(server, tmp_path):
    started = []

    def make(http, workers=2, redis_port=None):
        n = Nginx(tmp_path, redis_port or server.port, http, workers)
        started.append(n)
        return n

    yield make
    for n in started:
        n.stop()


def metrics(n):
    """Parse the Prometheus text exposition into {name{labels}: value}."""
    out = {}
    for line in n.get("/metrics").text.splitlines():
        if line and not line.startswith("#"):
            key, value = line.rsplit(" ", 1)
            out[key] = float(value)
    return out


# --------------------------------------------------------------------------
# admin UI
# --------------------------------------------------------------------------


def admin_binary():
    env = os.environ.get("REPSHEET_ADMIN")
    if env:
        return env
    # The most recently built of the release and debug binaries.
    built = [p for p in (ROOT / "admin" / "target" / profile / "repsheet-admin" for profile in ("release", "debug"))
             if p.exists()]
    if not built:
        pytest.skip("repsheet-admin not built; run make admin")
    return str(max(built, key=lambda p: p.stat().st_mtime))


class Admin:
    """A running repsheet-admin. `get`/`post` send same-origin requests."""

    def __init__(self, tmp, redis_port, args=()):
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.log_path = Path(tempfile.mkdtemp(dir=tmp)) / "admin.log"
        self.log = open(self.log_path, "w")
        self.proc = subprocess.Popen(
            [admin_binary(), "--redis", f"redis://127.0.0.1:{redis_port}",
             "--listen", f"127.0.0.1:{self.port}", *args],
            stdout=self.log, stderr=subprocess.STDOUT,
        )
        self.session = requests.Session()
        wait_for(lambda: self.session.get(self.base + "/healthz", timeout=1).status_code == 200,
                 message=f"admin to start; log:\n{self.log_path}")

    def get(self, path, **kw):
        return self.session.get(self.base + path, timeout=5, **kw)

    def post(self, path, data, headers=None, **kw):
        h = {"Origin": self.base}
        h.update(headers or {})
        return self.session.post(self.base + path, data=data, headers=h, timeout=5,
                                 allow_redirects=False, **kw)

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=10)
        self.log.close()
        text = self.log_path.read_text()
        assert "panicked" not in text, text[-4000:]


@pytest.fixture
def admin_factory(server, r, tmp_path):
    started = []

    def make(args=()):
        a = Admin(tmp_path, server.port, args)
        started.append(a)
        return a

    yield make
    for a in started:
        a.stop()


@pytest.fixture
def admin(admin_factory):
    return admin_factory()

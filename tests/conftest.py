"""
Test fixtures: start a real Valkey (or Redis) server with the repsheet module
and, for the nginx tests, a real nginx built with the repsheet module.

Binaries are taken from .deps/ (built by script/bootstrap) unless overridden:
  REPSHEET_SERVER   path to valkey-server / redis-server
  REPSHEET_NGINX    path to an nginx binary built with the repsheet module
  REPSHEET_MODULE   path to the nginx dynamic module, if built with DYNAMIC=1
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
    for name in ("valkey-server", "redis-server"):
        local = DEPS / "prefix" / "bin" / name
        if local.exists():
            return str(local)
        found = shutil.which(name)
        if found:
            return found
    pytest.exit("no valkey-server or redis-server found; run script/bootstrap", 2)


class Server:
    def __init__(self, tmp, module_args=()):
        self.port = free_port()
        self.dir = tmp
        args = [
            server_binary(),
            "--port", str(self.port),
            "--bind", "127.0.0.1",
            "--save", "",
            "--appendonly", "no",
            "--repl-diskless-sync-delay", "0",
            "--dir", str(tmp),
            "--loadmodule", str(MODULE), *module_args,
        ]
        self.log = open(tmp / "server.log", "w")
        self.proc = subprocess.Popen(args, stdout=self.log, stderr=subprocess.STDOUT)
        self.client = redis.Redis(port=self.port, decode_responses=True)
        wait_for(self.client.ping, message="server to start")

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=10)
        self.log.close()


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
        check = subprocess.run([*cmd, "-t"], capture_output=True, text=True)
        if check.returncode != 0:
            raise RuntimeError(f"nginx config test failed:\n{check.stderr}")
        self.proc = subprocess.Popen(cmd, stderr=subprocess.DEVNULL)
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
        log = self.error_log()
        # Sanitizer reports and worker crashes must fail the test run.
        for marker in ("AddressSanitizer", "runtime error:", "exited on signal"):
            assert marker not in log, f"nginx error log contains {marker!r}:\n{log[-4000:]}"


@pytest.fixture
def nginx_factory(server, tmp_path):
    started = []

    def make(http, workers=2):
        n = Nginx(tmp_path, server.port, http, workers)
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

"""
Test fixtures: a real nginx built with the module, a fake DNS server whose
records each test controls, and a real Valkey with the Repsheet module for
the Redis cache and reporting tests.

Binaries are taken from .deps/ (built by script/bootstrap) unless overridden:
  BOT_VERIFIER_NGINX    path to an nginx binary built with the module
  BOT_VERIFIER_MODULE   path to the dynamic module, if built with DYNAMIC=1
  REPSHEET_NGINX_MODULE path to the Repsheet nginx dynamic module, if built with DYNAMIC=1
  REPSHEET_SERVER       path to valkey-server / redis-server
"""

import ipaddress
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest
import redis
import requests
from dnslib import AAAA, PTR, QTYPE, RCODE, RR, A, DNSRecord

ROOT = Path(__file__).resolve().parent.parent
DEPS = ROOT / ".deps"
UBSAN_SUPP = Path(__file__).with_name("ubsan.supp")

GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
BINGBOT = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
BROWSER = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"


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


def sanitizer_problem(text):
    """The offending report if `text` shows a crash, an ASan error or any UBSan report."""
    for marker in ("AddressSanitizer", "runtime error:", "BUG REPORT"):
        if marker in text:
            i = text.index(marker)
            return text[max(0, i - 300): i + 6000]
    if "exited on signal" in text:
        return text[-4000:]
    return None


# --------------------------------------------------------------------------
# fake DNS
# --------------------------------------------------------------------------


class FakeDNS:
    """A UDP DNS server answering PTR, A and AAAA from dictionaries.

    ptr:       address -> hostname
    addrs:     hostname -> [addresses] (A and AAAA)
    servfail:  names answered with SERVFAIL
    silent:    names never answered (timeouts)
    delay:     seconds to wait before answering anything
    queries:   every (name, type) received
    """

    def __init__(self):
        self.ptr = {}
        self.addrs = {}
        self.servfail = set()
        self.silent = set()
        self.delay = 0.0
        self.queries = []
        self.lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    @staticmethod
    def reverse_name(addr):
        return ipaddress.ip_address(addr).reverse_pointer + "."

    @staticmethod
    def norm(name):
        name = name.lower()
        return name if name.endswith(".") else name + "."

    def record(self, addr, host, forward=None):
        """addr's PTR is host; host resolves to forward (default: [addr])."""
        self.ptr[addr] = host
        self.addrs[self.norm(host)] = list(forward if forward is not None else [addr])

    def queries_for(self, *names):
        wanted = {self.norm(n) for n in names}
        with self.lock:
            return [q for q in self.queries if q[0] in wanted]

    def reverse_queries(self, addr):
        return self.queries_for(self.reverse_name(addr))

    def answer(self, request):
        q = request.q
        name = self.norm(str(q.qname))
        qtype = QTYPE[q.qtype]
        reply = request.reply()
        if name in self.servfail:
            reply.header.rcode = RCODE.SERVFAIL
            return reply
        if qtype == "PTR":
            for addr, host in self.ptr.items():
                if self.reverse_name(addr) == name:
                    reply.add_answer(RR(q.qname, QTYPE.PTR, rdata=PTR(host), ttl=60))
                    return reply
            reply.header.rcode = RCODE.NXDOMAIN
            return reply
        if qtype in ("A", "AAAA"):
            if name not in self.addrs:
                reply.header.rcode = RCODE.NXDOMAIN
                return reply
            for addr in self.addrs[name]:
                ip = ipaddress.ip_address(addr)
                if qtype == "A" and ip.version == 4:
                    reply.add_answer(RR(q.qname, QTYPE.A, rdata=A(addr), ttl=60))
                if qtype == "AAAA" and ip.version == 6:
                    reply.add_answer(RR(q.qname, QTYPE.AAAA, rdata=AAAA(addr), ttl=60))
            return reply
        reply.header.rcode = RCODE.NOTIMP
        return reply

    def serve(self):
        self.sock.settimeout(0.2)
        while self.running:
            try:
                data, peer = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                request = DNSRecord.parse(data)
            except Exception:  # noqa: BLE001
                continue
            name = self.norm(str(request.q.qname))
            with self.lock:
                self.queries.append((name, QTYPE[request.q.qtype]))
            if name in self.silent:
                continue
            if self.delay:
                threading.Timer(self.delay, self.send, (request, peer)).start()
            else:
                self.send(request, peer)

    def send(self, request, peer):
        try:
            self.sock.sendto(self.answer(request).pack(), peer)
        except OSError:
            pass

    def stop(self):
        self.running = False
        self.sock.close()


@pytest.fixture
def dns():
    d = FakeDNS()
    yield d
    d.stop()


# --------------------------------------------------------------------------
# Valkey (+ Repsheet module)
# --------------------------------------------------------------------------


def server_binary():
    env = os.environ.get("REPSHEET_SERVER")
    if env:
        return env
    if os.environ.get("SANITIZE") == "1":
        return str(DEPS / "asan" / "bin" / "valkey-server")
    local = DEPS / "prefix" / "bin" / "valkey-server"
    if local.exists():
        return str(local)
    found = shutil.which("valkey-server") or shutil.which("redis-server")
    if found:
        return found
    pytest.exit("no valkey-server found; run script/bootstrap", 2)


def repsheet_module():
    if os.environ.get("SANITIZE") == "1":
        return DEPS / "asan" / "lib" / "repsheet.so"
    return DEPS / "prefix" / "lib" / "repsheet.so"


class Server:
    def __init__(self, tmp, port=None, password=None):
        self.port = port or free_port()
        self.log_path = Path(tmp) / f"server-{self.port}.log"
        args = [server_binary(), "--port", str(self.port), "--bind", "127.0.0.1", "--save", "",
                "--appendonly", "no", "--dir", str(tmp)]
        if password:
            args += ["--requirepass", password]
        module = repsheet_module()
        if module.exists():
            args += ["--loadmodule", str(module)]
        env = dict(os.environ)
        if os.environ.get("SANITIZE") == "1":
            env["ASAN_OPTIONS"] = "detect_leaks=0"
        self.log = open(self.log_path, "a")
        self.proc = subprocess.Popen(args, stdout=self.log, stderr=subprocess.STDOUT, env=env)
        self.client = redis.Redis(port=self.port, decode_responses=True, password=password)
        wait_for(self.client.ping, message="valkey to start")

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=10)
        self.log.close()


@pytest.fixture(scope="session")
def server(tmp_path_factory):
    s = Server(tmp_path_factory.mktemp("valkey"))
    yield s
    s.stop()


@pytest.fixture
def r(server):
    server.client.flushall()
    return server.client


# --------------------------------------------------------------------------
# nginx
# --------------------------------------------------------------------------


def has_repsheet_nginx_module():
    """True if nginx can use repsheet_* directives (built in, or loadable)."""
    if os.environ.get("REPSHEET_NGINX_MODULE"):
        return True
    out = subprocess.run([nginx_binary(), "-V"], capture_output=True, text=True).stderr
    return "repsheet" in out and "--add-dynamic-module" not in out


def nginx_binary():
    env = os.environ.get("BOT_VERIFIER_NGINX")
    if env:
        return env
    local = DEPS / "nginx" / "sbin" / "nginx"
    if local.exists():
        return str(local)
    pytest.skip("nginx with the module not built; run script/bootstrap")


class Nginx:
    """An nginx instance. `http` goes inside http{}; {port}, {resolver} and
    {redis} are substituted."""

    def __init__(self, tmp, http, dns_port, redis_port=None, workers=1):
        self.dir = Path(tempfile.mkdtemp(dir=tmp))
        (self.dir / "logs").mkdir()
        (self.dir / "html").mkdir()
        (self.dir / "html" / "index.html").write_text("hello\n")
        self.port = free_port()
        load = ""
        for env in ("BOT_VERIFIER_MODULE", "REPSHEET_NGINX_MODULE"):
            if os.environ.get(env):
                load += f"load_module {os.environ[env]};\n"
        body = (http.replace("{port}", str(self.port))
                    .replace("{resolver}", f"127.0.0.1:{dns_port}")
                    .replace("{redis}", f"127.0.0.1:{redis_port or 1}")
                    .replace("{dir}", str(self.dir)))
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
        self.cmd = [nginx_binary(), "-p", str(self.dir), "-c", str(self.dir / "nginx.conf")]
        self.env = dict(os.environ)
        san = f"log_path={self.dir}/sanitizer:print_stacktrace=1"
        self.env["ASAN_OPTIONS"] = san + ":detect_leaks=0"
        self.env["UBSAN_OPTIONS"] = f"{san}:suppressions={UBSAN_SUPP}"
        check = self.test()
        if check.returncode != 0:
            raise RuntimeError(f"nginx config test failed:\n{check.stderr}")
        self.proc = subprocess.Popen(self.cmd, stderr=subprocess.DEVNULL, env=self.env)
        self.url = f"http://127.0.0.1:{self.port}"
        wait_for(lambda: requests.get(self.url + "/__ready", timeout=1) is not None, message="nginx to start")

    def test(self):
        return subprocess.run([*self.cmd, "-t"], capture_output=True, text=True, env=self.env)

    def get(self, path="/", ip=None, ua=None, headers=None, **kwargs):
        h = dict(headers or {})
        if ip is not None:
            h["X-Real-IP"] = ip
        if ua is not None:
            h["User-Agent"] = ua
        return requests.get(self.url + path, headers=h, timeout=10, **kwargs)

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
        texts.append(self.error_log())
        for text in texts:
            problem = sanitizer_problem(text)
            assert problem is None, f"sanitizer or crash report:\n{problem}"


SERVER = """
    resolver {resolver} valid=1s;
    resolver_timeout 2s;
    %(http)s
    server {
        listen 127.0.0.1:{port};
        set_real_ip_from 127.0.0.1;
        real_ip_header X-Real-IP;
        add_header X-Result $bot_verifier_result always;
        add_header X-Provider $bot_verifier_provider always;

        location / {
            %(location)s
        }
        location = /metrics {
            bot_verifier_metrics;
        }
        location = /__ready {
            return 204;
        }
        %(server)s
    }
"""


@pytest.fixture
def nginx_factory(dns, tmp_path):
    started = []

    def make(location="bot_verifier on;", http="", server="", raw=None, workers=1, redis_port=None):
        conf = raw if raw is not None else SERVER % {"http": http, "location": location, "server": server}
        n = Nginx(tmp_path, conf, dns.port, redis_port, workers)
        started.append(n)
        return n

    yield make
    for n in started:
        n.stop()


def metrics(n):
    out = {}
    for line in n.get("/metrics").text.splitlines():
        if line and not line.startswith("#"):
            k, v = line.rsplit(" ", 1)
            out[k] = float(v)
    return out

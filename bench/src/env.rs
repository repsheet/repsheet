//! Processes under test: Valkey with the Repsheet module, and nginx (the
//! optimized build in .deps/nginx-bench) with one worker.

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub type Result<T> = std::result::Result<T, String>;

pub struct Paths {
    pub nginx: PathBuf,
    pub valkey: PathBuf,
    pub module: PathBuf,
}

impl Paths {
    /// Find the repository (the directory holding .deps/) from the current directory up.
    pub fn discover() -> Result<Paths> {
        let mut dir = std::env::current_dir().map_err(|e| e.to_string())?;
        loop {
            if dir.join(".deps").is_dir() && dir.join("redis").is_dir() {
                break;
            }
            if !dir.pop() {
                return Err("run from inside the repsheet repository (with .deps/ built)".into());
            }
        }
        let p = Paths {
            nginx: dir.join(".deps/nginx-bench/sbin/nginx"),
            valkey: dir.join(".deps/prefix/bin/valkey-server"),
            module: dir.join("redis/repsheet.so"),
        };
        for (what, path, fix) in [
            ("benchmark nginx", &p.nginx, "script/bootstrap bench"),
            ("valkey-server", &p.valkey, "script/bootstrap deps"),
            ("redis/repsheet.so", &p.module, "make module"),
        ] {
            if !path.exists() {
                return Err(format!("{what} not found at {}; run {fix}", path.display()));
            }
        }
        Ok(p)
    }
}

pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("free port")
}

fn wait_for(what: &str, timeout: Duration, mut f: impl FnMut() -> bool) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if f() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!("timed out waiting for {what}"))
}

// --------------------------------------------------------------------------
// Valkey
// --------------------------------------------------------------------------

pub struct Valkey {
    pub port: u16,
    child: Child,
}

impl Valkey {
    pub fn start(paths: &Paths, dir: &Path) -> Result<Valkey> {
        let port = free_port();
        let child = Command::new(&paths.valkey)
            .args([
                "--port",
                &port.to_string(),
                "--bind",
                "127.0.0.1",
                "--save",
                "",
                "--appendonly",
                "no",
            ])
            .arg("--dir")
            .arg(dir)
            .arg("--loadmodule")
            .arg(&paths.module)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("starting valkey: {e}"))?;
        let v = Valkey { port, child };
        wait_for("valkey", Duration::from_secs(10), || v.connection().is_ok())?;
        Ok(v)
    }

    pub fn connection(&self) -> Result<redis::Connection> {
        redis::Client::open(format!("redis://127.0.0.1:{}/", self.port))
            .and_then(|c| c.get_connection())
            .map_err(|e| e.to_string())
    }

    /// Run commands in pipelined batches.
    pub fn pipeline(&self, commands: impl Iterator<Item = Vec<String>>) -> Result<usize> {
        let mut conn = self.connection()?;
        let mut n = 0;
        let mut pipe = redis::pipe();
        let mut batch = 0;
        for args in commands {
            let mut cmd = redis::cmd(&args[0]);
            for a in &args[1..] {
                cmd.arg(a);
            }
            pipe.add_command(cmd).ignore();
            batch += 1;
            n += 1;
            if batch == 10_000 {
                pipe.exec(&mut conn).map_err(|e| e.to_string())?;
                pipe = redis::pipe();
                batch = 0;
            }
        }
        if batch > 0 {
            pipe.exec(&mut conn).map_err(|e| e.to_string())?;
        }
        Ok(n)
    }
}

impl Drop for Valkey {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// --------------------------------------------------------------------------
// nginx
// --------------------------------------------------------------------------

pub struct Nginx {
    pub addr: SocketAddr,
    dir: PathBuf,
    child: Child,
    worker: u32,
}

pub struct NginxConf<'a> {
    /// Inside http{}.
    pub http: &'a str,
    /// Inside location / {}.
    pub location: &'a str,
}

impl Nginx {
    pub fn start(paths: &Paths, dir: &Path, conf: &NginxConf, pin: Option<usize>) -> Result<Nginx> {
        fs::create_dir_all(dir.join("logs")).map_err(|e| e.to_string())?;
        fs::create_dir_all(dir.join("html")).map_err(|e| e.to_string())?;
        fs::write(dir.join("html/index.html"), "hello\n").map_err(|e| e.to_string())?;
        let port = free_port();
        let d = dir.display();
        let text = format!(
            r#"
worker_processes 1;
daemon off;
master_process on;
pid {d}/nginx.pid;
error_log {d}/logs/error.log warn;
events {{ worker_connections 4096; }}
http {{
    access_log off;
    keepalive_requests 10000000;
    keepalive_timeout 300s;
    root {d}/html;
    client_body_temp_path {d}/tmp;
    proxy_temp_path {d}/tmp;
    fastcgi_temp_path {d}/tmp;
    uwsgi_temp_path {d}/tmp;
    scgi_temp_path {d}/tmp;
    {http}
    server {{
        listen 127.0.0.1:{port} backlog=4096;
        set_real_ip_from 127.0.0.1;
        real_ip_header X-Real-IP;
        location / {{
            {location}
        }}
        location = /__metrics {{
            access_log off;
            {metrics}
        }}
    }}
}}
"#,
            http = conf.http,
            location = conf.location,
            metrics = if conf.http.contains("repsheet_redis") {
                "repsheet off; repsheet_metrics;"
            } else {
                "return 204;"
            },
        );
        fs::write(dir.join("nginx.conf"), text).map_err(|e| e.to_string())?;

        let mut cmd = match pin {
            Some(cpu) => {
                let mut c = Command::new("taskset");
                c.args(["-c", &cpu.to_string()]).arg(&paths.nginx);
                c
            }
            None => Command::new(&paths.nginx),
        };
        let child = cmd
            .arg("-p")
            .arg(dir)
            .arg("-c")
            .arg(dir.join("nginx.conf"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("starting nginx: {e}"))?;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
        let mut n = Nginx {
            addr,
            dir: dir.to_path_buf(),
            child,
            worker: 0,
        };
        wait_for("nginx", Duration::from_secs(10), || {
            TcpStream::connect(addr).is_ok()
        })
        .map_err(|e| format!("{e}; see {}/logs/error.log", d))?;
        n.worker = n.find_worker()?;
        Ok(n)
    }

    fn find_worker(&self) -> Result<u32> {
        let pid_file = self.dir.join("nginx.pid");
        let mut master = String::new();
        wait_for("nginx pid file", Duration::from_secs(5), || {
            master = fs::read_to_string(&pid_file)
                .unwrap_or_default()
                .trim()
                .to_string();
            !master.is_empty()
        })?;
        let children_file = format!("/proc/{master}/task/{master}/children");
        let mut worker = 0;
        wait_for("nginx worker", Duration::from_secs(5), || {
            worker = fs::read_to_string(&children_file)
                .ok()
                .and_then(|s| s.split_whitespace().next().and_then(|p| p.parse().ok()))
                .unwrap_or(0);
            worker != 0
        })?;
        Ok(worker)
    }

    /// Nanoseconds the worker has spent on a CPU (all threads).
    pub fn worker_cpu_ns(&self) -> Result<u64> {
        let tasks =
            fs::read_dir(format!("/proc/{}/task", self.worker)).map_err(|e| e.to_string())?;
        let mut total = 0;
        for t in tasks.flatten() {
            let s = fs::read_to_string(t.path().join("schedstat")).map_err(|e| e.to_string())?;
            total += s
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
        }
        Ok(total)
    }

    /// GET a path with a plain blocking request (setup only).
    pub fn get(&self, path: &str) -> Result<String> {
        let mut s = TcpStream::connect(self.addr).map_err(|e| e.to_string())?;
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        write!(
            s,
            "GET {path} HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n"
        )
        .map_err(|e| e.to_string())?;
        let mut out = String::new();
        s.read_to_string(&mut out).map_err(|e| e.to_string())?;
        Ok(out)
    }

    /// A metric's value from repsheet_metrics (first matching line).
    pub fn metric(&self, name: &str) -> Option<f64> {
        let body = self.get("/__metrics").ok()?;
        body.lines()
            .find(|l| l.starts_with(name) && l[name.len()..].starts_with([' ', '{']))
            .and_then(|l| l.rsplit(' ').next())
            .and_then(|v| v.parse().ok())
    }

    /// Wait until the store holds at least `n` decisions.
    pub fn wait_decisions(&self, n: usize, timeout: Duration) -> Result<()> {
        wait_for(&format!("nginx to load {n} decisions"), timeout, || {
            self.metric("repsheet_decisions")
                .is_some_and(|v| v as usize >= n)
        })
    }

    pub fn error_log(&self) -> String {
        fs::read_to_string(self.dir.join("logs/error.log")).unwrap_or_default()
    }
}

impl Drop for Nginx {
    fn drop(&mut self) {
        // SIGQUIT: graceful; then make sure.
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Pin the current process (the load generator) to the given CPUs.
pub fn pin_self(cpus: &[usize]) -> Result<()> {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        for &c in cpus {
            libc::CPU_SET(c, &mut set);
        }
        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
            return Err("sched_setaffinity failed".into());
        }
    }
    Ok(())
}

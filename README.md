
<p align="center">
  <img src="https://raw.githubusercontent.com/minoansecurity/porter/main/logo.svg" alt="porter" width="220"/>
  <br/>
  <strong>porter</strong>
  <br/>
  <em>detect what services are running on your host's ports</em>
</p>

Zero-dependency Rust port scanner for Linux and macOS; library-first, thin CLI included.

---

## CLI Usage

```
cargo install porter
```

Or from source:

```
make install
```

### List

```
$ porter

porter — detect what services are running on your host's ports

PORT     PROCESS        PID      UPTIME     STATUS
3000     node           142      4m         ● active
8080     python3        198      2m         ● active
5432     postgres       201      12m        ● active
```

### Watch

```
$ porter watch
Watching for port changes... (Ctrl+C to stop)
+ 3000  node    pid:142
- 8080  python  pid:198  (was up 2m)
+ 9090  java    pid:304
```

### Kill

```
$ porter kill 3000
  ✓ Sent SIGTERM to :3000 — node (PID 142)
```

Use `-f` for SIGKILL when a process won't go quietly.

```bash
porter                        # list all listening ports
porter watch                  # stream port changes in real-time
porter kill 3000              # kill by port
porter kill 3000 5173 8080    # kill multiple
porter kill -f 3000           # force kill (SIGKILL)
```

---

## Library Usage

```toml
[dependencies]
porter = "<version>"
```

### Scan

```rust
use porter::scan;

for p in scan().unwrap() {
    println!("port {}: {} (pid {})", p.port, p.process, p.pid);
}
```

### Watch

React to ports opening and closing in real time. The closure receives a typed `PortChange`; match on it to get the `PortInfo` with `port`, `pid`, `process`, and `uptime_secs` as fields:

```rust
use porter::{PortChange, watch};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

let stop = Arc::new(AtomicBool::new(false));
watch(Duration::from_secs(1), stop, |change| {
    match change {
        PortChange::Opened(p) => println!("new service on port {}: {} (pid {})", p.port, p.process, p.pid),
        PortChange::Closed(p) => println!("port {} closed (was {})", p.port, p.process),
    }
}).unwrap();
```

### Kill

```rust
use porter::{scan, kill_pid};

let ports = scan().unwrap();
if let Some(p) = ports.iter().find(|p| p.port == 3000) {
    kill_pid(p.pid, false); // SIGTERM
}
```

### Diff

Compare two scan snapshots:

```rust
use porter::{PortChange, scan, diff};

let before = scan().unwrap();
// ... time passes ...
let after = scan().unwrap();

for change in diff(&before, &after) {
    match change {
        PortChange::Opened(p) => println!("new service on port {}: {} (pid {})", p.port, p.process, p.pid),
        PortChange::Closed(p) => println!("port {} closed (was {})", p.port, p.process),
    }
}
```

---

## How it works

| Platform | Method |
|----------|--------|
| Linux | Reads `/proc/net/tcp`, `/proc/net/tcp6`, and `/proc/<pid>/fd` |
| macOS | Shells out to `lsof` and `ps` |

## Credits

Inspired by [port-whisperer](https://github.com/LarsenCundric/port-whisperer), but rebuilt as an embeddable Rust library.

## License

Apache-2.0

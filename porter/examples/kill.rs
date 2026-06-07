use porter::{scan, kill_pid};

fn main() {
    let ports = scan().unwrap();
    if let Some(p) = ports.iter().find(|p| p.port == 3000) {
        if kill_pid(p.pid, false) {
            println!("killed {} (pid {}) on port {}", p.process, p.pid, p.port);
        } else {
            println!("failed to kill pid {}", p.pid);
        }
    } else {
        println!("nothing on port 3000");
    }
}

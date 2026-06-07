use porter::{PortChange, scan, diff};

fn main() {
    let before = scan().unwrap();
    println!("snapshot taken, waiting 3 seconds...");
    std::thread::sleep(std::time::Duration::from_secs(3));
    let after = scan().unwrap();

    for change in diff(&before, &after) {
        match change {
            PortChange::Opened(p) => println!("new service on port {}: {} (pid {})", p.port, p.process, p.pid),
            PortChange::Closed(p) => println!("port {} closed (was {})", p.port, p.process),
        }
    }
}

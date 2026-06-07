use porter::{PortChange, watch};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

fn main() {
    let stop = Arc::new(AtomicBool::new(false));
    watch(Duration::from_secs(1), stop, |change| {
        match change {
            PortChange::Opened(p) => println!("new service on port {}: {} (pid {})", p.port, p.process, p.pid),
            PortChange::Closed(p) => println!("port {} closed (was {})", p.port, p.process),
        }
    }).unwrap();
}

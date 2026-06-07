use porter::{PortChange, format_uptime, sanitize, watch};
use crate::{is_unprivileged, GREEN, RED, YELLOW, DIM, RESET};

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

pub fn run() {
    if is_unprivileged() {
        eprintln!("{YELLOW}⚠ Running without root — some ports may be hidden. Use sudo porter for full visibility.{RESET}");
    }

    println!("{DIM}Watching for port changes... (Ctrl+C to stop){RESET}");

    // Ctrl+C already kills the process — the stop flag is for library consumers.
    // For the CLI we just let it run until interrupted.
    let stop = Arc::new(AtomicBool::new(false));

    if let Err(e) = watch(std::time::Duration::from_secs(2), stop, |change| {
        match change {
            PortChange::Opened(p) => println!(
                "{GREEN}+{RESET} {}  {}  pid:{}", p.port, sanitize(&p.process), p.pid,
            ),
            PortChange::Closed(p) => println!(
                "{RED}-{RESET} {}  {}  pid:{}  {DIM}(was up {}){RESET}",
                p.port, sanitize(&p.process), p.pid, format_uptime(p.uptime_secs),
            ),
        }
    }) {
        eprintln!("{RED}✕ {e}{RESET}");
        std::process::exit(1);
    }
}

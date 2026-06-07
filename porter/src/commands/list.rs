use porter::{format_uptime, sanitize, scan};
use crate::{is_unprivileged, GREEN, RED, YELLOW, DIM, BOLD, RESET};

pub fn run() {
    println!("{BOLD}harry porter{RESET} {DIM}— detect what services are running on your host's ports{RESET}\n");

    let ports = match scan() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{RED}✕ {e}{RESET}");
            std::process::exit(1);
        }
    };

    if ports.is_empty() {
        println!("{DIM}No listening ports found.{RESET}");
    } else {
        println!("{BOLD}{:<8} {:<24} {:<8} {:<10} STATUS{RESET}", "PORT", "PROCESS", "PID", "UPTIME");
        for p in &ports {
            println!("{:<8} {:<24} {:<8} {:<10} {GREEN}●{RESET} active",
                p.port, sanitize(&p.process), p.pid, format_uptime(p.uptime_secs));
        }
    }

    if is_unprivileged() {
        eprintln!("{YELLOW}⚠ Running without root — some ports may be hidden. Use sudo porter for full visibility.{RESET}");
    }
}

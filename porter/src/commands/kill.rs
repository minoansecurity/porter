use porter::{kill_pid, sanitize, scan};
use crate::{GREEN, RED, RESET};

pub fn run(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: porter kill [-f] <port> [port ...]");
        std::process::exit(1);
    }

    let force = args.iter().any(|a| a == "-f" || a == "--force");
    let signal_name = if force { "SIGKILL" } else { "SIGTERM" };

    let ports = match scan() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("  {RED}✕ {e}{RESET}");
            std::process::exit(1);
        }
    };

    let mut failed = false;

    for arg in args.iter().filter(|a| *a != "-f" && *a != "--force") {
        let Ok(port) = arg.parse::<u16>() else {
            eprintln!("  {RED}✕ \"{arg}\" is not a valid port number{RESET}");
            failed = true;
            continue;
        };

        let Some(target) = ports.iter().find(|p| p.port == port) else {
            eprintln!("  {RED}✕ No listener on :{port}{RESET}");
            failed = true;
            continue;
        };

        if kill_pid(target.pid, force) {
            println!("  {GREEN}✓ Sent {signal_name} to :{} — {} (PID {}){RESET}",
                target.port, sanitize(&target.process), target.pid);
        } else {
            eprintln!("  {RED}✕ Failed to kill :{} — {} (PID {}){RESET}",
                target.port, sanitize(&target.process), target.pid);
            failed = true;
        }
    }

    println!();
    if failed { std::process::exit(1); }
}

// macOS-specific port scanning implementation.
// Uses `lsof` to discover listening TCP sockets and `ps` for process uptimes.

use super::{PortInfo, ScanError};
use std::collections::HashMap;
use std::process::Command;

/// Scan all listening TCP ports on macOS using lsof.
/// Returns a PortInfo for each listening socket found.
pub fn scan_ports() -> Result<Vec<PortInfo>, ScanError> {
    // lsof flags:
    //   -iTCP         → only TCP sockets
    //   -sTCP:LISTEN  → only in LISTEN state
    //   -n            → no DNS resolution
    //   -P            → no port name resolution (show numbers)
    //   -F pcn        → machine-readable output: p=PID, c=command, n=name
    let out = Command::new("lsof")
        .args(["-iTCP", "-sTCP:LISTEN", "-n", "-P", "-F", "pcn"])
        .output()
        .map_err(|e| ScanError::Unavailable(format!("lsof: {e}")))?;

    let mut entries = Vec::new();
    let mut pid = 0u32;
    let mut process = String::new();

    // Parse lsof's field-based output format.
    // Each line starts with a single-char tag: 'p' for PID, 'c' for command, 'n' for name.
    // So its a state machine, emit all ports for each pid/process!
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Some((&tag, _)) = line.as_bytes().split_first() else {
            continue;
        };
        let val = &line[1..];

        match tag {
            // 'p' line: new process section, update current PID
            b'p' => {
                pid = val.parse().unwrap_or(0);
                process.clear();
            }

            // 'c' line: command/process name for the current PID
            b'c' => process = val.to_string(),
            
            // 'n' line: network name like "*:8080" or "127.0.0.1:3000"
            // Extract the port number after the last colon
            b'n' => {
                if let Some(port) = val.rsplit(':').next().and_then(|s| s.parse().ok()) {
                    entries.push((pid, process.clone(), port));
                }
            }
            _ => {}
        }
    }

    // Get uptimes for all discovered PIDs in one ps call
    let pids: Vec<u32> = entries.iter().map(|(pid, _, _)| *pid).collect();
    let uptimes = get_uptimes(&pids);

    let ports = entries
        .into_iter()
        .map(|(pid, process, port)| PortInfo {
            port,
            pid,
            process,
            uptime_secs: uptimes.get(&pid).copied().unwrap_or(0),
        })
        .collect();

    Ok(ports)
}

/// Run `ps -o pid=,etime=` for the given PIDs and return a map of PID → uptime in seconds.
/// Output looks like:
///   " 2766 01-07:55:09"
///   "97895 35-01:42:15"
fn get_uptimes(pids: &[u32]) -> HashMap<u32, u64> {
    if pids.is_empty() {
        return HashMap::new();
    }

    let pid_args: Vec<_> = pids.iter().map(|p| p.to_string()).collect();
    let Ok(out) = Command::new("ps")
        .args(["-o", "pid=,etime=", "-p"])
        .args(&pid_args)
        .output()
    else {
        return HashMap::new();
    };

    let mut map = HashMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let line = line.trim();
        if let Some((pid_str, etime)) = line.split_once(char::is_whitespace) {
            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                map.insert(pid, parse_etime(etime.trim()));
            }
        }
    }
    map
}

/// Parse a `ps` elapsed time string into total seconds.
/// Formats: "SS", "MM:SS", "HH:MM:SS", "D-HH:MM:SS"
fn parse_etime(s: &str) -> u64 {
    // Split off days if present (format: "D-HH:MM:SS")
    let (days, rest) = s
        .split_once('-')
        .map_or((0, s), |(d, r)| (d.parse().unwrap_or(0), r));

    // Split remaining by colon into time components
    let parts: Vec<u64> = rest.split(':').filter_map(|x| x.parse().ok()).collect();

    match parts.as_slice() {
        [h, m, s] => days * 86400 + h * 3600 + m * 60 + s,
        [m, s] => days * 86400 + m * 60 + s,
        _ => 0,
    }
}

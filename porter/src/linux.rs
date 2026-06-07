// Linux-specific port scanning implementation.
// Reads /proc/net/tcp{,6} to find listening sockets, then maps inodes
// back to processes via /proc/<pid>/fd/ symlinks.

use super::{PortInfo, ScanError};
use std::collections::HashMap;
use std::fs;

/// Scan all listening TCP ports on Linux by reading /proc.
/// No external commands needed — everything comes from the proc filesystem.
pub fn scan_ports() -> Result<Vec<PortInfo>, ScanError> {
    // At least one of tcp/tcp6 must be readable
    let tcp4 = fs::read_to_string("/proc/net/tcp");
    let tcp6 = fs::read_to_string("/proc/net/tcp6");

    if tcp4.is_err() && tcp6.is_err() {
        return Err(ScanError::Unavailable("/proc/net/tcp not readable".into()));
    }

    // Build a map of socket inode → (pid, process_name)
    let inode_map = build_inode_map();
    // Get system boot time for calculating process uptime
    let btime = boot_time();
    let mut ports = Vec::new();

    // Parse both IPv4 and IPv6 TCP socket tables
    for tcp in [&tcp4, &tcp6] {
        let Ok(tcp) = tcp else {
            continue;
        };

        // Skip the header line, then parse each socket entry
        for line in tcp.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();

            // Column 3 is the socket state; "0A" = TCP_LISTEN
            if cols.len() < 10 || cols[3] != "0A" {
                continue;
            }

            // Column 1 is "local_address:port" in hex (e.g. "0100007F:1F90")
            // Extract the port number from after the last colon
            let Some(port) = cols[1]
                .rsplit_once(':')
                .and_then(|(_, h)| u16::from_str_radix(h, 16).ok())
            else {
                continue;
            };

            // Column 9 is the socket's inode number
            let Ok(inode) = cols[9].parse::<u64>() else {
                continue;
            };

            // Look up which process owns this socket inode
            let (pid, process, uptime) = inode_map
                .get(&inode)
                .map(|(pid, name)| (*pid, name.clone(), process_uptime(*pid, btime)))
                .unwrap_or((0, "unknown".into(), 0));

            ports.push(PortInfo {
                port,
                pid,
                process,
                uptime_secs: uptime,
            });
        }
    }

    Ok(ports)
}

/// Build a mapping from socket inode numbers to (pid, process_name).
/// Scans /proc/<pid>/fd/ for each process, looking for socket symlinks.
fn build_inode_map() -> HashMap<u64, (u32, String)> {
    let mut map = HashMap::new();

    let Ok(procs) = fs::read_dir("/proc") else {
        return map;
    };

    for entry in procs.flatten() {
        // Only process numeric directory names (those are PIDs)
        let name = entry.file_name();
        let Ok(pid) = name.to_str().unwrap_or_default().parse::<u32>() else {
            continue;
        };

        // Read all file descriptors for this process
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };

        // Lazily resolve the process name only when we find a socket
        let mut pname: Option<String> = None;

        for fd in fds.flatten() {
            // Each fd is a symlink; socket fds look like "socket:[12345]"
            let Ok(link) = fs::read_link(fd.path()) else {
                continue;
            };

            let link_str = link.to_string_lossy();

            // Extract the inode number from "socket:[<inode>]"
            let Some(inode) = link_str
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse::<u64>().ok())
            else {
                continue;
            };

            // Resolve process name on first socket hit (avoids unnecessary reads)
            let process_name = pname.get_or_insert_with(|| read_process_name(pid));
            map.insert(inode, (pid, process_name.clone()));
        }
    }

    map
}

/// Read system boot time from /proc/stat (the "btime" line).
/// Returns seconds since Unix epoch when the system booted.
fn boot_time() -> u64 {
    let Ok(stat) = fs::read_to_string("/proc/stat") else {
        return 0;
    };

    stat.lines()
        .find(|l| l.starts_with("btime "))
        .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        .unwrap_or(0)
}

/// Calculate how long a process has been running, in seconds.
/// Uses /proc/<pid>/stat field 22 (starttime, in clock ticks since boot).
fn process_uptime(pid: u32, btime: u64) -> u64 {
    
    // Probably redundant in practice, but check that the boottime has passed correctly
    if btime == 0 {
        return 0;
    }

    // Prevent TOCTOU if the process has died
    let Ok(pstat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return 0;
    };

    // The comm field (field 2) can contain spaces and parens, so we find
    // the LAST closing paren to skip past it reliably
    let Some(i) = pstat.rfind(')') else {
        return 0;
    };

    // After the closing paren, fields are space-separated.
    // Field 22 (starttime) is at offset 19 from the first field after ')'.
    let starttime: u64 = pstat[i + 2..]
        .split_whitespace()
        .nth(19)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Convert clock ticks to seconds (USER_HZ is always 100 in the Linux kernel ABI)
    let starttime = starttime / 100;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    now.saturating_sub(btime + starttime)
}

/// Read the process name for a PID.
/// Tries /proc/<pid>/cmdline first (argv[0]), falls back to /proc/<pid>/comm.
fn read_process_name(pid: u32) -> String {
    // cmdline contains null-separated args; take the first one (the binary path)
    let name = fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .and_then(|bytes| {
            // Find the first null byte (end of argv[0])
            let end = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
            String::from_utf8(bytes[..end].to_vec()).ok()
        })
        .map(|s| {
            // Strip the path, keep only the binary name
            s.rsplit('/')
                .next()
                .unwrap_or(&s)
                .to_string()
        })
        .unwrap_or_default();

    // Fall back to /proc/<pid>/comm if cmdline was empty (e.g. kernel threads)
    if name.is_empty() {
        fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".into())
    } else {
        name
    }
}

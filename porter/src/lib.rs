#![forbid(unsafe_code)]

//! A library-first, zero-dependency port scanner for Linux and macOS.
//!
//! Scan listening TCP ports, diff snapshots, watch for changes, or kill
//! processes by port — all from Rust code. A CLI is included, but the
//! library API is the primary interface.

use std::collections::HashMap;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// --- Types ---

/// Information about a single listening TCP port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortInfo {
    pub port: u16,
    pub pid: u32,
    pub process: String,
    pub uptime_secs: u64,
}

impl std::fmt::Display for PortInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, ":{} {} (pid {}, up {})", self.port, self.process, self.pid, format_uptime(self.uptime_secs))
    }
}

/// A change detected between two port scans.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortChange {
    Opened(PortInfo),
    Closed(PortInfo),
}

impl std::fmt::Display for PortChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortChange::Opened(p) => write!(f, "+ {p}"),
            PortChange::Closed(p) => write!(f, "- {p}"),
        }
    }
}

/// Why a scan failed.
#[derive(Clone, Debug)]
pub enum ScanError {
    /// /proc not readable (Linux) or lsof not available (macOS)
    Unavailable(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::Unavailable(msg) => write!(f, "scan failed: {msg}"),
        }
    }
}

impl std::error::Error for ScanError {}

// --- Platform-specific scanning ---

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::scan_ports;

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "macos")]
use darwin::scan_ports;

// --- Public API ---

/// Scan all listening TCP ports on the system.
/// Deduplicates by port number (first entry wins) and returns sorted by port.
/// Returns an error if the scan mechanism is unavailable.
#[must_use]
pub fn scan() -> Result<Vec<PortInfo>, ScanError> {
    let raw = scan_ports()?;
    let mut by_port = HashMap::new();

    for entry in raw {
        by_port.entry(entry.port).or_insert(entry);
    }

    let mut ports: Vec<_> = by_port.into_values().collect();
    ports.sort_by_key(|entry| entry.port);
    Ok(ports)
}

/// Compare two scan results and return what changed (opened/closed ports).
#[must_use]
pub fn diff(prev: &[PortInfo], curr: &[PortInfo]) -> Vec<PortChange> {
    let prev_map: HashMap<u16, &PortInfo> = prev.iter().map(|p| (p.port, p)).collect();
    let curr_map: HashMap<u16, &PortInfo> = curr.iter().map(|p| (p.port, p)).collect();

    let opened = curr_map
        .iter()
        .filter(|(port, _)| !prev_map.contains_key(port))
        .map(|(_, &info)| PortChange::Opened(info.clone()));

    let closed = prev_map
        .iter()
        .filter(|(port, _)| !curr_map.contains_key(port))
        .map(|(_, &info)| PortChange::Closed(info.clone()));

    opened.chain(closed).collect()
}

/// Send a signal to a process by PID. Returns true if successful.
/// Refuses to signal PID 0, 1, or values above i32::MAX for safety.
#[must_use]
pub fn kill_pid(pid: u32, force: bool) -> bool {
    if pid <= 1 || pid > i32::MAX as u32 {
        return false;
    }
    let signal = if force { "-9" } else { "-15" };
    Command::new("kill")
        .args([signal, &pid.to_string()])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Poll for port changes and call the handler on each open/close.
/// Set `stop` to true to exit the loop. Returns the error if a scan fails.
/// Use `std::thread::spawn` if you need it non-blocking.
pub fn watch(
    interval: std::time::Duration,
    stop: Arc<AtomicBool>,
    mut on_change: impl FnMut(PortChange),
) -> Result<(), ScanError> {
    let mut prev = scan()?;
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(interval);
        if stop.load(Ordering::Relaxed) { break; }
        let curr = scan()?;
        for change in diff(&prev, &curr) {
            on_change(change);
        }
        prev = curr;
    }
    Ok(())
}

/// Replace non-printable characters with '?' to prevent terminal escape injection.
/// Allows ASCII graphic characters and spaces only. Not safe for shell arguments.
#[must_use]
pub fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' }).collect()
}

/// Format seconds into a short human-readable duration.
#[must_use]
pub fn format_uptime(seconds: u64) -> String {
    match seconds {
        0..60 => format!("{seconds}s"),
        60..3600 => format!("{}m", seconds / 60),
        3600..86400 => format!("{}h", seconds / 3600),
        _ => format!("{}d", seconds / 86400),
    }
}

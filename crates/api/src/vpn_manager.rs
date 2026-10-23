//! OpenVPN tunnel manager.
//!
//! Manages `openvpn --config <file> --daemon` processes for VPN profiles.
//! Graceful degradation: if the openvpn binary is missing (or the sandbox
//! lacks tun-device permissions), connect returns a clear error and the
//! profile status becomes `error` — nothing crashes.
//!
//! Process tracking: the profile row stores the OS pid; status queries check
//! whether the pid is still alive to detect silent tunnel death.

use secuscan_db::repo;
use secuscan_db::models::VpnProfileRow;
use sqlx::SqlitePool;
use std::path::PathBuf;

const OPENVPN_BIN: &str = "openvpn";

/// Is the openvpn binary available on PATH?
pub fn openvpn_available() -> bool {
    which(OPENVPN_BIN).is_some()
}

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var("PATH").ok()?;
    for dir in path.split(':') {
        let p = PathBuf::from(dir).join(bin);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Is the given pid still alive?
pub fn pid_alive(pid: i64) -> bool {
    // /proc/<pid> exists only for live processes on Linux.
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// Connect a VPN profile. Writes the config to a temp file, spawns openvpn
/// in daemon mode, and waits briefly for the tun interface to appear.
pub async fn connect(db: &SqlitePool, profile: &VpnProfileRow) -> Result<String, String> {
    if !openvpn_available() {
        let err = "openvpn binary not found on PATH — install openvpn to use VPN profiles";
        let _ = repo::vpn::update_status(db, &profile.id, "error", Some(err), None, None).await;
        return Err(err.into());
    }
    if profile.status == "connected" {
        if let Some(pid) = profile.process_id {
            if pid_alive(pid) {
                return Ok(profile.interface.clone().unwrap_or_else(|| "tun0".into()));
            }
            // Stale connected state — fall through and reconnect.
        }
    }

    let _ = repo::vpn::update_status(db, &profile.id, "connecting", None, None, None).await;

    // Write config to a private temp file.
    let dir = std::env::temp_dir().join("secuscan-vpn");
    let _ = std::fs::create_dir_all(&dir);
    let cfg_path = dir.join(format!("{}.ovpn", profile.id));
    std::fs::write(&cfg_path, &profile.config_text)
        .map_err(|e| format!("write config: {e}"))?;

    // Spawn openvpn daemon.
    let child = std::process::Command::new(OPENVPN_BIN)
        .arg("--config")
        .arg(&cfg_path)
        .arg("--daemon")
        .arg(format!("secuscan-vpn-{}", &profile.id[..8.min(profile.id.len())]))
        .arg("--log")
        .arg(dir.join(format!("{}.log", profile.id)))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    let child = match child {
        Ok(c) => c,
        Err(e) => {
            let err = format!("spawn openvpn: {e}");
            let _ = repo::vpn::update_status(db, &profile.id, "error", Some(&err), None, None).await;
            return Err(err);
        }
    };
    let pid = child.id() as i64;

    // Wait up to 20s for the tun interface.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        if std::time::Instant::now() >= deadline {
            let err = "openvpn did not establish a tunnel within 20s — check the profile log";
            let _ = repo::vpn::update_status(db, &profile.id, "error", Some(err), Some(pid), None).await;
            return Err(err.into());
        }
        // Detect immediate death (bad config, missing certs, no tun perms).
        if !pid_alive(pid) {
            let log = std::fs::read_to_string(dir.join(format!("{}.log", profile.id)))
                .unwrap_or_default();
            let tail: String = {
                let lines: Vec<&str> = log.lines().collect();
                let start = lines.len().saturating_sub(5);
                lines[start..].join("\n")
            };
            let err = format!("openvpn exited during startup: {tail}");
            let _ = repo::vpn::update_status(db, &profile.id, "error", Some(&err), Some(pid), None).await;
            return Err(err);
        }
        if let Some(iface) = detect_tun_iface() {
            repo::vpn::update_status(db, &profile.id, "connected", None, Some(pid), Some(&iface))
                .await
                .map_err(|e| e.to_string())?;
            return Ok(iface);
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// Disconnect a VPN profile by killing its daemon process.
pub async fn disconnect(db: &SqlitePool, profile: &VpnProfileRow) -> Result<(), String> {
    if let Some(pid) = profile.process_id {
        if pid_alive(pid) {
            // Best-effort SIGTERM via the kill syscall.
            unsafe {
                // libc isn't a direct dependency; use the std trick of
                // spawning `kill`. This keeps the crate dependency-light.
                let _ = std::process::Command::new("kill")
                    .arg(pid.to_string())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
        }
    }
    repo::vpn::update_status(db, &profile.id, "disconnected", None, None, None)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Detect the first tun/tap interface created by openvpn.
fn detect_tun_iface() -> Option<String> {
    for entry in std::fs::read_dir("/sys/class/net").ok()? {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("tun") || name.starts_with("tap") {
            return Some(name);
        }
    }
    None
}

/// Reconcile statuses at startup: profiles marked connected but whose pid
/// is dead flip to error.
pub async fn reconcile(db: &SqlitePool) {
    let Ok(profiles) = repo::vpn::list(db).await else { return };
    for p in profiles {
        if p.status == "connected" {
            let alive = p.process_id.map(pid_alive).unwrap_or(false);
            if !alive {
                let _ = repo::vpn::update_status(
                    db, &p.id, "error",
                    Some("tunnel process died while the server was down"),
                    None, None,
                ).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn which_finds_system_binary() {
        // `sh` exists everywhere.
        assert!(which("sh").is_some());
        assert!(which("definitely-not-a-real-binary-xyz").is_none());
    }

    #[test]
    fn pid_alive_rejects_bogus_pid() {
        assert!(!pid_alive(4_000_000_000));
        // Our own pid is alive.
        assert!(pid_alive(std::process::id() as i64));
    }

    #[test]
    fn openvpn_available_is_bool() {
        // Just exercise it; the sandbox may or may not have openvpn.
        let _ = openvpn_available();
    }
}

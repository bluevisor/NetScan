use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct BannerResult {
    pub ip: IpAddr,
    pub port: u16,
    pub banner: String,
    pub version: Option<String>,
}

/// Grab banners from open ports on a host
pub async fn grab_banners(
    ip: IpAddr,
    ports: &[u16],
    tx: mpsc::Sender<BannerResult>,
) {
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(10));

    let mut handles = Vec::new();
    for &port in ports {
        let tx = tx.clone();
        let sem = semaphore.clone();
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            if let Some(result) = grab_single_banner(ip, port).await {
                let _ = tx.send(result).await;
            }
        });
        handles.push(handle);
    }

    for h in handles {
        let _ = h.await;
    }
}

async fn grab_single_banner(ip: IpAddr, port: u16) -> Option<BannerResult> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(
        Duration::from_secs(3),
        TcpStream::connect(&addr),
    ).await.ok()?.ok()?;

    // Some services send a banner immediately, others need a probe
    let probe = match port {
        80 | 8080 | 8000 | 8443 | 443 => {
            Some(format!("HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n", ip).into_bytes())
        }
        _ => None,
    };

    if let Some(probe_data) = probe {
        let _ = stream.write_all(&probe_data).await;
    }

    let mut buf = vec![0u8; 1024];
    let banner = match tokio::time::timeout(
        Duration::from_secs(3),
        stream.read(&mut buf),
    ).await {
        Ok(Ok(n)) if n > 0 => {
            // Clean up: take first line or first 256 bytes, strip non-printable
            let raw = String::from_utf8_lossy(&buf[..n]);
            let first_line = raw.lines().next().unwrap_or("").to_string();
            if first_line.is_empty() {
                return None;
            }
            first_line.chars().take(256).collect::<String>()
        }
        _ => return None,
    };

    let version = extract_version(&banner);

    Some(BannerResult {
        ip,
        port,
        banner,
        version,
    })
}

// ── SSH banner classification ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SshClassification {
    pub os_hint: Option<String>,
    pub device_hint: Option<String>,
}

/// Classify an SSH banner string into OS and device hints.
pub fn classify_ssh_banner(banner: &str) -> Option<SshClassification> {
    if !banner.starts_with("SSH-") {
        return None;
    }

    let mut os_hint: Option<String> = None;
    let mut device_hint: Option<String> = None;

    let lower = banner.to_lowercase();

    if lower.contains("dropbear") {
        device_hint = Some("embedded device (router/IoT)".to_string());
    } else if lower.contains("cisco") {
        device_hint = Some("network equipment (Cisco)".to_string());
    } else if lower.contains("rosssh") {
        device_hint = Some("MikroTik router".to_string());
    } else if lower.contains("lancom") {
        device_hint = Some("LANCOM router".to_string());
    } else if lower.contains("libssh") {
        device_hint = Some("IoT/embedded (libssh)".to_string());
    } else if lower.contains("openssh") {
        // Try to extract version number to correlate with OS
        if let Some(version_str) = extract_openssh_version(banner) {
            os_hint = Some(correlate_openssh_version(&version_str));
        }
    }

    if os_hint.is_none() && device_hint.is_none() {
        return None;
    }

    Some(SshClassification { os_hint, device_hint })
}

fn extract_openssh_version(banner: &str) -> Option<String> {
    // Banner format: SSH-2.0-OpenSSH_X.Y[pZ] [platform]
    // Find "OpenSSH_" and take the version token
    let idx = banner.to_lowercase().find("openssh_")?;
    let rest = &banner[idx + 8..];
    let end = rest.find(|c: char| c == ' ' || c == '\r' || c == '\n').unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

fn correlate_openssh_version(version: &str) -> String {
    // Extract major.minor
    let parts: Vec<&str> = version.split('p').next().unwrap_or(version).split('.').collect();
    let major: u32 = parts.get(0).and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    match (major, minor) {
        (9, m) if m >= 6 => "recent Linux or macOS (OpenSSH 9.6+)".to_string(),
        (9, _) => "Linux or macOS (OpenSSH 9.x)".to_string(),
        (8, _) => "Linux or macOS (OpenSSH 8.x)".to_string(),
        (7, _) => "Linux (OpenSSH 7.x) or older macOS".to_string(),
        _ => format!("Linux/Unix (OpenSSH {})", version),
    }
}

// ── Version extraction ───────────────────────────────────────────────────────

/// Try to extract version info from a banner string
fn extract_version(banner: &str) -> Option<String> {
    // Simple extraction without regex: look for version-like patterns
    if banner.starts_with("SSH-") {
        return Some(banner.trim().to_string());
    }

    // HTTP Server header
    if banner.contains("Server:") {
        if let Some(pos) = banner.find("Server:") {
            let server = banner[pos + 7..].trim();
            let end = server.find('\r').unwrap_or(server.len());
            return Some(server[..end].to_string());
        }
    }

    // FTP banner
    if banner.starts_with("220") {
        return Some(banner[4..].trim().to_string());
    }

    None
}

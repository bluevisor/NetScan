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

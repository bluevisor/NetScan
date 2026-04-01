use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct OsFpResult {
    pub ip: IpAddr,
    pub ttl: Option<u8>,
    pub os_guess: Option<String>,
    pub confidence: f32,
}

/// Guess OS based on TTL from a TCP connection
/// This is a simplified approach — full OS fingerprinting (like nmap) requires raw sockets
pub async fn fingerprint_os(ip: IpAddr, open_port: u16) -> Option<OsFpResult> {
    let addr = SocketAddr::new(ip, open_port);
    let stream = tokio::time::timeout(
        Duration::from_secs(3),
        TcpStream::connect(&addr),
    ).await.ok()?.ok()?;

    // Get TTL from the socket (platform-specific)
    let ttl = get_ttl(&stream);

    let os_guess = ttl.map(|t| guess_os_from_ttl(t));
    let confidence = if ttl.is_some() { 0.4 } else { 0.0 };

    Some(OsFpResult {
        ip,
        ttl,
        os_guess,
        confidence,
    })
}

fn get_ttl(stream: &TcpStream) -> Option<u8> {
    // Use the socket2 crate to read TTL
    let std_stream = stream.as_ref();
    use std::os::fd::AsRawFd;
    let fd = std_stream.as_raw_fd();
    let socket = unsafe { socket2::Socket::from_raw_fd(fd) };
    let ttl = socket.ttl().ok().map(|t| t as u8);
    // Don't let socket2 close our fd
    std::mem::forget(socket);
    ttl
}

use std::os::fd::FromRawFd;

fn guess_os_from_ttl(ttl: u8) -> String {
    // Initial TTL values:
    // Linux: 64, Windows: 128, macOS/iOS: 64, Cisco: 255, Solaris: 255
    // TTL decreases by 1 per hop, so we look at the nearest power
    if ttl <= 64 && ttl > 32 {
        "Linux/macOS/iOS (TTL~64)".to_string()
    } else if ttl <= 128 && ttl > 64 {
        "Windows (TTL~128)".to_string()
    } else if ttl > 128 {
        "Cisco/Solaris (TTL~255)".to_string()
    } else {
        format!("Unknown (TTL={})", ttl)
    }
}

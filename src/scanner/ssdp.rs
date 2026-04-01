use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const SSDP_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;

#[derive(Debug, Clone)]
pub struct SsdpResult {
    pub ip: IpAddr,
    pub server: Option<String>,
    pub location: Option<String>,
    pub service_type: Option<String>,
    pub usn: Option<String>,
}

pub async fn ssdp_discover(tx: mpsc::Sender<SsdpResult>) {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return,
    };

    let msearch = format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: 239.255.255.250:1900\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: 3\r\n\
         ST: ssdp:all\r\n\
         \r\n"
    );

    let dest = SocketAddr::new(IpAddr::V4(SSDP_ADDR), SSDP_PORT);
    let _ = socket.send_to(msearch.as_bytes(), dest).await;

    let mut buf = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);

    loop {
        match tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, src))) => {
                if let Ok(response) = std::str::from_utf8(&buf[..len]) {
                    let result = parse_ssdp_response(response, src.ip());
                    let _ = tx.send(result).await;
                }
            }
            _ => break,
        }
    }
}

fn parse_ssdp_response(response: &str, ip: IpAddr) -> SsdpResult {
    let mut result = SsdpResult {
        ip,
        server: None,
        location: None,
        service_type: None,
        usn: None,
    };

    for line in response.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("server:") {
            result.server = Some(line[7..].trim().to_string());
        } else if lower.starts_with("location:") {
            result.location = Some(line[9..].trim().to_string());
        } else if lower.starts_with("st:") {
            result.service_type = Some(line[3..].trim().to_string());
        } else if lower.starts_with("usn:") {
            result.usn = Some(line[4..].trim().to_string());
        }
    }

    result
}

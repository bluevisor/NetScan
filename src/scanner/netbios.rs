use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const NETBIOS_PORT: u16 = 137;

#[derive(Debug, Clone)]
pub struct NetBiosResult {
    pub ip: IpAddr,
    pub name: String,
    pub group: Option<String>,
}

pub async fn netbios_query(
    targets: &[Ipv4Addr],
    tx: mpsc::Sender<NetBiosResult>,
) {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return,
    };

    // NetBIOS Name Query packet (NBSTAT)
    let query = build_nbstat_query();

    for &target in targets {
        let dest = SocketAddr::new(IpAddr::V4(target), NETBIOS_PORT);
        let _ = socket.send_to(&query, dest).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let mut buf = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);

    loop {
        match tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, src))) => {
                if let Some(result) = parse_nbstat_response(&buf[..len], src.ip()) {
                    let _ = tx.send(result).await;
                }
            }
            _ => break,
        }
    }
}

fn build_nbstat_query() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(50);
    // Transaction ID
    pkt.extend_from_slice(&[0x00, 0x01]);
    // Flags: NBSTAT query
    pkt.extend_from_slice(&[0x00, 0x00]);
    // QDCOUNT=1
    pkt.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT, NSCOUNT, ARCOUNT = 0
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Encode wildcard name "*" (CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
    pkt.push(0x20); // length 32
    // First-level encoding of "*\0\0..."  (16 bytes padded with spaces)
    let name_bytes = b"*               "; // 16 chars
    for &b in &name_bytes[..16] {
        pkt.push(((b >> 4) & 0x0F) + b'A');
        pkt.push((b & 0x0F) + b'A');
    }
    pkt.push(0x00); // root
    // QTYPE = NBSTAT (0x0021)
    pkt.extend_from_slice(&[0x00, 0x21]);
    // QCLASS = IN
    pkt.extend_from_slice(&[0x00, 0x01]);
    pkt
}

fn parse_nbstat_response(data: &[u8], ip: IpAddr) -> Option<NetBiosResult> {
    // Minimal parsing: skip header (12 bytes) + query name
    if data.len() < 57 {
        return None;
    }

    // Find the NBSTAT response data
    // Skip header (12) + name (34) + type (2) + class (2) + ttl (4) + rdlength (2) = 56
    let mut offset = 12;
    // Skip the name
    while offset < data.len() && data[offset] != 0 {
        let len = data[offset] as usize;
        offset += 1 + len;
    }
    offset += 1; // null terminator
    offset += 10; // type(2) + class(2) + ttl(4) + rdlength(2)

    if offset >= data.len() {
        return None;
    }

    let num_names = data[offset] as usize;
    offset += 1;

    let mut computer_name = None;
    let mut group_name = None;

    for _ in 0..num_names {
        if offset + 18 > data.len() {
            break;
        }
        // Name is 15 bytes padded with spaces, plus 1 byte suffix
        let name_raw = &data[offset..offset + 15];
        let suffix = data[offset + 15];
        let flags = u16::from_be_bytes([data[offset + 16], data[offset + 17]]);

        let name = std::str::from_utf8(name_raw)
            .unwrap_or("")
            .trim()
            .to_string();

        let is_group = flags & 0x8000 != 0;

        if suffix == 0x00 {
            if is_group {
                if group_name.is_none() {
                    group_name = Some(name);
                }
            } else if computer_name.is_none() {
                computer_name = Some(name);
            }
        }

        offset += 18;
    }

    computer_name.map(|name| NetBiosResult {
        ip,
        name,
        group: group_name,
    })
}

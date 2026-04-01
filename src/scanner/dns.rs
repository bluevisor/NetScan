use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct DnsResult {
    pub ip: IpAddr,
    pub hostname: String,
}

pub async fn reverse_dns_lookup(
    targets: &[Ipv4Addr],
    dns_server: Ipv4Addr,
    tx: mpsc::Sender<DnsResult>,
) {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return,
    };

    let dest = SocketAddr::new(IpAddr::V4(dns_server), 53);

    // Send PTR queries for each target
    for (i, &target) in targets.iter().enumerate() {
        let txid = (i as u16).wrapping_add(0x1000);
        let query = build_ptr_query(txid, target);
        let _ = socket.send_to(&query, dest).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let mut buf = [0u8; 512];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);

    loop {
        match tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _src))) => {
                if let Some(result) = parse_ptr_response(&buf[..len], targets) {
                    let _ = tx.send(result).await;
                }
            }
            _ => break,
        }
    }
}

fn build_ptr_query(txid: u16, ip: Ipv4Addr) -> Vec<u8> {
    // Construct the reverse DNS name: e.g. 100.1.168.192.in-addr.arpa
    let octets = ip.octets();
    let qname = format!(
        "{}.{}.{}.{}.in-addr.arpa",
        octets[3], octets[2], octets[1], octets[0]
    );

    let mut pkt = Vec::with_capacity(30 + qname.len());

    // Transaction ID
    pkt.push((txid >> 8) as u8);
    pkt.push((txid & 0xFF) as u8);
    // Flags: standard query, recursion desired
    pkt.extend_from_slice(&[0x01, 0x00]);
    // QDCOUNT = 1
    pkt.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT, NSCOUNT, ARCOUNT = 0
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Encode QNAME as DNS labels
    for label in qname.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0x00); // root label

    // QTYPE = PTR (0x000C)
    pkt.extend_from_slice(&[0x00, 0x0C]);
    // QCLASS = IN
    pkt.extend_from_slice(&[0x00, 0x01]);

    pkt
}

fn parse_ptr_response(data: &[u8], targets: &[Ipv4Addr]) -> Option<DnsResult> {
    if data.len() < 12 {
        return None;
    }

    // Read ANCOUNT
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    if ancount == 0 {
        return None;
    }

    // Skip the header and question section
    let mut offset = 12;

    // Skip question name
    offset = skip_dns_name(data, offset)?;
    // Skip QTYPE and QCLASS
    offset += 4;

    if offset >= data.len() {
        return None;
    }

    // Parse first answer record
    // Skip answer name (may be pointer)
    offset = skip_dns_name(data, offset)?;

    if offset + 10 > data.len() {
        return None;
    }

    let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2; // type
    offset += 2; // class
    offset += 4; // ttl
    let rdlength = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    // Only process PTR records (type 12)
    if rtype != 12 {
        return None;
    }

    if offset + rdlength > data.len() {
        return None;
    }

    // Read the PTR hostname
    let hostname = read_dns_name(data, offset)?;

    // Extract the IP from the question section to match against targets
    // We'll try to infer from the question section (offset 12)
    let question_ip = extract_ip_from_question(data)?;

    // Match against known targets
    let matched_ip = targets.iter().find(|&&t| t == question_ip).copied()?;

    Some(DnsResult {
        ip: IpAddr::V4(matched_ip),
        hostname,
    })
}

fn extract_ip_from_question(data: &[u8]) -> Option<Ipv4Addr> {
    // Question section starts at offset 12
    // Read the QNAME labels until null byte
    let mut offset = 12;
    let mut labels: Vec<String> = Vec::new();
    loop {
        if offset >= data.len() {
            return None;
        }
        let len = data[offset] as usize;
        if len == 0 {
            break;
        }
        offset += 1;
        if offset + len > data.len() {
            return None;
        }
        let label = std::str::from_utf8(&data[offset..offset + len]).ok()?;
        labels.push(label.to_string());
        offset += len;
    }
    // Expect: d.c.b.a.in-addr.arpa → IP is a.b.c.d
    if labels.len() < 6 {
        return None;
    }
    let d: u8 = labels[0].parse().ok()?;
    let c: u8 = labels[1].parse().ok()?;
    let b: u8 = labels[2].parse().ok()?;
    let a: u8 = labels[3].parse().ok()?;
    Some(Ipv4Addr::new(a, b, c, d))
}

fn skip_dns_name(data: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        if offset >= data.len() {
            return None;
        }
        let byte = data[offset];
        if byte == 0 {
            return Some(offset + 1);
        } else if (byte & 0xC0) == 0xC0 {
            // Pointer: 2 bytes
            return Some(offset + 2);
        } else {
            offset += 1 + (byte as usize);
        }
    }
}

fn read_dns_name(data: &[u8], mut offset: usize) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut safety = 0;

    loop {
        if safety > 20 || offset >= data.len() {
            break;
        }
        safety += 1;

        let byte = data[offset];
        if byte == 0 {
            break;
        } else if (byte & 0xC0) == 0xC0 {
            if offset + 1 >= data.len() {
                break;
            }
            let ptr = (((byte & 0x3F) as usize) << 8) | (data[offset + 1] as usize);
            if !jumped {
                jumped = true;
            }
            offset = ptr;
        } else {
            let len = byte as usize;
            offset += 1;
            if offset + len > data.len() {
                break;
            }
            if let Ok(label) = std::str::from_utf8(&data[offset..offset + len]) {
                labels.push(label.to_string());
            }
            offset += len;
        }
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

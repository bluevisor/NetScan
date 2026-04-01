use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, atomic::AtomicBool, atomic::Ordering};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

#[derive(Debug, Clone)]
pub struct MdnsResult {
    pub ip: Option<IpAddr>,
    pub hostname: Option<String>,
    pub service_type: String,
    pub instance_name: String,
    pub txt_records: HashMap<String, String>,
    pub port: Option<u16>,
}

/// Continuously listen for mDNS announcements and responses until `shutdown` is set.
/// Unlike `mdns_discover`, this function does not time out; it runs indefinitely.
pub async fn mdns_listen_continuous(tx: mpsc::Sender<MdnsResult>, shutdown: Arc<AtomicBool>) {
    let socket = match UdpSocket::bind("0.0.0.0:5353").await {
        Ok(s) => s,
        Err(_) => match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("mDNS continuous: failed to bind socket: {}", e);
                return;
            }
        },
    };

    let _ = socket.join_multicast_v4(MDNS_ADDR, Ipv4Addr::UNSPECIFIED);

    let mut buf = [0u8; 4096];

    while !shutdown.load(Ordering::Relaxed) {
        match tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await {
            Ok(Ok((len, src))) => {
                if let Some(results) = parse_mdns_response(&buf[..len], src) {
                    for result in results {
                        if tx.send(result).await.is_err() {
                            break;
                        }
                    }
                }
            }
            Ok(Err(_)) => break,
            Err(_) => {} // timeout — loop and check shutdown
        }
    }

    let _ = socket.leave_multicast_v4(MDNS_ADDR, Ipv4Addr::UNSPECIFIED);
}

/// Common service types to query
const SERVICE_QUERIES: &[&str] = &[
    "_services._dns-sd._udp.local",
    "_http._tcp.local",
    "_https._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_companion-link._tcp.local",
    "_homekit._tcp.local",
    "_smb._tcp.local",
    "_afpovertcp._tcp.local",
    "_ssh._tcp.local",
    "_printer._tcp.local",
    "_ipp._tcp.local",
    "_pdl-datastream._tcp.local",
    "_scanner._tcp.local",
    "_googlecast._tcp.local",
    "_spotify-connect._tcp.local",
    "_sonos._tcp.local",
    "_hap._tcp.local",
    "_sleep-proxy._udp.local",
];

/// Run mDNS discovery by sending queries and listening for responses
pub async fn mdns_discover(tx: mpsc::Sender<MdnsResult>) {
    let socket = match UdpSocket::bind("0.0.0.0:5353").await {
        Ok(s) => s,
        Err(e) => {
            // Try alternate port — 5353 might be in use
            match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => {
                    eprintln!("mDNS: failed to bind socket: {}", e);
                    return;
                }
            }
        }
    };

    // Join multicast group
    let _ = socket.join_multicast_v4(MDNS_ADDR, Ipv4Addr::UNSPECIFIED);

    let mdns_dest = SocketAddr::new(IpAddr::V4(MDNS_ADDR), MDNS_PORT);

    // Send queries for each service type
    for service in SERVICE_QUERIES {
        let query = build_mdns_query(service);
        let _ = socket.send_to(&query, mdns_dest).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Listen for responses
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

    loop {
        match tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, src))) => {
                if let Some(results) = parse_mdns_response(&buf[..len], src) {
                    for result in results {
                        let _ = tx.send(result).await;
                    }
                }
            }
            _ => break,
        }
    }

    let _ = socket.leave_multicast_v4(MDNS_ADDR, Ipv4Addr::UNSPECIFIED);
}

/// Build a minimal mDNS query packet for a service type
fn build_mdns_query(name: &str) -> Vec<u8> {
    let mut packet = Vec::new();

    // Header: ID=0, QR=0 (query), OPCODE=0, 1 question
    packet.extend_from_slice(&[0x00, 0x00]); // ID
    packet.extend_from_slice(&[0x00, 0x00]); // Flags (standard query)
    packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    // Encode domain name
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00); // Root label

    packet.extend_from_slice(&[0x00, 0x0C]); // QTYPE = PTR
    packet.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

    packet
}

/// Parse an mDNS response packet, extracting service instances and records
fn parse_mdns_response(data: &[u8], src: SocketAddr) -> Option<Vec<MdnsResult>> {
    if data.len() < 12 {
        return None;
    }

    let _id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let _qr = (flags >> 15) & 1;

    // We want responses (QR=1) or unsolicited announcements
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    let mut offset = 12;
    let mut results = Vec::new();

    // Skip questions
    for _ in 0..qdcount {
        offset = skip_dns_name(data, offset)?;
        offset += 4; // QTYPE + QCLASS
        if offset > data.len() {
            return None;
        }
    }

    // Track IP addresses from A records and TXT from TXT records
    let mut a_records: HashMap<String, IpAddr> = HashMap::new();
    let mut txt_records_map: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut srv_records: HashMap<String, (String, u16)> = HashMap::new(); // name -> (target, port)
    let mut ptr_records: Vec<(String, String)> = Vec::new(); // (service_type, instance_name)

    let total_records = ancount + nscount + arcount;
    for _ in 0..total_records {
        if offset >= data.len() {
            break;
        }
        let (name, new_offset) = read_dns_name(data, offset)?;
        offset = new_offset;

        if offset + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let _rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let _ttl = u32::from_be_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > data.len() {
            break;
        }

        let rdata = &data[offset..offset + rdlength];

        match rtype {
            1 => { // A record
                if rdlength == 4 {
                    let ip = IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
                    a_records.insert(name.clone(), ip);
                }
            }
            12 => { // PTR record
                if let Some((pointed_name, _)) = read_dns_name(data, offset) {
                    ptr_records.push((name.clone(), pointed_name));
                }
            }
            16 => { // TXT record
                let txt = parse_txt_rdata(rdata);
                txt_records_map.insert(name.clone(), txt);
            }
            33 => { // SRV record
                if rdlength >= 6 {
                    let _priority = u16::from_be_bytes([rdata[0], rdata[1]]);
                    let _weight = u16::from_be_bytes([rdata[2], rdata[3]]);
                    let port = u16::from_be_bytes([rdata[4], rdata[5]]);
                    if let Some((target, _)) = read_dns_name(data, offset + 6) {
                        srv_records.insert(name.clone(), (target, port));
                    }
                }
            }
            _ => {}
        }

        offset += rdlength;
    }

    // Build results from PTR records (service instances)
    for (service_type, instance_name) in &ptr_records {
        let txt = txt_records_map.get(instance_name).cloned().unwrap_or_default();
        let port = srv_records.get(instance_name).map(|(_, p)| *p);
        let hostname = srv_records.get(instance_name).map(|(t, _)| t.trim_end_matches('.').to_string());

        // Try to find IP from A records
        let ip = hostname.as_ref()
            .and_then(|h| a_records.get(h).copied())
            .or(Some(src.ip()));

        results.push(MdnsResult {
            ip,
            hostname,
            service_type: service_type.clone(),
            instance_name: instance_name.clone(),
            txt_records: txt,
            port,
        });
    }

    // If no PTR records but we have A records (unsolicited announcements)
    if results.is_empty() && !a_records.is_empty() {
        for (name, ip) in &a_records {
            results.push(MdnsResult {
                ip: Some(*ip),
                hostname: Some(name.trim_end_matches('.').to_string()),
                service_type: String::new(),
                instance_name: String::new(),
                txt_records: HashMap::new(),
                port: None,
            });
        }
    }

    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

/// Parse TXT record RDATA into key-value pairs
fn parse_txt_rdata(data: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut i = 0;
    while i < data.len() {
        let len = data[i] as usize;
        i += 1;
        if i + len > data.len() {
            break;
        }
        if let Ok(s) = std::str::from_utf8(&data[i..i + len]) {
            if let Some(eq) = s.find('=') {
                map.insert(s[..eq].to_string(), s[eq + 1..].to_string());
            }
        }
        i += len;
    }
    map
}

/// Read a DNS name from the packet, handling compression pointers
fn read_dns_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut jumped = false;
    let mut return_offset = 0;

    loop {
        if offset >= data.len() {
            return None;
        }
        let len = data[offset] as usize;

        if len == 0 {
            offset += 1;
            break;
        }

        // Compression pointer
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                return None;
            }
            let pointer = ((len & 0x3F) << 8) | data[offset + 1] as usize;
            if !jumped {
                return_offset = offset + 2;
                jumped = true;
            }
            offset = pointer;
            continue;
        }

        offset += 1;
        if offset + len > data.len() {
            return None;
        }
        if let Ok(label) = std::str::from_utf8(&data[offset..offset + len]) {
            labels.push(label.to_string());
        }
        offset += len;
    }

    let final_offset = if jumped { return_offset } else { offset };
    Some((labels.join("."), final_offset))
}

/// Skip over a DNS name in the packet, returning the offset after it
fn skip_dns_name(data: &[u8], start: usize) -> Option<usize> {
    let mut offset = start;
    loop {
        if offset >= data.len() {
            return None;
        }
        let len = data[offset] as usize;
        if len == 0 {
            return Some(offset + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(offset + 2);
        }
        offset += 1 + len;
    }
}

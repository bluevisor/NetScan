use std::net::{IpAddr, Ipv4Addr};

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::Packet;

use crate::model::SnifferEvent;

pub fn parse_ethernet_frame(data: &[u8]) -> Vec<SnifferEvent> {
    let mut events = Vec::new();

    let eth = match EthernetPacket::new(data) {
        Some(e) => e,
        None => return events,
    };

    match eth.get_ethertype() {
        EtherTypes::Arp => {
            if let Some(arp) = ArpPacket::new(eth.payload()) {
                let op = if arp.get_operation() == ArpOperations::Request {
                    "request"
                } else {
                    "reply"
                };
                let mut event = SnifferEvent::new(
                    "ARP",
                    format!(
                        "ARP {} {} → {} ({}→{})",
                        op,
                        arp.get_sender_proto_addr(),
                        arp.get_target_proto_addr(),
                        arp.get_sender_hw_addr(),
                        arp.get_target_hw_addr(),
                    ),
                );
                event.source_ip = Some(IpAddr::V4(arp.get_sender_proto_addr()));
                event.dest_ip = Some(IpAddr::V4(arp.get_target_proto_addr()));
                events.push(event);
            }
        }
        EtherTypes::Ipv4 => {
            if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                let src = ipv4.get_source();
                let dst = ipv4.get_destination();

                match ipv4.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            let sport = tcp.get_source();
                            let dport = tcp.get_destination();

                            // Check for HTTP
                            if (sport == 80 || dport == 80) && !tcp.payload().is_empty() {
                                if let Some(evt) = parse_http(tcp.payload(), src, dst) {
                                    events.push(evt);
                                }
                            }

                            // Check for TLS ClientHello (port 443 or others)
                            if tcp.payload().len() > 5 && tcp.payload()[0] == 0x16 {
                                if let Some(evt) = parse_tls_sni(tcp.payload(), src, dst) {
                                    events.push(evt);
                                }
                            }
                        }
                    }
                    IpNextHeaderProtocols::Udp => {
                        if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                            let sport = udp.get_source();
                            let dport = udp.get_destination();

                            // mDNS
                            if sport == 5353 || dport == 5353 {
                                if let Some(evt) = parse_mdns_packet(udp.payload(), src, dst) {
                                    events.push(evt);
                                }
                            }

                            // DNS
                            if sport == 53 || dport == 53 {
                                if let Some(evt) = parse_dns_packet(udp.payload(), src, dst, sport == 53) {
                                    events.push(evt);
                                }
                            }

                            // DHCP
                            if sport == 67 || sport == 68 || dport == 67 || dport == 68 {
                                if let Some(evt) = parse_dhcp_packet(udp.payload(), src, dst) {
                                    events.push(evt);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }

    events
}

fn parse_http(payload: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> Option<SnifferEvent> {
    let text = std::str::from_utf8(payload).ok()?;

    // Look for Host header
    for line in text.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("host:") {
            let host = line[5..].trim();
            let mut event = SnifferEvent::new(
                "HTTP",
                format!("Host: {} ← {}", host, src),
            );
            event.source_ip = Some(IpAddr::V4(src));
            event.dest_ip = Some(IpAddr::V4(dst));
            return Some(event);
        }
    }

    // Look for User-Agent
    for line in text.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("user-agent:") {
            let ua = line[11..].trim();
            let short_ua: String = ua.chars().take(80).collect();
            let mut event = SnifferEvent::new(
                "HTTP",
                format!("UA: {} ← {}", short_ua, src),
            );
            event.source_ip = Some(IpAddr::V4(src));
            event.dest_ip = Some(IpAddr::V4(dst));
            return Some(event);
        }
    }

    None
}

fn parse_tls_sni(payload: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> Option<SnifferEvent> {
    // TLS record: content_type(1) version(2) length(2) handshake_type(1)
    if payload.len() < 44 || payload[0] != 0x16 || payload[5] != 0x01 {
        return None; // Not a ClientHello
    }

    // Parse ClientHello to find SNI extension
    // Skip: record header(5) + handshake header(4) + version(2) + random(32) = 43
    let mut offset = 43;
    if offset >= payload.len() {
        return None;
    }

    // Session ID
    let sid_len = payload[offset] as usize;
    offset += 1 + sid_len;

    if offset + 2 > payload.len() {
        return None;
    }

    // Cipher suites
    let cs_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
    offset += 2 + cs_len;

    if offset >= payload.len() {
        return None;
    }

    // Compression methods
    let cm_len = payload[offset] as usize;
    offset += 1 + cm_len;

    if offset + 2 > payload.len() {
        return None;
    }

    // Extensions
    let _ext_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
    offset += 2;

    // Walk extensions looking for SNI (type 0x0000)
    while offset + 4 <= payload.len() {
        let ext_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let ext_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
        offset += 4;

        if ext_type == 0x0000 && ext_len > 5 && offset + ext_len <= payload.len() {
            // SNI extension: list_length(2) + type(1) + name_length(2) + name
            let name_len = u16::from_be_bytes([payload[offset + 3], payload[offset + 4]]) as usize;
            let name_start = offset + 5;
            if name_start + name_len <= payload.len() {
                if let Ok(sni) = std::str::from_utf8(&payload[name_start..name_start + name_len]) {
                    let mut event = SnifferEvent::new(
                        "TLS",
                        format!("SNI: {} ← {}", sni, src),
                    );
                    event.source_ip = Some(IpAddr::V4(src));
                    event.dest_ip = Some(IpAddr::V4(dst));
                    return Some(event);
                }
            }
        }

        offset += ext_len;
    }

    None
}

fn parse_dns_packet(payload: &[u8], src: Ipv4Addr, dst: Ipv4Addr, is_response: bool) -> Option<SnifferEvent> {
    if payload.len() < 12 {
        return None;
    }

    let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    if qdcount == 0 {
        return None;
    }

    // Read first query name
    let mut offset = 12;
    let mut labels = Vec::new();
    while offset < payload.len() {
        let len = payload[offset] as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            break; // compression pointer, stop
        }
        offset += 1;
        if offset + len > payload.len() {
            break;
        }
        if let Ok(label) = std::str::from_utf8(&payload[offset..offset + len]) {
            labels.push(label.to_string());
        }
        offset += len;
    }

    if labels.is_empty() {
        return None;
    }

    let qname = labels.join(".");
    let direction = if is_response { "response" } else { "query" };
    let mut event = SnifferEvent::new(
        "DNS",
        format!("{} {} ← {}", direction, qname, if is_response { dst } else { src }),
    );
    event.source_ip = Some(IpAddr::V4(src));
    event.dest_ip = Some(IpAddr::V4(dst));
    Some(event)
}

fn parse_mdns_packet(payload: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> Option<SnifferEvent> {
    if payload.len() < 12 {
        return None;
    }

    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags >> 15) & 1 == 1;
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);

    // Read first name
    let mut offset = 12;
    let mut labels = Vec::new();
    while offset < payload.len() {
        let len = payload[offset] as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            break;
        }
        offset += 1;
        if offset + len > payload.len() {
            break;
        }
        if let Ok(label) = std::str::from_utf8(&payload[offset..offset + len]) {
            labels.push(label.to_string());
        }
        offset += len;
    }

    if labels.is_empty() {
        return None;
    }

    let name = labels.join(".");
    let kind = if is_response {
        format!("announce ({}ans)", ancount)
    } else {
        format!("query ({}q)", qdcount)
    };

    let mut event = SnifferEvent::new(
        "mDNS",
        format!("{} {} ← {}", kind, name, src),
    );
    event.source_ip = Some(IpAddr::V4(src));
    event.dest_ip = Some(IpAddr::V4(dst));
    Some(event)
}

fn parse_dhcp_packet(payload: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> Option<SnifferEvent> {
    // DHCP: minimum 240 bytes (236 base + 4 magic cookie)
    if payload.len() < 240 {
        return None;
    }

    let op = payload[0]; // 1=request, 2=reply
    let magic = &payload[236..240];
    if magic != [99, 130, 83, 99] {
        return None; // Not DHCP
    }

    // Extract hostname from option 12
    let mut offset = 240;
    let mut hostname = None;
    let mut msg_type = "unknown";

    while offset + 2 < payload.len() {
        let opt = payload[offset];
        if opt == 255 {
            break; // End
        }
        if opt == 0 {
            offset += 1; // Pad
            continue;
        }
        let len = payload[offset + 1] as usize;
        offset += 2;
        if offset + len > payload.len() {
            break;
        }

        match opt {
            12 => { // Hostname
                hostname = std::str::from_utf8(&payload[offset..offset + len]).ok().map(String::from);
            }
            53 if len == 1 => { // DHCP Message Type
                msg_type = match payload[offset] {
                    1 => "DISCOVER",
                    2 => "OFFER",
                    3 => "REQUEST",
                    4 => "DECLINE",
                    5 => "ACK",
                    6 => "NAK",
                    7 => "RELEASE",
                    8 => "INFORM",
                    _ => "unknown",
                };
            }
            _ => {}
        }
        offset += len;
    }

    let host_str = hostname.as_deref().unwrap_or("?");
    let mut event = SnifferEvent::new(
        "DHCP",
        format!("{} host={} {}→{}", msg_type, host_str, src, dst),
    );
    event.source_ip = Some(IpAddr::V4(src));
    event.dest_ip = Some(IpAddr::V4(dst));
    Some(event)
}

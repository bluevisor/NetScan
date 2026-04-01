use std::net::{IpAddr, Ipv4Addr};

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;

use crate::model::SnifferEvent;

/// Structured info extracted from LLDP or CDP frames.
pub struct LldpCdpInfo {
    pub source_mac: Option<MacAddr>,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub platform: Option<String>,
    pub management_ip: Option<IpAddr>,
}

/// DHCP fingerprint extracted from a DHCP packet.
pub struct DhcpFingerprint {
    pub source_mac: Option<MacAddr>,
    pub hostname: Option<String>,
    pub option55: Vec<u8>,
    pub vendor_class: Option<String>,
    pub source_ip: Ipv4Addr,
}

pub fn parse_ethernet_frame(data: &[u8]) -> (Vec<SnifferEvent>, Option<LldpCdpInfo>) {
    let mut events = Vec::new();
    let mut lldp_cdp_info: Option<LldpCdpInfo> = None;

    let eth = match EthernetPacket::new(data) {
        Some(e) => e,
        None => return (events, lldp_cdp_info),
    };

    let src_mac = eth.get_source();

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
                                let (evt, fp) = parse_dhcp_packet(udp.payload(), src, dst);
                                if let Some(e) = evt {
                                    events.push(e);
                                }
                                // We store the fingerprint but don't have a separate channel here;
                                // capture.rs handles it via the returned value.
                                // For now we drop fp (wired in capture.rs via a different approach).
                                let _ = fp;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        // LLDP: EtherType 0x88CC
        et if et.0 == 0x88CC => {
            let (evt, info) = parse_lldp(eth.payload(), src_mac);
            if let Some(e) = evt {
                events.push(e);
            }
            lldp_cdp_info = info;
        }
        // CDP comes as a SNAP frame inside 802.3 (EtherType <= 1500 means length field)
        // pnet will report EtherType as the length value; we detect via SNAP header in payload.
        et if et.0 <= 1500 => {
            // LLC + SNAP: AA AA 03 <OUI 3 bytes> <proto 2 bytes>
            let payload = eth.payload();
            if payload.len() >= 8
                && payload[0] == 0xAA
                && payload[1] == 0xAA
                && payload[2] == 0x03
                && payload[3] == 0x00
                && payload[4] == 0x00
                && payload[5] == 0x0C
                && payload[6] == 0x20
                && payload[7] == 0x00
            {
                // CDP payload starts at byte 8
                let (evt, info) = parse_cdp(&payload[8..], src_mac);
                if let Some(e) = evt {
                    events.push(e);
                }
                lldp_cdp_info = info;
            }
        }
        _ => {}
    }

    (events, lldp_cdp_info)
}

// ── LLDP ────────────────────────────────────────────────────────────────────

fn parse_lldp(payload: &[u8], src_mac: MacAddr) -> (Option<SnifferEvent>, Option<LldpCdpInfo>) {
    let mut system_name: Option<String> = None;
    let mut system_description: Option<String> = None;
    let mut port_description: Option<String> = None;
    let mut management_ip: Option<IpAddr> = None;

    let mut offset = 0;
    while offset + 2 <= payload.len() {
        let type_and_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let tlv_type = (type_and_len >> 9) as u8; // top 7 bits
        let tlv_len = (type_and_len & 0x01FF) as usize; // bottom 9 bits
        offset += 2;

        if tlv_type == 0 {
            break; // End of LLDPDU
        }
        if offset + tlv_len > payload.len() {
            break;
        }

        let value = &payload[offset..offset + tlv_len];
        match tlv_type {
            4 => { // Port Description
                port_description = std::str::from_utf8(value).ok().map(String::from);
            }
            5 => { // System Name
                system_name = std::str::from_utf8(value).ok().map(String::from);
            }
            6 => { // System Description
                system_description = std::str::from_utf8(value).ok().map(String::from);
            }
            8 => { // Management Address
                // subtype(1) + addr_len(1) + addr_subtype(1) + addr
                if value.len() >= 3 {
                    let addr_len = value[0] as usize;
                    let addr_subtype = value[1];
                    if addr_subtype == 1 && addr_len == 5 && value.len() >= 6 {
                        // IPv4
                        management_ip = Some(IpAddr::V4(Ipv4Addr::new(
                            value[2], value[3], value[4], value[5],
                        )));
                    }
                }
            }
            _ => {}
        }

        offset += tlv_len;
    }

    let summary = format!(
        "LLDP from {} name={} desc={} port={} mgmt={}",
        src_mac,
        system_name.as_deref().unwrap_or("?"),
        system_description.as_deref().unwrap_or("?"),
        port_description.as_deref().unwrap_or("?"),
        management_ip.map(|ip| ip.to_string()).as_deref().unwrap_or("?"),
    );

    let event = SnifferEvent::new("LLDP", summary);

    let info = LldpCdpInfo {
        source_mac: Some(src_mac),
        system_name,
        system_description,
        platform: None,
        management_ip,
    };

    (Some(event), Some(info))
}

// ── CDP ─────────────────────────────────────────────────────────────────────

fn parse_cdp(payload: &[u8], src_mac: MacAddr) -> (Option<SnifferEvent>, Option<LldpCdpInfo>) {
    // CDP packet: version(1) ttl(1) checksum(2) then TLVs
    if payload.len() < 4 {
        return (None, None);
    }

    let mut device_id: Option<String> = None;
    let mut platform: Option<String> = None;
    let mut software_version: Option<String> = None;

    let mut offset = 4; // skip version, ttl, checksum
    while offset + 4 <= payload.len() {
        let tlv_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let tlv_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
        offset += 4;

        if tlv_len < 4 {
            break;
        }
        let value_len = tlv_len - 4;
        if offset + value_len > payload.len() {
            break;
        }

        let value = &payload[offset..offset + value_len];
        match tlv_type {
            0x0001 => { // Device ID
                device_id = std::str::from_utf8(value).ok().map(String::from);
            }
            0x0005 => { // Software Version
                software_version = std::str::from_utf8(value).ok().map(String::from);
            }
            0x0006 => { // Platform
                platform = std::str::from_utf8(value).ok().map(String::from);
            }
            _ => {}
        }

        offset += value_len;
    }

    let summary = format!(
        "CDP from {} device_id={} platform={} sw={}",
        src_mac,
        device_id.as_deref().unwrap_or("?"),
        platform.as_deref().unwrap_or("?"),
        software_version.as_deref().unwrap_or("?"),
    );

    let event = SnifferEvent::new("CDP", summary);

    let info = LldpCdpInfo {
        source_mac: Some(src_mac),
        system_name: device_id,
        system_description: software_version,
        platform,
        management_ip: None,
    };

    (Some(event), Some(info))
}

// ── HTTP / TLS / DNS / mDNS (unchanged) ─────────────────────────────────────

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

// ── DHCP with fingerprinting ─────────────────────────────────────────────────

/// Match option-55 list and vendor class to a likely OS string.
pub fn match_dhcp_fingerprint(option55: &[u8], vendor_class: Option<&str>) -> Option<String> {
    // Vendor class overrides
    if let Some(vc) = vendor_class {
        let vc_lower = vc.to_lowercase();
        if vc.starts_with("MSFT ") {
            return Some("Windows".to_string());
        }
        if vc_lower.contains("android") {
            return Some("Android".to_string());
        }
        if vc_lower.contains("dhcpcd") {
            return Some("Linux".to_string());
        }
    }

    // Known option-55 fingerprints (compare as slices)
    let ios_fp: &[&[u8]] = &[
        &[1, 3, 6, 15, 119, 252],
        &[1, 3, 6, 15, 119, 252, 95],
    ];
    let macos_fp: &[u8] = &[1, 121, 3, 6, 15, 114, 119, 252];
    let windows_fp: &[u8] = &[1, 15, 3, 6, 44, 46, 47, 31, 33, 121, 249, 252, 43];
    let android_fp: &[u8] = &[1, 3, 6, 15, 26, 28, 51, 58, 59];

    for fp in ios_fp {
        if option55 == *fp {
            return Some("iOS".to_string());
        }
    }
    if option55 == macos_fp {
        return Some("macOS".to_string());
    }
    if option55 == windows_fp {
        return Some("Windows 10/11".to_string());
    }
    if option55 == android_fp {
        return Some("Android".to_string());
    }

    None
}

pub fn parse_dhcp_packet(payload: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> (Option<SnifferEvent>, Option<DhcpFingerprint>) {
    // DHCP: minimum 240 bytes (236 base + 4 magic cookie)
    if payload.len() < 240 {
        return (None, None);
    }

    let _op = payload[0]; // 1=request, 2=reply
    let magic = &payload[236..240];
    if magic != [99, 130, 83, 99] {
        return (None, None); // Not DHCP
    }

    // Extract options
    let mut offset = 240;
    let mut hostname: Option<String> = None;
    let mut msg_type = "unknown";
    let mut option55: Vec<u8> = Vec::new();
    let mut vendor_class: Option<String> = None;

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
            55 => { // Parameter Request List
                option55 = payload[offset..offset + len].to_vec();
            }
            60 => { // Vendor Class Identifier
                vendor_class = std::str::from_utf8(&payload[offset..offset + len]).ok().map(String::from);
            }
            _ => {}
        }
        offset += len;
    }

    // Build OS hint from fingerprint
    let os_hint = match_dhcp_fingerprint(&option55, vendor_class.as_deref());

    let host_str = hostname.as_deref().unwrap_or("?");
    let os_str = os_hint.as_deref().unwrap_or("");
    let summary = if os_str.is_empty() {
        format!("{} host={} {}→{}", msg_type, host_str, src, dst)
    } else {
        format!("{} host={} os={} {}→{}", msg_type, host_str, os_str, src, dst)
    };

    let mut event = SnifferEvent::new("DHCP", summary);
    event.source_ip = Some(IpAddr::V4(src));
    event.dest_ip = Some(IpAddr::V4(dst));

    let fp = DhcpFingerprint {
        source_mac: None, // MAC not available at this layer; capture.rs can fill it
        hostname,
        option55,
        vendor_class,
        source_ip: src,
    };

    (Some(event), Some(fp))
}

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use pnet::util::MacAddr;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Device {
    pub ip: IpAddr,
    #[serde(serialize_with = "serialize_mac_option")]
    pub mac: Option<MacAddr>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub device_type: DeviceType,
    pub model: Option<String>,
    pub os: Option<String>,
    pub ports: Vec<PortInfo>,
    pub mdns_services: Vec<MdnsService>,
    #[serde(skip)]
    pub first_seen: Instant,
    #[serde(skip)]
    pub last_seen: Instant,
    pub confidence: f32,
    pub sources: Vec<DiscoveryMethod>,
    #[serde(skip)]
    pub scan_state: DeviceScanState,
}

fn serialize_mac_option<S: serde::Serializer>(mac: &Option<MacAddr>, s: S) -> Result<S::Ok, S::Error> {
    match mac {
        Some(m) => s.serialize_str(&m.to_string()),
        None => s.serialize_none(),
    }
}

impl Device {
    pub fn new(ip: IpAddr) -> Self {
        let now = Instant::now();
        Self {
            ip,
            mac: None,
            vendor: None,
            hostname: None,
            device_type: DeviceType::Unknown,
            model: None,
            os: None,
            ports: Vec::new(),
            mdns_services: Vec::new(),
            first_seen: now,
            last_seen: now,
            confidence: 0.0,
            sources: Vec::new(),
            scan_state: DeviceScanState::Discovered,
        }
    }

    pub fn add_source(&mut self, method: DiscoveryMethod) {
        if !self.sources.contains(&method) {
            self.sources.push(method);
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub service: Option<String>,
    pub banner: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MdnsService {
    pub service_type: String,
    pub name: String,
    pub txt_records: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum DeviceType {
    Router, Phone, Tablet, Computer, IoT, NAS, Printer, Camera, TV, AccessPoint, Unknown,
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceType::Router => write!(f, "Router"),
            DeviceType::Phone => write!(f, "Phone"),
            DeviceType::Tablet => write!(f, "Tablet"),
            DeviceType::Computer => write!(f, "Computer"),
            DeviceType::IoT => write!(f, "IoT"),
            DeviceType::NAS => write!(f, "NAS"),
            DeviceType::Printer => write!(f, "Printer"),
            DeviceType::Camera => write!(f, "Camera"),
            DeviceType::TV => write!(f, "TV"),
            DeviceType::AccessPoint => write!(f, "AP"),
            DeviceType::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum DiscoveryMethod { Arp, TcpConnect, Mdns, Ssdp, NetBios, Dhcp, Sniff, Banner, OsFp }

impl std::fmt::Display for DiscoveryMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum Protocol { Tcp, Udp }

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum PortState { Open, Closed, Filtered }

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DeviceScanState { Discovered, Scanning, Done }

#[derive(Debug, Clone, Serialize)]
pub struct SnifferEvent {
    #[serde(skip)]
    pub timestamp: Instant,
    pub protocol: String,
    pub summary: String,
    pub source_ip: Option<IpAddr>,
    pub dest_ip: Option<IpAddr>,
}

impl SnifferEvent {
    pub fn new(protocol: &str, summary: String) -> Self {
        Self {
            timestamp: Instant::now(),
            protocol: protocol.to_string(),
            summary,
            source_ip: None,
            dest_ip: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanPhase { Phase1Instant, Phase2Fast, Phase3Deep, Complete }

impl std::fmt::Display for ScanPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanPhase::Phase1Instant => write!(f, "Phase 1/3: Discovery"),
            ScanPhase::Phase2Fast => write!(f, "Phase 2/3: Services"),
            ScanPhase::Phase3Deep => write!(f, "Phase 3/3: Deep Scan"),
            ScanPhase::Complete => write!(f, "Scan Complete"),
        }
    }
}

pub const TOP_100_PORTS: &[u16] = &[
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
    5000, 5001, 5003, 5009, 5050, 5051, 5060, 5101, 5190, 5357, 5432,
    5631, 5666, 5800, 5900, 5901, 6000, 6001, 6646, 7070, 8000, 8008,
    8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49154,
];

pub fn port_service_name(port: u16) -> Option<&'static str> {
    match port {
        7 => Some("echo"), 21 => Some("ftp"), 22 => Some("ssh"), 23 => Some("telnet"),
        25 => Some("smtp"), 53 => Some("dns"), 80 => Some("http"), 88 => Some("kerberos"),
        110 => Some("pop3"), 111 => Some("rpcbind"), 135 => Some("msrpc"),
        139 => Some("netbios-ssn"), 143 => Some("imap"), 389 => Some("ldap"),
        443 => Some("https"), 445 => Some("microsoft-ds"), 465 => Some("smtps"),
        514 => Some("syslog"), 515 => Some("printer"), 548 => Some("afp"),
        554 => Some("rtsp"), 587 => Some("submission"), 631 => Some("ipp"),
        873 => Some("rsync"), 993 => Some("imaps"), 995 => Some("pop3s"),
        1433 => Some("mssql"), 1723 => Some("pptp"), 1900 => Some("ssdp"),
        2049 => Some("nfs"), 3000 => Some("dev-server"), 3306 => Some("mysql"),
        3389 => Some("rdp"), 5000 => Some("upnp"), 5001 => Some("synology"),
        5060 => Some("sip"), 5353 => Some("mdns"), 5432 => Some("postgresql"),
        5900 => Some("vnc"), 5901 => Some("vnc-1"), 6000 => Some("x11"),
        8000 => Some("http-alt"), 8080 => Some("http-proxy"), 8443 => Some("https-alt"),
        8888 => Some("http-alt2"), 9100 => Some("jetdirect"), 9999 => Some("abyss"),
        10000 => Some("webmin"), 62078 => Some("iphone-sync"),
        _ => None,
    }
}

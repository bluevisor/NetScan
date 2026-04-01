use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, atomic::AtomicBool};
use std::time::Duration;

use tokio::sync::{mpsc, Mutex};

use crate::identify::{apple, device_type, oui};
use crate::model::*;
use crate::net::interface::InterfaceInfo;
use crate::net::raw::PrivilegeLevel;
use crate::scanner::{arp, banner, mdns, netbios, os_fp, ports, ssdp};

pub struct ScanState {
    pub devices: HashMap<IpAddr, Device>,
    pub sniffer_events: Vec<SnifferEvent>,
    pub phase: ScanPhase,
    pub paused: bool,
    pub interface: InterfaceInfo,
    pub privilege: PrivilegeLevel,
    pub hosts_scanned: usize,
    pub total_hosts: usize,
}

impl ScanState {
    pub fn new(interface: InterfaceInfo, privilege: PrivilegeLevel, total_hosts: usize) -> Self {
        Self {
            devices: HashMap::new(),
            sniffer_events: Vec::new(),
            phase: ScanPhase::Phase1Instant,
            paused: false,
            interface,
            privilege,
            hosts_scanned: 0,
            total_hosts,
        }
    }

    pub fn get_or_create_device(&mut self, ip: IpAddr) -> &mut Device {
        self.devices.entry(ip).or_insert_with(|| Device::new(ip))
    }

    pub fn sorted_devices(&self) -> Vec<&Device> {
        let mut devs: Vec<&Device> = self.devices.values().collect();
        devs.sort_by(|a, b| {
            match (a.ip, b.ip) {
                (IpAddr::V4(a4), IpAddr::V4(b4)) => {
                    a4.octets().cmp(&b4.octets())
                }
                _ => a.ip.cmp(&b.ip),
            }
        });
        devs
    }

    pub fn add_sniffer_event(&mut self, event: SnifferEvent) {
        // Keep max 500 events
        if self.sniffer_events.len() >= 500 {
            self.sniffer_events.remove(0);
        }
        self.sniffer_events.push(event);
    }
}

pub type SharedState = Arc<Mutex<ScanState>>;

/// Run the full scan orchestration
pub async fn run_scan(
    state: SharedState,
    shutdown: Arc<AtomicBool>,
) {
    let (iface, priv_level, targets) = {
        let s = state.lock().await;
        let targets = crate::net::interface::subnet_hosts(s.interface.network);
        (s.interface.clone(), s.privilege, targets)
    };

    // === PHASE 1: Instant discovery ===
    {
        let mut s = state.lock().await;
        s.phase = ScanPhase::Phase1Instant;
    }

    // Start sniffer in background if root
    let sniffer_shutdown = shutdown.clone();
    let sniffer_state = state.clone();
    if priv_level == PrivilegeLevel::Root {
        let iface_name = iface.name.clone();
        let (sniff_tx, mut sniff_rx) = mpsc::channel::<SnifferEvent>(256);

        // Sniffer capture thread (blocking)
        std::thread::spawn(move || {
            crate::sniffer::capture::start_capture(&iface_name, sniff_tx, sniffer_shutdown);
        });

        // Sniffer event consumer
        let sniff_state = sniffer_state.clone();
        tokio::spawn(async move {
            while let Some(event) = sniff_rx.recv().await {
                let mut s = sniff_state.lock().await;
                s.add_sniffer_event(event);
            }
        });
    }

    // ARP scan or ping sweep
    if priv_level == PrivilegeLevel::Root {
        let (arp_tx, mut arp_rx) = mpsc::channel::<arp::ArpResult>(256);
        let iface_clone = iface.clone();
        let targets_clone = targets.clone();

        tokio::spawn(async move {
            arp::arp_scan(&iface_clone, &targets_clone, arp_tx).await;
        });

        let state_clone = state.clone();
        tokio::spawn(async move {
            while let Some(result) = arp_rx.recv().await {
                let mut s = state_clone.lock().await;
                let dev = s.get_or_create_device(IpAddr::V4(result.ip));
                dev.mac = Some(result.mac);
                dev.last_seen = std::time::Instant::now();
                dev.add_source(DiscoveryMethod::Arp);

                // OUI lookup
                if let Some(vendor) = oui::lookup_vendor(&result.mac) {
                    dev.vendor = Some(vendor.to_string());
                }
                if oui::is_randomized_mac(&result.mac) {
                    dev.vendor = Some("(randomized MAC)".to_string());
                }
            }
        });

        // Wait for ARP phase
        tokio::time::sleep(Duration::from_secs(3)).await;
    } else {
        let (ping_tx, mut ping_rx) = mpsc::channel::<Ipv4Addr>(256);
        let targets_clone = targets.clone();

        tokio::spawn(async move {
            arp::ping_sweep(&targets_clone, ping_tx).await;
        });

        let state_clone = state.clone();
        tokio::spawn(async move {
            while let Some(ip) = ping_rx.recv().await {
                let mut s = state_clone.lock().await;
                let dev = s.get_or_create_device(IpAddr::V4(ip));
                dev.last_seen = std::time::Instant::now();
                dev.add_source(DiscoveryMethod::TcpConnect);
            }
        });

        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }

    // === PHASE 2: Fast scan ===
    {
        let mut s = state.lock().await;
        s.phase = ScanPhase::Phase2Fast;
    }

    // Get discovered hosts
    let discovered_ips: Vec<Ipv4Addr> = {
        let s = state.lock().await;
        s.devices.keys().filter_map(|ip| {
            if let IpAddr::V4(v4) = ip { Some(*v4) } else { None }
        }).collect()
    };

    // Port scan top 100 on all discovered hosts
    let (port_tx, mut port_rx) = mpsc::channel::<ports::PortScanResult>(512);
    for &ip in &discovered_ips {
        let tx = port_tx.clone();
        tokio::spawn(async move {
            ports::scan_ports(ip, TOP_100_PORTS, tx, 1000, 50).await;
        });
    }
    drop(port_tx);

    let port_state = state.clone();
    let port_collector = tokio::spawn(async move {
        while let Some(result) = port_rx.recv().await {
            let mut s = port_state.lock().await;
            let dev = s.get_or_create_device(result.ip);
            if !dev.ports.iter().any(|p| p.port == result.port_info.port) {
                dev.ports.push(result.port_info);
                dev.ports.sort_by_key(|p| p.port);
            }
            dev.add_source(DiscoveryMethod::TcpConnect);
            dev.scan_state = DeviceScanState::Scanning;
        }
    });

    // mDNS discovery
    let (mdns_tx, mut mdns_rx) = mpsc::channel::<mdns::MdnsResult>(256);
    tokio::spawn(async move {
        mdns::mdns_discover(mdns_tx).await;
    });

    let mdns_state = state.clone();
    let mdns_collector = tokio::spawn(async move {
        while let Some(result) = mdns_rx.recv().await {
            let mut s = mdns_state.lock().await;
            if let Some(ip) = result.ip {
                let dev = s.get_or_create_device(ip);
                if let Some(ref hostname) = result.hostname {
                    if dev.hostname.is_none() {
                        dev.hostname = Some(hostname.clone());
                    }
                }
                if !result.service_type.is_empty() {
                    dev.mdns_services.push(MdnsService {
                        service_type: result.service_type.clone(),
                        name: result.instance_name.clone(),
                        txt_records: result.txt_records.clone(),
                    });
                }
                dev.add_source(DiscoveryMethod::Mdns);

                // Apple device fingerprinting
                let services: Vec<String> = dev.mdns_services.iter()
                    .map(|s| s.service_type.clone())
                    .collect();
                let mut all_txt: HashMap<String, String> = HashMap::new();
                for svc in &dev.mdns_services {
                    all_txt.extend(svc.txt_records.clone());
                }

                let model_id = all_txt.get("model").map(|s| s.as_str());
                let apple_info = apple::classify_apple_device(
                    model_id,
                    dev.hostname.as_deref(),
                    &services,
                    &all_txt,
                );
                if apple_info.confidence > dev.confidence {
                    dev.vendor = Some(apple_info.brand);
                    dev.confidence = apple_info.confidence;
                    if let Some(dt) = &apple_info.device_type {
                        dev.device_type = match dt.as_str() {
                            "Phone" => DeviceType::Phone,
                            "Tablet" => DeviceType::Tablet,
                            "Computer" => DeviceType::Computer,
                            "TV" => DeviceType::TV,
                            "IoT" => DeviceType::IoT,
                            _ => dev.device_type,
                        };
                    }
                    if let Some(name) = apple_info.marketing_name {
                        dev.model = Some(name);
                    }
                }
            }
        }
    });

    // SSDP discovery
    let (ssdp_tx, mut ssdp_rx) = mpsc::channel::<ssdp::SsdpResult>(256);
    tokio::spawn(async move {
        ssdp::ssdp_discover(ssdp_tx).await;
    });

    let ssdp_state = state.clone();
    let ssdp_collector = tokio::spawn(async move {
        while let Some(result) = ssdp_rx.recv().await {
            let mut s = ssdp_state.lock().await;
            let dev = s.get_or_create_device(result.ip);
            dev.add_source(DiscoveryMethod::Ssdp);
            if let Some(server) = &result.server {
                if dev.os.is_none() {
                    dev.os = Some(server.clone());
                }
            }
        }
    });

    // NetBIOS
    let (nb_tx, mut nb_rx) = mpsc::channel::<netbios::NetBiosResult>(256);
    let nb_targets = discovered_ips.clone();
    tokio::spawn(async move {
        netbios::netbios_query(&nb_targets, nb_tx).await;
    });

    let nb_state = state.clone();
    let nb_collector = tokio::spawn(async move {
        while let Some(result) = nb_rx.recv().await {
            let mut s = nb_state.lock().await;
            let dev = s.get_or_create_device(result.ip);
            if dev.hostname.is_none() {
                dev.hostname = Some(result.name);
            }
            dev.add_source(DiscoveryMethod::NetBios);
        }
    });

    // Wait for phase 2 to complete
    let _ = tokio::join!(port_collector, mdns_collector, ssdp_collector, nb_collector);

    // Classify all devices
    {
        let mut s = state.lock().await;
        let ips: Vec<IpAddr> = s.devices.keys().cloned().collect();
        for ip in ips {
            if let Some(dev) = s.devices.get_mut(&ip) {
                device_type::classify_device(dev);
            }
        }
    }

    if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }

    // === PHASE 3: Deep scan ===
    {
        let mut s = state.lock().await;
        s.phase = ScanPhase::Phase3Deep;
    }

    // Get hosts with open ports for banner grabbing
    let hosts_with_ports: Vec<(IpAddr, Vec<u16>)> = {
        let s = state.lock().await;
        s.devices.iter().filter_map(|(ip, dev)| {
            let open: Vec<u16> = dev.ports.iter()
                .filter(|p| p.state == PortState::Open)
                .map(|p| p.port)
                .collect();
            if open.is_empty() { None } else { Some((*ip, open)) }
        }).collect()
    };

    // Banner grabbing
    let (banner_tx, mut banner_rx) = mpsc::channel::<banner::BannerResult>(256);
    for (ip, open_ports) in &hosts_with_ports {
        let tx = banner_tx.clone();
        let ip = *ip;
        let ports_list = open_ports.clone();
        tokio::spawn(async move {
            banner::grab_banners(ip, &ports_list, tx).await;
        });
    }
    drop(banner_tx);

    let banner_state = state.clone();
    let banner_collector = tokio::spawn(async move {
        while let Some(result) = banner_rx.recv().await {
            let mut s = banner_state.lock().await;
            if let Some(dev) = s.devices.get_mut(&result.ip) {
                if let Some(port_info) = dev.ports.iter_mut().find(|p| p.port == result.port) {
                    port_info.banner = Some(result.banner);
                    port_info.version = result.version;
                }
                dev.add_source(DiscoveryMethod::Banner);
            }
        }
    });

    // OS fingerprinting
    let os_state = state.clone();
    for (ip, open_ports) in &hosts_with_ports {
        let ip = *ip;
        let port = open_ports[0];
        let state_ref = os_state.clone();
        tokio::spawn(async move {
            if let Some(result) = os_fp::fingerprint_os(ip, port).await {
                let mut s = state_ref.lock().await;
                if let Some(dev) = s.devices.get_mut(&ip) {
                    if dev.os.is_none() {
                        dev.os = result.os_guess;
                    }
                    dev.add_source(DiscoveryMethod::OsFp);
                }
            }
        });
    }

    // Top 1000 port scan on discovered hosts
    let top1000 = ports::top_1000_ports();
    let (port2_tx, mut port2_rx) = mpsc::channel::<ports::PortScanResult>(512);
    for &ip in &discovered_ips {
        let tx = port2_tx.clone();
        let ports_to_scan = top1000.clone();
        tokio::spawn(async move {
            ports::scan_ports(ip, &ports_to_scan, tx, 1500, 100).await;
        });
    }
    drop(port2_tx);

    let port2_state = state.clone();
    let port2_collector = tokio::spawn(async move {
        while let Some(result) = port2_rx.recv().await {
            let mut s = port2_state.lock().await;
            let dev = s.get_or_create_device(result.ip);
            if !dev.ports.iter().any(|p| p.port == result.port_info.port) {
                dev.ports.push(result.port_info);
                dev.ports.sort_by_key(|p| p.port);
            }
        }
    });

    let _ = tokio::join!(banner_collector, port2_collector);

    // Mark complete
    {
        let mut s = state.lock().await;
        s.phase = ScanPhase::Complete;
        for dev in s.devices.values_mut() {
            dev.scan_state = DeviceScanState::Done;
        }
    }
}

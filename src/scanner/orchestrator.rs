use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{atomic::AtomicBool, Arc};
use std::time::Duration;

use tokio::sync::{mpsc, Mutex};

use crate::identify::{apple, device_type, llm, oui};
use crate::model::*;
use crate::net::interface::InterfaceInfo;
use crate::net::raw::PrivilegeLevel;
use crate::scanner::{arp, banner, dns, mdns, netbios, os_fp, ports, smb, snmp, ssdp, upnp, wsd};
use crate::sniffer::parser::{DhcpFingerprint, LldpCdpInfo};

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
        devs.sort_by(|a, b| match (a.ip, b.ip) {
            (IpAddr::V4(a4), IpAddr::V4(b4)) => a4.octets().cmp(&b4.octets()),
            _ => a.ip.cmp(&b.ip),
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

fn merge_mdns_result(device: &mut Device, result: &mdns::MdnsResult) -> bool {
    let mut changed = false;

    if let Some(hostname) = &result.hostname {
        if device.hostname.is_none() {
            device.hostname = Some(hostname.clone());
            changed = true;
        }
    }

    if !result.service_type.is_empty() {
        if let Some(existing) = device
            .mdns_services
            .iter_mut()
            .find(|svc| svc.service_type == result.service_type && svc.name == result.instance_name)
        {
            let before = existing.txt_records.clone();
            existing.txt_records.extend(result.txt_records.clone());
            changed |= existing.txt_records != before;
        } else {
            device.mdns_services.push(MdnsService {
                service_type: result.service_type.clone(),
                name: result.instance_name.clone(),
                txt_records: result.txt_records.clone(),
            });
            changed = true;
        }
    }

    if changed {
        device.add_source(DiscoveryMethod::Mdns);
    }

    changed
}

fn apply_apple_classification(device: &mut Device) {
    let services: Vec<String> = device
        .mdns_services
        .iter()
        .map(|service| service.service_type.clone())
        .collect();
    let mut all_txt: HashMap<String, String> = HashMap::new();
    for service in &device.mdns_services {
        all_txt.extend(service.txt_records.clone());
    }

    let model_id = all_txt.get("model").map(|s| s.as_str());
    let apple_info =
        apple::classify_apple_device(model_id, device.hostname.as_deref(), &services, &all_txt);
    if apple_info.confidence > device.confidence {
        device.vendor = Some(apple_info.brand);
        device.confidence = apple_info.confidence;
        if let Some(dt) = &apple_info.device_type {
            device.device_type = match dt.as_str() {
                "Phone" => DeviceType::Phone,
                "Tablet" => DeviceType::Tablet,
                "Computer" => DeviceType::Computer,
                "TV" => DeviceType::TV,
                "IoT" => DeviceType::IoT,
                _ => device.device_type,
            };
        }
        if let Some(name) = apple_info.marketing_name {
            device.model = Some(name);
        }
    }
}

async fn probe_apple_mobile_services(state: SharedState, ip: IpAddr) {
    let results =
        mdns::probe_services(mdns::APPLE_MOBILE_SERVICE_QUERIES, Duration::from_secs(2)).await;
    if results.is_empty() {
        return;
    }

    let mut s = state.lock().await;
    if let Some(device) = s.devices.get_mut(&ip) {
        let mut changed = false;
        for result in results {
            if result.ip == Some(ip) {
                changed |= merge_mdns_result(device, &result);
            }
        }
        if changed {
            apply_apple_classification(device);
        }
    }
}

/// Run the full scan orchestration
pub async fn run_scan(
    state: SharedState,
    shutdown: Arc<AtomicBool>,
    llm_config: llm::LlmGuessConfig,
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

    // Start sniffer in background if root — use full variant with LLDP/CDP + DHCP channels
    let sniffer_shutdown = shutdown.clone();
    let sniffer_state = state.clone();
    if priv_level == PrivilegeLevel::Root {
        let iface_name = iface.name.clone();
        let (sniff_tx, mut sniff_rx) = mpsc::channel::<SnifferEvent>(256);
        let (lldp_cdp_tx, mut lldp_cdp_rx) = mpsc::channel::<LldpCdpInfo>(64);
        let (dhcp_fp_tx, mut dhcp_fp_rx) = mpsc::channel::<DhcpFingerprint>(64);

        // Sniffer capture thread (blocking) — full variant
        std::thread::spawn(move || {
            crate::sniffer::capture::start_capture_full(
                &iface_name,
                sniff_tx,
                lldp_cdp_tx,
                dhcp_fp_tx,
                sniffer_shutdown,
            );
        });

        // Sniffer event consumer
        let sniff_state = sniffer_state.clone();
        tokio::spawn(async move {
            while let Some(event) = sniff_rx.recv().await {
                let mut s = sniff_state.lock().await;
                s.add_sniffer_event(event);
            }
        });

        // LLDP/CDP consumer — update device vendor/model/hostname
        let lldp_state = sniffer_state.clone();
        tokio::spawn(async move {
            while let Some(info) = lldp_cdp_rx.recv().await {
                let mut s = lldp_state.lock().await;
                // Try to find the device by management IP, otherwise by MAC
                let ip = if let Some(mgmt_ip) = info.management_ip {
                    Some(mgmt_ip)
                } else if let Some(mac) = info.source_mac {
                    s.devices
                        .iter()
                        .find(|(_, d)| d.mac == Some(mac))
                        .map(|(ip, _)| *ip)
                } else {
                    None
                };
                if let Some(ip) = ip {
                    let dev = s.get_or_create_device(ip);
                    if let Some(ref name) = info.system_name {
                        if dev.hostname.is_none() {
                            dev.hostname = Some(name.clone());
                        }
                    }
                    if let Some(ref desc) = info.system_description {
                        if dev.os.is_none() {
                            dev.os = Some(desc.clone());
                        }
                    }
                    if let Some(ref platform) = info.platform {
                        if dev.vendor.is_none() {
                            dev.vendor = Some(platform.clone());
                        }
                    }
                    dev.add_source(DiscoveryMethod::LldpCdp);
                }
            }
        });

        // DHCP fingerprint consumer — update device OS hint
        let dhcp_state = sniffer_state.clone();
        tokio::spawn(async move {
            while let Some(fp) = dhcp_fp_rx.recv().await {
                let mut s = dhcp_state.lock().await;
                let ip = IpAddr::V4(fp.source_ip);
                let dev = s.get_or_create_device(ip);
                if let Some(ref hostname) = fp.hostname {
                    if dev.hostname.is_none() {
                        dev.hostname = Some(hostname.clone());
                    }
                }
                let os_hint = crate::sniffer::parser::match_dhcp_fingerprint(
                    &fp.option55,
                    fp.vendor_class.as_deref(),
                );
                if let Some(os) = os_hint {
                    if dev.os.is_none() {
                        dev.os = Some(os);
                    }
                }
                dev.add_source(DiscoveryMethod::Dhcp);
            }
        });
    }

    // Start continuous mDNS listener
    let mdns_continuous_shutdown = shutdown.clone();
    let mdns_cont_state = state.clone();
    {
        let (mdns_cont_tx, mut mdns_cont_rx) = mpsc::channel::<mdns::MdnsResult>(256);
        tokio::spawn(async move {
            mdns::mdns_listen_continuous(mdns_cont_tx, mdns_continuous_shutdown).await;
        });

        let cont_state = mdns_cont_state.clone();
        tokio::spawn(async move {
            while let Some(result) = mdns_cont_rx.recv().await {
                let mut s = cont_state.lock().await;
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
                }
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
        s.devices
            .keys()
            .filter_map(|ip| {
                if let IpAddr::V4(v4) = ip {
                    Some(*v4)
                } else {
                    None
                }
            })
            .collect()
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

    // mDNS discovery (one-shot query)
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
                if merge_mdns_result(dev, &result) {
                    apply_apple_classification(dev);
                }
            }
        }
    });

    // SSDP discovery — collect location URLs for UPnP fetch
    let (ssdp_tx, mut ssdp_rx) = mpsc::channel::<ssdp::SsdpResult>(256);
    tokio::spawn(async move {
        ssdp::ssdp_discover(ssdp_tx).await;
    });

    let ssdp_state = state.clone();
    let ssdp_locations: Arc<Mutex<Vec<(IpAddr, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let ssdp_locs_clone = ssdp_locations.clone();
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
            // Collect location URLs for UPnP fetch
            if let Some(ref location) = result.location {
                let mut locs = ssdp_locs_clone.lock().await;
                locs.push((result.ip, location.clone()));
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

    // DNS PTR lookup — use first IP in subnet as DNS server (likely the gateway)
    let (dns_tx, mut dns_rx) = mpsc::channel::<dns::DnsResult>(256);
    let dns_targets = discovered_ips.clone();
    let dns_server = targets
        .first()
        .copied()
        .unwrap_or(Ipv4Addr::new(192, 168, 1, 1));
    tokio::spawn(async move {
        dns::reverse_dns_lookup(&dns_targets, dns_server, dns_tx).await;
    });

    let dns_state = state.clone();
    let dns_collector = tokio::spawn(async move {
        while let Some(result) = dns_rx.recv().await {
            let mut s = dns_state.lock().await;
            let dev = s.get_or_create_device(result.ip);
            if dev.hostname.is_none() {
                dev.hostname = Some(result.hostname);
            }
            dev.add_source(DiscoveryMethod::Dns);
        }
    });

    // SNMP queries
    let (snmp_tx, mut snmp_rx) = mpsc::channel::<snmp::SnmpResult>(256);
    let snmp_targets = discovered_ips.clone();
    tokio::spawn(async move {
        snmp::snmp_query(&snmp_targets, snmp_tx).await;
    });

    let snmp_state = state.clone();
    let snmp_collector = tokio::spawn(async move {
        while let Some(result) = snmp_rx.recv().await {
            let mut s = snmp_state.lock().await;
            let dev = s.get_or_create_device(result.ip);
            if let Some(ref desc) = result.sys_descr {
                if dev.os.is_none() {
                    dev.os = Some(desc.clone());
                }
            }
            if let Some(ref name) = result.sys_name {
                if dev.hostname.is_none() {
                    dev.hostname = Some(name.clone());
                }
            }
            dev.add_source(DiscoveryMethod::Snmp);
        }
    });

    // WSD discovery
    let (wsd_tx, mut wsd_rx) = mpsc::channel::<wsd::WsdResult>(256);
    tokio::spawn(async move {
        wsd::wsd_discover(wsd_tx).await;
    });

    let wsd_state = state.clone();
    let wsd_collector = tokio::spawn(async move {
        while let Some(result) = wsd_rx.recv().await {
            let mut s = wsd_state.lock().await;
            let dev = s.get_or_create_device(result.ip);
            if let Some(ref dt) = result.device_type {
                if dev.device_type == DeviceType::Unknown {
                    // Try to map WSD device type string
                    let dtl = dt.to_lowercase();
                    if dtl.contains("printer") {
                        dev.device_type = DeviceType::Printer;
                    } else if dtl.contains("computer") {
                        dev.device_type = DeviceType::Computer;
                    }
                }
            }
            if let Some(ref name) = result.friendly_name {
                if dev.hostname.is_none() {
                    dev.hostname = Some(name.clone());
                }
            }
            dev.add_source(DiscoveryMethod::Wsd);
        }
    });

    // Wait for phase 2 to complete
    let _ = tokio::join!(
        port_collector,
        mdns_collector,
        ssdp_collector,
        nb_collector,
        dns_collector,
        snmp_collector,
        wsd_collector,
    );

    // UPnP XML fetch using collected SSDP location URLs
    {
        let locations = ssdp_locations.lock().await.clone();
        if !locations.is_empty() {
            let (upnp_tx, mut upnp_rx) = mpsc::channel::<upnp::UpnpDeviceInfo>(256);
            tokio::spawn(async move {
                upnp::upnp_fetch(&locations, upnp_tx).await;
            });

            let upnp_state = state.clone();
            while let Some(info) = upnp_rx.recv().await {
                let mut s = upnp_state.lock().await;
                let dev = s.get_or_create_device(info.ip);
                if let Some(ref mfr) = info.manufacturer {
                    if dev.vendor.is_none() {
                        dev.vendor = Some(mfr.clone());
                    }
                }
                if let Some(ref model) = info.model_name {
                    if dev.model.is_none() {
                        dev.model = Some(model.clone());
                    }
                }
                if let Some(ref name) = info.friendly_name {
                    if dev.hostname.is_none() {
                        dev.hostname = Some(name.clone());
                    }
                }
                dev.add_source(DiscoveryMethod::Upnp);
            }
        }
    }

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
        s.devices
            .iter()
            .filter_map(|(ip, dev)| {
                let open: Vec<u16> = dev
                    .ports
                    .iter()
                    .filter(|p| p.state == PortState::Open)
                    .map(|p| p.port)
                    .collect();
                if open.is_empty() {
                    None
                } else {
                    Some((*ip, open))
                }
            })
            .collect()
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

    // SMB enumeration on hosts with port 445 open
    let smb_hosts: Vec<IpAddr> = hosts_with_ports
        .iter()
        .filter(|(_, ports)| ports.contains(&445))
        .map(|(ip, _)| *ip)
        .collect();

    let (smb_tx, mut smb_rx) = mpsc::channel::<smb::SmbResult>(256);
    for &ip in &smb_hosts {
        let tx = smb_tx.clone();
        tokio::spawn(async move {
            smb::smb_enumerate(ip, tx).await;
        });
    }
    drop(smb_tx);

    let smb_state = state.clone();
    let smb_collector = tokio::spawn(async move {
        while let Some(result) = smb_rx.recv().await {
            let mut s = smb_state.lock().await;
            let dev = s.get_or_create_device(result.ip);
            if let Some(ref os_ver) = result.os_version {
                if dev.os.is_none() {
                    dev.os = Some(os_ver.clone());
                }
            }
            if let Some(ref name) = result.computer_name {
                if dev.hostname.is_none() {
                    dev.hostname = Some(name.clone());
                }
            }
            dev.add_source(DiscoveryMethod::Smb);
        }
    });

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

    let _ = tokio::join!(banner_collector, smb_collector, port2_collector);

    // Apply SSH banner classification to devices with SSH banners
    {
        let mut s = state.lock().await;
        let ips: Vec<IpAddr> = s.devices.keys().cloned().collect();
        for ip in ips {
            if let Some(dev) = s.devices.get_mut(&ip) {
                device_type::apply_ssh_classification(dev);
            }
        }
    }

    // Re-classify devices with banner data now available
    {
        let mut s = state.lock().await;
        let ips: Vec<IpAddr> = s.devices.keys().cloned().collect();
        for ip in ips {
            if let Some(dev) = s.devices.get_mut(&ip) {
                device_type::classify_device(dev);
            }
        }
    }

    if llm_config.enabled && !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        apply_llm_best_guesses(state.clone(), &llm_config).await;
    }

    // Mark complete
    {
        let mut s = state.lock().await;
        s.phase = ScanPhase::Complete;
        for dev in s.devices.values_mut() {
            dev.scan_state = DeviceScanState::Done;
        }
    }
}

async fn apply_llm_best_guesses(state: SharedState, llm_config: &llm::LlmGuessConfig) {
    let candidates: Vec<Device> = {
        let s = state.lock().await;
        s.devices
            .values()
            .filter(|device| llm::needs_llm_guess(device))
            .cloned()
            .collect()
    };

    if candidates.is_empty() {
        return;
    }

    for candidate in candidates {
        match llm::guess_device(&candidate, llm_config).await {
            Ok(Some(guess)) => {
                let mut s = state.lock().await;
                if let Some(device) = s.devices.get_mut(&candidate.ip) {
                    llm::apply_guess(device, guess);
                }
            }
            Ok(None) => {}
            Err(err) => {
                eprintln!("LLM best guess skipped for {}: {}", candidate.ip, err);
                break;
            }
        }
    }
}

pub async fn deep_scan_device(state: SharedState, ip: IpAddr, llm_config: llm::LlmGuessConfig) {
    let ipv4 = match ip {
        IpAddr::V4(ipv4) => ipv4,
        _ => {
            let mut s = state.lock().await;
            if let Some(device) = s.devices.get_mut(&ip) {
                device.scan_state = DeviceScanState::Done;
            }
            return;
        }
    };

    let (port_tx, mut port_rx) = mpsc::channel::<ports::PortScanResult>(512);
    let top1000 = ports::top_1000_ports();
    let port_task = tokio::spawn(async move {
        ports::scan_ports(ipv4, &top1000, port_tx, 1500, 100).await;
    });

    while let Some(result) = port_rx.recv().await {
        let mut s = state.lock().await;
        if let Some(dev) = s.devices.get_mut(&result.ip) {
            if !dev.ports.iter().any(|p| p.port == result.port_info.port) {
                dev.ports.push(result.port_info);
                dev.ports.sort_by_key(|p| p.port);
            }
            dev.add_source(DiscoveryMethod::TcpConnect);
        }
    }
    let _ = port_task.await;

    let open_ports = {
        let s = state.lock().await;
        s.devices
            .get(&ip)
            .map(|dev| {
                dev.ports
                    .iter()
                    .filter(|p| p.state == PortState::Open)
                    .map(|p| p.port)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };

    let mut apple_probe_attempted = false;
    let should_probe_apple = {
        let s = state.lock().await;
        s.devices
            .get(&ip)
            .map(apple::should_probe_mobile_services)
            .unwrap_or(false)
    };
    if should_probe_apple {
        probe_apple_mobile_services(state.clone(), ip).await;
        apple_probe_attempted = true;
    }

    let (banner_tx, mut banner_rx) = mpsc::channel::<banner::BannerResult>(256);
    let banner_task = if open_ports.is_empty() {
        drop(banner_tx);
        None
    } else {
        let banner_ports = open_ports.clone();
        Some(tokio::spawn(async move {
            banner::grab_banners(ip, &banner_ports, banner_tx).await;
        }))
    };

    let os_task = open_ports
        .first()
        .copied()
        .map(|port| tokio::spawn(async move { os_fp::fingerprint_os(ip, port).await }));

    let smb_task = if open_ports.contains(&445) {
        let (smb_tx, smb_rx) = mpsc::channel::<smb::SmbResult>(1);
        let task = tokio::spawn(async move {
            smb::smb_enumerate(ip, smb_tx).await;
        });
        Some((task, smb_rx))
    } else {
        None
    };

    while let Some(result) = banner_rx.recv().await {
        let mut s = state.lock().await;
        if let Some(dev) = s.devices.get_mut(&result.ip) {
            if let Some(port_info) = dev.ports.iter_mut().find(|p| p.port == result.port) {
                port_info.banner = Some(result.banner);
                port_info.version = result.version;
            }
            dev.add_source(DiscoveryMethod::Banner);
        }
    }

    if let Some(task) = banner_task {
        let _ = task.await;
    }

    if let Some(task) = os_task {
        if let Ok(Some(result)) = task.await {
            let mut s = state.lock().await;
            if let Some(dev) = s.devices.get_mut(&result.ip) {
                if dev.os.is_none() {
                    dev.os = result.os_guess;
                }
                dev.add_source(DiscoveryMethod::OsFp);
            }
        }
    }

    if let Some((task, mut smb_rx)) = smb_task {
        while let Some(result) = smb_rx.recv().await {
            let mut s = state.lock().await;
            let dev = s.get_or_create_device(result.ip);
            if let Some(ref os_ver) = result.os_version {
                if dev.os.is_none() {
                    dev.os = Some(os_ver.clone());
                }
            }
            if let Some(ref name) = result.computer_name {
                if dev.hostname.is_none() {
                    dev.hostname = Some(name.clone());
                }
            }
            dev.add_source(DiscoveryMethod::Smb);
        }
        let _ = task.await;
    }

    if !apple_probe_attempted {
        let should_probe_apple = {
            let s = state.lock().await;
            s.devices
                .get(&ip)
                .map(apple::should_probe_mobile_services)
                .unwrap_or(false)
        };
        if should_probe_apple {
            probe_apple_mobile_services(state.clone(), ip).await;
        }
    }

    {
        let mut s = state.lock().await;
        if let Some(dev) = s.devices.get_mut(&ip) {
            device_type::apply_ssh_classification(dev);
            device_type::classify_device(dev);
        }
    }

    if llm_config.enabled {
        let maybe_device = {
            let s = state.lock().await;
            s.devices.get(&ip).cloned()
        };
        if let Some(device) = maybe_device {
            if let Ok(Some(guess)) = llm::guess_device(&device, &llm_config).await {
                let mut s = state.lock().await;
                if let Some(dev) = s.devices.get_mut(&ip) {
                    llm::apply_guess(dev, guess);
                }
            }
        }
    }

    let mut s = state.lock().await;
    if let Some(device) = s.devices.get_mut(&ip) {
        device.scan_state = DeviceScanState::Done;
    }
}

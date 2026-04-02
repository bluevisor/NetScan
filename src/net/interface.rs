use ipnetwork::Ipv4Network;
use pnet_datalink::{self};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub ip: Ipv4Addr,
    pub mac: pnet::util::MacAddr,
    pub network: Ipv4Network,
}

pub fn list_interfaces() -> Vec<InterfaceInfo> {
    let mut results = Vec::new();
    for iface in pnet_datalink::interfaces() {
        if iface.is_loopback() || !iface.is_up() || !iface.is_running() {
            continue;
        }
        let mac = match iface.mac {
            Some(m) if m != pnet::util::MacAddr::zero() => m,
            _ => continue,
        };
        for ip_net in &iface.ips {
            if let IpAddr::V4(ipv4) = ip_net.ip() {
                if ipv4.is_loopback() || ipv4.is_link_local() {
                    continue;
                }
                if let Ok(network) = Ipv4Network::new(ipv4, ip_net.prefix()) {
                    results.push(InterfaceInfo {
                        name: iface.name.clone(),
                        ip: ipv4,
                        mac,
                        network,
                    });
                }
            }
        }
    }
    results
}

pub fn pick_interface(name: Option<&str>) -> Option<InterfaceInfo> {
    let interfaces = list_interfaces();
    if let Some(name) = name {
        interfaces.into_iter().find(|i| i.name == name)
    } else {
        interfaces.into_iter().next()
    }
}

pub fn subnet_hosts(network: Ipv4Network) -> Vec<Ipv4Addr> {
    network
        .iter()
        .filter(|ip| *ip != network.network() && *ip != network.broadcast())
        .collect()
}

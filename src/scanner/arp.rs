use std::net::Ipv4Addr;
use std::time::Duration;

use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use pnet_datalink::{self, Channel};
use tokio::sync::mpsc;
use tokio::time;

use crate::net::interface::InterfaceInfo;

#[derive(Debug, Clone)]
pub struct ArpResult {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
}

/// Perform ARP sweep on the subnet. Sends ARP requests and collects replies.
/// This requires root privileges.
pub async fn arp_scan(
    iface: &InterfaceInfo,
    targets: &[Ipv4Addr],
    tx: mpsc::Sender<ArpResult>,
) {
    let interface = pnet_datalink::interfaces()
        .into_iter()
        .find(|i| i.name == iface.name)
        .expect("Interface not found");

    let (mut sender, mut receiver) = match pnet_datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            eprintln!("Unsupported channel type");
            return;
        }
        Err(e) => {
            eprintln!("Failed to create datalink channel: {}", e);
            return;
        }
    };

    let source_mac = iface.mac;
    let source_ip = iface.ip;

    // Send ARP requests for all targets
    for &target_ip in targets {
        let mut eth_buf = [0u8; 42]; // 14 ethernet + 28 ARP
        {
            let mut eth_pkt = MutableEthernetPacket::new(&mut eth_buf).unwrap();
            eth_pkt.set_destination(MacAddr::broadcast());
            eth_pkt.set_source(source_mac);
            eth_pkt.set_ethertype(EtherTypes::Arp);

            let mut arp_buf = [0u8; 28];
            {
                let mut arp_pkt = MutableArpPacket::new(&mut arp_buf).unwrap();
                arp_pkt.set_hardware_type(ArpHardwareTypes::Ethernet);
                arp_pkt.set_protocol_type(EtherTypes::Ipv4);
                arp_pkt.set_hw_addr_len(6);
                arp_pkt.set_proto_addr_len(4);
                arp_pkt.set_operation(ArpOperations::Request);
                arp_pkt.set_sender_hw_addr(source_mac);
                arp_pkt.set_sender_proto_addr(source_ip);
                arp_pkt.set_target_hw_addr(MacAddr::zero());
                arp_pkt.set_target_proto_addr(target_ip);
            }
            eth_pkt.payload_mut().copy_from_slice(&arp_buf);
        }

        if sender.send_to(&eth_buf, None).is_none() {
            // Channel may be closed
            return;
        }

        // Small delay between sends to avoid flooding
        tokio::time::sleep(Duration::from_micros(100)).await;
    }

    // Collect ARP replies for up to 3 seconds
    let deadline = time::Instant::now() + Duration::from_secs(3);

    loop {
        if time::Instant::now() >= deadline {
            break;
        }

        match receiver.next() {
            Ok(packet) => {
                let eth = pnet::packet::ethernet::EthernetPacket::new(packet);
                if let Some(eth) = eth {
                    if eth.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = ArpPacket::new(eth.payload()) {
                            if arp.get_operation() == ArpOperations::Reply {
                                let result = ArpResult {
                                    ip: arp.get_sender_proto_addr(),
                                    mac: arp.get_sender_hw_addr(),
                                };
                                let _ = tx.send(result).await;
                            }
                        }
                    }
                }
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

/// Fallback for non-root: TCP connect to common ports to discover hosts
pub async fn ping_sweep(
    targets: &[Ipv4Addr],
    tx: mpsc::Sender<Ipv4Addr>,
) {
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(100));

    let mut handles = Vec::new();
    for &target in targets {
        let tx = tx.clone();
        let sem = semaphore.clone();
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            // Try connecting to port 80 or 443
            let addrs = [
                std::net::SocketAddr::new(std::net::IpAddr::V4(target), 80),
                std::net::SocketAddr::new(std::net::IpAddr::V4(target), 443),
            ];
            for addr in &addrs {
                match tokio::time::timeout(
                    Duration::from_millis(500),
                    tokio::net::TcpStream::connect(addr),
                ).await {
                    Ok(Ok(_)) => {
                        let _ = tx.send(target).await;
                        return;
                    }
                    _ => continue,
                }
            }
        });
        handles.push(handle);
    }

    for h in handles {
        let _ = h.await;
    }
}

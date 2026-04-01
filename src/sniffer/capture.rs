use std::sync::Arc;

use pnet_datalink::{self, Channel};
use tokio::sync::mpsc;

use crate::model::SnifferEvent;
use super::parser::{self, LldpCdpInfo, DhcpFingerprint};

/// Start passive packet capture on the given interface (simple variant — no extra channels).
/// Runs in a blocking thread (pnet datalink is synchronous).
/// Requires root privileges.
pub fn start_capture(
    interface_name: &str,
    tx: mpsc::Sender<SnifferEvent>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) {
    // Create dummy channels that are immediately dropped so sends are silently discarded.
    let (lldp_cdp_tx, _lldp_cdp_rx) = mpsc::channel::<LldpCdpInfo>(32);
    let (dhcp_fp_tx, _dhcp_fp_rx) = mpsc::channel::<DhcpFingerprint>(32);
    start_capture_full(interface_name, tx, lldp_cdp_tx, dhcp_fp_tx, shutdown);
}

/// Full variant with separate channels for LLDP/CDP info and DHCP fingerprints.
pub fn start_capture_full(
    interface_name: &str,
    tx: mpsc::Sender<SnifferEvent>,
    lldp_cdp_tx: mpsc::Sender<LldpCdpInfo>,
    _dhcp_fp_tx: mpsc::Sender<DhcpFingerprint>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) {
    let interface = pnet_datalink::interfaces()
        .into_iter()
        .find(|i| i.name == interface_name)
        .expect("Sniffer: interface not found");

    let (_sender, mut receiver) = match pnet_datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => {
            eprintln!("Sniffer: failed to open channel");
            return;
        }
    };

    while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        match receiver.next() {
            Ok(packet) => {
                let (events, lldp_cdp) = parser::parse_ethernet_frame(packet);
                for event in events {
                    if tx.blocking_send(event).is_err() {
                        return; // Channel closed
                    }
                }
                if let Some(info) = lldp_cdp {
                    let _ = lldp_cdp_tx.blocking_send(info);
                }
            }
            Err(_) => continue,
        }
    }
}

use std::sync::Arc;

use pnet_datalink::{self, Channel};
use tokio::sync::mpsc;

use crate::model::SnifferEvent;
use super::parser;

/// Start passive packet capture on the given interface.
/// Runs in a blocking thread (pnet datalink is synchronous).
/// Requires root privileges.
pub fn start_capture(
    interface_name: &str,
    tx: mpsc::Sender<SnifferEvent>,
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
                let events = parser::parse_ethernet_frame(packet);
                for event in events {
                    if tx.blocking_send(event).is_err() {
                        return; // Channel closed
                    }
                }
            }
            Err(_) => continue,
        }
    }
}

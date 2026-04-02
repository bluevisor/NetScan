use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::sync::mpsc;

use crate::model::{port_service_name, PortInfo, PortState, Protocol, TOP_100_PORTS};

#[derive(Debug, Clone)]
pub struct PortScanResult {
    pub ip: IpAddr,
    pub port_info: PortInfo,
}

/// Scan a list of ports on a single host using TCP connect
pub async fn scan_ports(
    ip: Ipv4Addr,
    ports: &[u16],
    tx: mpsc::Sender<PortScanResult>,
    timeout_ms: u64,
    concurrency: usize,
) {
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));

    let mut handles = Vec::new();
    for &port in ports {
        let tx = tx.clone();
        let sem = semaphore.clone();
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let addr = SocketAddr::new(IpAddr::V4(ip), port);

            let state = match tokio::time::timeout(
                Duration::from_millis(timeout_ms),
                tokio::net::TcpStream::connect(&addr),
            )
            .await
            {
                Ok(Ok(_stream)) => PortState::Open,
                Ok(Err(_)) => PortState::Closed,
                Err(_) => PortState::Filtered,
            };

            if state == PortState::Open {
                let result = PortScanResult {
                    ip: IpAddr::V4(ip),
                    port_info: PortInfo {
                        port,
                        protocol: Protocol::Tcp,
                        state,
                        service: port_service_name(port).map(String::from),
                        banner: None,
                        version: None,
                    },
                };
                let _ = tx.send(result).await;
            }
        });
        handles.push(handle);
    }

    for h in handles {
        let _ = h.await;
    }
}

/// Generate the "top 1000" port list (top 100 + next most common)
pub fn top_1000_ports() -> Vec<u16> {
    let mut ports: Vec<u16> = TOP_100_PORTS.to_vec();
    // Add additional well-known ports not in top 100
    let additional: Vec<u16> = (1..=1024)
        .chain(
            [
                1080, 1099, 1194, 1434, 1521, 1583, 1604, 1701, 1883, 2082, 2083, 2086, 2087, 2181,
                2222, 2375, 2376, 3268, 3269, 3300, 3301, 3307, 3310, 3333, 3478, 4000, 4040, 4443,
                4444, 4567, 4711, 4712, 4848, 4993, 4994, 5002, 5003, 5004, 5005, 5006, 5007, 5008,
                5010, 5050, 5100, 5222, 5269, 5280, 5500, 5555, 5601, 5672, 5683, 5901, 5984, 5985,
                5986, 6379, 6443, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 6881,
                6882, 6883, 6969, 7000, 7001, 7002, 7443, 7474, 7547, 7777, 7778, 8000, 8001, 8002,
                8003, 8004, 8005, 8006, 8010, 8042, 8060, 8069, 8082, 8083, 8084, 8085, 8086, 8087,
                8088, 8089, 8090, 8091, 8118, 8123, 8180, 8181, 8200, 8222, 8291, 8333, 8334, 8400,
                8444, 8500, 8600, 8686, 8787, 8800, 8880, 8883, 8899, 8983, 9000, 9001, 9002, 9003,
                9042, 9043, 9060, 9080, 9090, 9091, 9092, 9093, 9110, 9111, 9160, 9191, 9200, 9300,
                9418, 9443, 9500, 9595, 9600, 9800, 9876, 9981, 9982, 9998, 10001, 10010, 10080,
                10250, 10443, 11211, 11300, 12345, 15672, 16010, 16080, 18080, 19132, 20000, 25565,
                27017, 27018, 28017, 50000, 50070, 62078,
            ]
            .iter()
            .copied(),
        )
        .filter(|p| !ports.contains(p))
        .collect();
    ports.extend(additional);
    ports.sort();
    ports.dedup();
    ports
}

/// Generate full 65535 port range minus already-scanned ports
pub fn remaining_ports(already_scanned: &[u16]) -> Vec<u16> {
    (1..=65535u16)
        .filter(|p| !already_scanned.contains(p))
        .collect()
}

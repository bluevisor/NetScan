use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const WSD_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const WSD_PORT: u16 = 3702;

#[derive(Debug, Clone)]
pub struct WsdResult {
    pub ip: IpAddr,
    pub device_type: Option<String>,
    pub friendly_name: Option<String>,
}

pub async fn wsd_discover(tx: mpsc::Sender<WsdResult>) {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return,
    };

    let probe = build_wsd_probe();
    let dest = SocketAddr::new(IpAddr::V4(WSD_ADDR), WSD_PORT);
    let _ = socket.send_to(probe.as_bytes(), dest).await;

    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);

    loop {
        match tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, src))) => {
                if let Ok(response) = std::str::from_utf8(&buf[..len]) {
                    let result = parse_wsd_response(response, src.ip());
                    let _ = tx.send(result).await;
                }
            }
            _ => break,
        }
    }
}

fn build_wsd_probe() -> String {
    // WS-Discovery Probe message using a static UUID
    let uuid = "a8c96b42-1e76-4c78-9b23-3f5d2a0e6c19";
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
  xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <soap:Header>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
    <wsa:MessageID>urn:uuid:{}</wsa:MessageID>
  </soap:Header>
  <soap:Body>
    <wsd:Probe>
      <wsd:Types/>
    </wsd:Probe>
  </soap:Body>
</soap:Envelope>"#,
        uuid
    )
}

fn parse_wsd_response(response: &str, ip: IpAddr) -> WsdResult {
    // Extract device type from <wsd:Types> or <d:Types>
    let device_type = extract_xml_tag_any(response, &["wsd:Types", "d:Types", "Types"]);

    // Extract friendly name or endpoint address from <wsa:Address> or <wsd:XAddrs>
    let friendly_name = extract_xml_tag_any(
        response,
        &["wsd:XAddrs", "d:XAddrs", "wsa:Address", "wsdd:Name", "Name"],
    );

    WsdResult {
        ip,
        device_type,
        friendly_name,
    }
}

fn extract_xml_tag_any(xml: &str, tags: &[&str]) -> Option<String> {
    for &tag in tags {
        let open = format!("<{}>", tag);
        let close = format!("</{}>", tag);
        if let Some(start) = xml.find(&open) {
            let content_start = start + open.len();
            if let Some(end) = xml[content_start..].find(&close) {
                let value = xml[content_start..content_start + end].trim().to_string();
                if !value.is_empty() {
                    return Some(value);
                }
            }
        }
    }
    None
}

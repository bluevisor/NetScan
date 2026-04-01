use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct UpnpDeviceInfo {
    pub ip: IpAddr,
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub model_description: Option<String>,
    pub device_type: Option<String>,
}

pub async fn upnp_fetch(targets: &[(IpAddr, String)], tx: mpsc::Sender<UpnpDeviceInfo>) {
    for (ip, location_url) in targets {
        if let Some(info) = fetch_upnp_device(*ip, location_url).await {
            let _ = tx.send(info).await;
        }
    }
}

async fn fetch_upnp_device(ip: IpAddr, location_url: &str) -> Option<UpnpDeviceInfo> {
    // Parse the URL: http://host:port/path
    let url = location_url.trim();
    let without_scheme = url.strip_prefix("http://")?;
    let (host_port, path) = if let Some(slash) = without_scheme.find('/') {
        (&without_scheme[..slash], &without_scheme[slash..])
    } else {
        (without_scheme, "/")
    };

    let (host, port) = if let Some(colon) = host_port.rfind(':') {
        let port: u16 = host_port[colon + 1..].parse().ok()?;
        (&host_port[..colon], port)
    } else {
        (host_port, 80u16)
    };

    let addr: SocketAddr = format!("{}:{}", host, port).parse().ok()?;

    let mut stream = match tokio::time::timeout(
        Duration::from_secs(3),
        TcpStream::connect(addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        path, host, port
    );

    if stream.write_all(request.as_bytes()).await.is_err() {
        return None;
    }

    let mut response = String::new();
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        stream.read_to_string(&mut response),
    )
    .await;

    // Find body after headers
    let body = if let Some(pos) = response.find("\r\n\r\n") {
        &response[pos + 4..]
    } else if let Some(pos) = response.find("\n\n") {
        &response[pos + 2..]
    } else {
        &response
    };

    Some(UpnpDeviceInfo {
        ip,
        friendly_name: extract_xml_tag(body, "friendlyName"),
        manufacturer: extract_xml_tag(body, "manufacturer"),
        model_name: extract_xml_tag(body, "modelName"),
        model_description: extract_xml_tag(body, "modelDescription"),
        device_type: extract_xml_tag(body, "deviceType"),
    })
}

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)?;
    let value = xml[start..start + end].trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct TlsFpResult {
    pub ip: IpAddr,
    pub port: u16,
    pub server_hello_version: Option<String>,
    pub cipher_suite: Option<String>,
}

/// Connect to a TLS port and extract basic info from ServerHello
/// Full JA3 would require intercepting the ClientHello from the sniffer
pub async fn tls_probe(ip: IpAddr, port: u16) -> Option<TlsFpResult> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr))
        .await
        .ok()?
        .ok()?;

    // Send a minimal TLS ClientHello
    let client_hello = build_minimal_client_hello();
    stream.write_all(&client_hello).await.ok()?;

    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n < 7 {
        return None;
    }

    // Parse TLS record header
    let content_type = buf[0];
    if content_type != 0x16 {
        // Handshake
        return None;
    }

    let tls_version = u16::from_be_bytes([buf[1], buf[2]]);
    let version_str = match tls_version {
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "Unknown",
    };

    // ServerHello starts at offset 5 (after record header)
    let handshake_type = buf[5];
    if handshake_type != 0x02 {
        // ServerHello
        return None;
    }

    // Cipher suite is at a known offset in ServerHello
    // Skip: handshake header (4) + server version (2) + random (32) + session_id_len + session_id
    let mut offset = 9; // 5 (record) + 4 (handshake header)
    offset += 2; // server version
    offset += 32; // random

    if offset >= n {
        return None;
    }
    let session_id_len = buf[offset] as usize;
    offset += 1 + session_id_len;

    if offset + 2 > n {
        return None;
    }
    let cipher = u16::from_be_bytes([buf[offset], buf[offset + 1]]);

    Some(TlsFpResult {
        ip,
        port,
        server_hello_version: Some(version_str.to_string()),
        cipher_suite: Some(format!("0x{:04X}", cipher)),
    })
}

fn build_minimal_client_hello() -> Vec<u8> {
    // Minimal TLS 1.2 ClientHello
    let mut hello = Vec::new();

    // TLS Record Header
    hello.push(0x16); // Content Type: Handshake
    hello.extend_from_slice(&[0x03, 0x01]); // Version: TLS 1.0 (for compat)

    // We'll fill in the length later
    let record_len_pos = hello.len();
    hello.extend_from_slice(&[0x00, 0x00]); // placeholder

    // Handshake Header
    hello.push(0x01); // ClientHello
    let handshake_len_pos = hello.len();
    hello.extend_from_slice(&[0x00, 0x00, 0x00]); // placeholder

    // Client Version: TLS 1.2
    hello.extend_from_slice(&[0x03, 0x03]);

    // Random: 32 bytes
    hello.extend_from_slice(&[0x00; 32]);

    // Session ID: 0 length
    hello.push(0x00);

    // Cipher Suites
    let ciphers: &[u16] = &[
        0x1301, 0x1302, 0x1303, // TLS 1.3
        0xC02C, 0xC02B, 0xC030, 0xC02F, // ECDHE
        0x009F, 0x009E, 0x006B, 0x0067, // DHE
        0x00FF, // renegotiation_info
    ];
    hello.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
    for &c in ciphers {
        hello.extend_from_slice(&c.to_be_bytes());
    }

    // Compression: null only
    hello.push(0x01);
    hello.push(0x00);

    // Extensions: SNI placeholder
    hello.extend_from_slice(&[0x00, 0x05]); // extensions length
    // Supported versions extension (minimal)
    hello.extend_from_slice(&[0x00, 0x2B]); // extension type
    hello.extend_from_slice(&[0x00, 0x01]); // length
    hello.push(0x00); // empty for brevity

    // Fix lengths
    let handshake_len = hello.len() - handshake_len_pos - 3;
    hello[handshake_len_pos] = ((handshake_len >> 16) & 0xFF) as u8;
    hello[handshake_len_pos + 1] = ((handshake_len >> 8) & 0xFF) as u8;
    hello[handshake_len_pos + 2] = (handshake_len & 0xFF) as u8;

    let record_len = hello.len() - record_len_pos - 2;
    hello[record_len_pos] = ((record_len >> 8) & 0xFF) as u8;
    hello[record_len_pos + 1] = (record_len & 0xFF) as u8;

    hello
}

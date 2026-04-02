use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct SmbResult {
    pub ip: IpAddr,
    pub os_version: Option<String>,
    pub computer_name: Option<String>,
    pub domain: Option<String>,
}

/// Connect to port 445, send an SMB1 Negotiate request, and parse the response
/// to extract OS version, computer name, and domain.
pub async fn smb_enumerate(ip: IpAddr, tx: mpsc::Sender<SmbResult>) {
    let addr = SocketAddr::new(ip, 445);
    let mut stream =
        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return,
        };

    // Build SMB1 Negotiate request
    let packet = build_smb1_negotiate();

    if stream.write_all(&packet).await.is_err() {
        return;
    }

    // Read response — NetBIOS header (4 bytes) + SMB data
    let mut header = [0u8; 4];
    if tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut header))
        .await
        .is_err()
    {
        return;
    }
    if header[0] != 0x00 {
        return; // Not a session message
    }
    let body_len = u32::from_be_bytes(header) as usize & 0x00FFFFFF;
    if body_len == 0 || body_len > 65536 {
        return;
    }

    let mut body = vec![0u8; body_len];
    if tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut body))
        .await
        .is_err()
    {
        return;
    }

    let result = parse_smb1_negotiate_response(&body, ip);
    if let Some(r) = result {
        let _ = tx.send(r).await;
    }
}

/// Build a minimal SMB1 Negotiate Protocol request wrapped in a NetBIOS Session header.
fn build_smb1_negotiate() -> Vec<u8> {
    // Dialect: "\x02NT LM 0.12\x00"
    let dialect: &[u8] = b"\x02NT LM 0.12\x00";

    // SMB header (32 bytes) + parameters (WordCount=0, 1 byte) +
    // ByteCount (2 bytes) + dialect
    let word_count: u8 = 0;
    let byte_count = dialect.len() as u16;

    let mut smb: Vec<u8> = Vec::new();
    // Protocol magic
    smb.extend_from_slice(&[0xFF, b'S', b'M', b'B']);
    // Command: Negotiate (0x72)
    smb.push(0x72);
    // NT Status (4 bytes)
    smb.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // Flags
    smb.push(0x18);
    // Flags2
    smb.extend_from_slice(&[0x53, 0xC8]);
    // Process ID High
    smb.extend_from_slice(&[0x00, 0x00]);
    // Signature (8 bytes)
    smb.extend_from_slice(&[0x00; 8]);
    // Reserved
    smb.extend_from_slice(&[0x00, 0x00]);
    // TreeID
    smb.extend_from_slice(&[0x00, 0x00]);
    // ProcessID
    smb.extend_from_slice(&[0x01, 0x00]);
    // UserID
    smb.extend_from_slice(&[0x00, 0x00]);
    // MultiplexID
    smb.extend_from_slice(&[0x40, 0x00]);
    // WordCount
    smb.push(word_count);
    // ByteCount
    smb.extend_from_slice(&byte_count.to_le_bytes());
    // Dialect
    smb.extend_from_slice(dialect);

    // NetBIOS Session Service header: type=0x00, length (3 bytes big-endian)
    let smb_len = smb.len() as u32;
    let mut packet = vec![
        0x00,
        ((smb_len >> 16) & 0xFF) as u8,
        ((smb_len >> 8) & 0xFF) as u8,
        (smb_len & 0xFF) as u8,
    ];
    packet.extend_from_slice(&smb);
    packet
}

/// Parse an SMB1 Negotiate response body (after NetBIOS header stripped).
/// Returns OS version, computer name, domain from the null-terminated UTF-16LE
/// strings in the ByteCount area.
fn parse_smb1_negotiate_response(body: &[u8], ip: IpAddr) -> Option<SmbResult> {
    // Must start with \xFF SMB
    if body.len() < 4 || body[0] != 0xFF || &body[1..4] != b"SMB" {
        return None;
    }
    // Command must be 0x72 (Negotiate)
    if body[4] != 0x72 {
        return None;
    }
    // NT Status
    let status = u32::from_le_bytes([body[5], body[6], body[7], body[8]]);
    if status != 0 {
        return None;
    }

    // SMB header is 32 bytes; after that: WordCount (1 byte)
    if body.len() < 33 {
        return None;
    }
    let word_count = body[32] as usize;
    // Parameters: word_count * 2 bytes
    let params_end = 33 + word_count * 2;
    if params_end + 2 > body.len() {
        return None;
    }
    let byte_count = u16::from_le_bytes([body[params_end], body[params_end + 1]]) as usize;
    let data_start = params_end + 2;
    if data_start + byte_count > body.len() {
        return None;
    }

    let data = &body[data_start..data_start + byte_count];

    // The byte-count area for a successful SMB1 Negotiate (no extended security)
    // contains: SecurityBlob or null-terminated UTF-16LE strings:
    // NativeOS, NativeLanMan, PrimaryDomain
    //
    // With extended security flag the layout differs; we attempt both.
    // Try reading three consecutive UTF-16LE null-terminated strings.
    let strings = read_utf16le_strings(data, 3);

    let os_version = strings.get(0).cloned().filter(|s| !s.is_empty());
    let computer_name = strings.get(1).cloned().filter(|s| !s.is_empty());
    let domain = strings.get(2).cloned().filter(|s| !s.is_empty());

    Some(SmbResult {
        ip,
        os_version,
        computer_name,
        domain,
    })
}

/// Read up to `max` null-terminated UTF-16LE strings from a byte slice.
fn read_utf16le_strings(data: &[u8], max: usize) -> Vec<String> {
    let mut results = Vec::new();
    let mut i = 0;

    while results.len() < max && i + 1 < data.len() {
        // Find the next \x00\x00 pair (null terminator for UTF-16LE)
        let mut end = i;
        loop {
            if end + 1 >= data.len() {
                end = data.len();
                break;
            }
            if data[end] == 0x00 && data[end + 1] == 0x00 {
                break;
            }
            end += 2;
        }

        let chunk = &data[i..end];
        // Decode UTF-16LE
        let u16_chars: Vec<u16> = chunk
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let s = String::from_utf16_lossy(&u16_chars);
        results.push(s.to_string());

        // Skip past the null terminator
        i = end + 2;
    }

    results
}

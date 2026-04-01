use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const SNMP_PORT: u16 = 161;

#[derive(Debug, Clone)]
pub struct SnmpResult {
    pub ip: IpAddr,
    pub sys_descr: Option<String>,
    pub sys_name: Option<String>,
}

pub async fn snmp_query(targets: &[Ipv4Addr], tx: mpsc::Sender<SnmpResult>) {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return,
    };

    // OIDs: sysDescr (1.3.6.1.2.1.1.1.0) and sysName (1.3.6.1.2.1.1.5.0)
    let sys_descr_oid: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
    let sys_name_oid: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];

    for (i, &target) in targets.iter().enumerate() {
        let txid = i as u16;
        let query = build_snmp_get(txid, "public", &[sys_descr_oid, sys_name_oid]);
        let dest = SocketAddr::new(IpAddr::V4(target), SNMP_PORT);
        let _ = socket.send_to(&query, dest).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let mut buf = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);

    loop {
        match tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, src))) => {
                if let Some(result) = parse_snmp_response(&buf[..len], src.ip()) {
                    let _ = tx.send(result).await;
                }
            }
            _ => break,
        }
    }
}

// BER/ASN.1 encoding helpers

fn ber_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}

fn ber_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(ber_length(value.len()));
    out.extend_from_slice(value);
    out
}

fn encode_oid(oid: &[u32]) -> Vec<u8> {
    if oid.len() < 2 {
        return vec![];
    }
    let mut bytes = vec![(oid[0] * 40 + oid[1]) as u8];
    for &component in &oid[2..] {
        if component < 128 {
            bytes.push(component as u8);
        } else {
            // Multi-byte base-128 encoding
            let mut tmp = Vec::new();
            let mut val = component;
            tmp.push((val & 0x7F) as u8);
            val >>= 7;
            while val > 0 {
                tmp.push(((val & 0x7F) | 0x80) as u8);
                val >>= 7;
            }
            tmp.reverse();
            bytes.extend(tmp);
        }
    }
    bytes
}

fn build_snmp_get(txid: u16, community: &str, oids: &[&[u32]]) -> Vec<u8> {
    // Build variable bindings list
    let mut varbind_list_inner = Vec::new();
    for &oid in oids {
        let oid_bytes = encode_oid(oid);
        let oid_tlv = ber_tlv(0x06, &oid_bytes); // OID tag
        let null_tlv = vec![0x05, 0x00]; // NULL
        let mut varbind = oid_tlv;
        varbind.extend(null_tlv);
        let varbind_seq = ber_tlv(0x30, &varbind); // SEQUENCE
        varbind_list_inner.extend(varbind_seq);
    }
    let varbind_list = ber_tlv(0x30, &varbind_list_inner); // SEQUENCE OF

    // Request ID (INTEGER)
    let req_id_bytes: [u8; 2] = txid.to_be_bytes();
    let request_id = ber_tlv(0x02, &req_id_bytes);

    // Error status = 0
    let error_status = ber_tlv(0x02, &[0x00]);
    // Error index = 0
    let error_index = ber_tlv(0x02, &[0x00]);

    // PDU: GetRequest (0xA0)
    let mut pdu_inner = Vec::new();
    pdu_inner.extend(request_id);
    pdu_inner.extend(error_status);
    pdu_inner.extend(error_index);
    pdu_inner.extend(varbind_list);
    let pdu = ber_tlv(0xA0, &pdu_inner);

    // Community string (OCTET STRING)
    let community_tlv = ber_tlv(0x04, community.as_bytes());

    // Version: v2c = 1 (INTEGER)
    let version = ber_tlv(0x02, &[0x01]);

    // SNMP message SEQUENCE
    let mut msg_inner = Vec::new();
    msg_inner.extend(version);
    msg_inner.extend(community_tlv);
    msg_inner.extend(pdu);

    ber_tlv(0x30, &msg_inner)
}

fn parse_snmp_response(data: &[u8], ip: IpAddr) -> Option<SnmpResult> {
    if data.len() < 2 {
        return None;
    }

    // Parse SEQUENCE wrapper
    let mut offset = 0;
    if data[offset] != 0x30 {
        return None;
    }
    offset += 1;
    let (_, new_offset) = read_ber_length(data, offset)?;
    offset = new_offset;

    // Skip version (INTEGER)
    offset = skip_ber_tlv(data, offset)?;
    // Skip community (OCTET STRING)
    offset = skip_ber_tlv(data, offset)?;

    // GetResponse PDU (0xA2)
    if offset >= data.len() || data[offset] != 0xA2 {
        return None;
    }
    offset += 1;
    let (_, new_offset) = read_ber_length(data, offset)?;
    offset = new_offset;

    // Skip request-id
    offset = skip_ber_tlv(data, offset)?;
    // Skip error-status
    offset = skip_ber_tlv(data, offset)?;
    // Skip error-index
    offset = skip_ber_tlv(data, offset)?;

    // VarBindList SEQUENCE
    if offset >= data.len() || data[offset] != 0x30 {
        return None;
    }
    offset += 1;
    let (_, new_offset) = read_ber_length(data, offset)?;
    offset = new_offset;

    let mut sys_descr = None;
    let mut sys_name = None;

    // Parse each VarBind
    let mut vb_offset = offset;
    loop {
        if vb_offset >= data.len() || data[vb_offset] != 0x30 {
            break;
        }
        vb_offset += 1;
        let (vb_len, new_offset) = read_ber_length(data, vb_offset)?;
        let vb_start = new_offset;
        let vb_end = vb_start + vb_len;
        vb_offset = new_offset;

        if vb_offset >= data.len() {
            break;
        }

        // Read OID
        if data[vb_offset] != 0x06 {
            vb_offset = vb_end;
            continue;
        }
        vb_offset += 1;
        let (oid_len, new_offset) = read_ber_length(data, vb_offset)?;
        let oid_bytes = &data[new_offset..new_offset + oid_len];
        vb_offset = new_offset + oid_len;

        // Determine which OID this is
        // sysDescr: 1.3.6.1.2.1.1.1.0 → first byte = 1*40+3=43 (0x2B), then 6,1,2,1,1,1,0
        // sysName:  1.3.6.1.2.1.1.5.0 → first byte = 0x2B, then 6,1,2,1,1,5,0
        let is_sys_descr = oid_bytes.starts_with(&[0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
        let is_sys_name = oid_bytes.starts_with(&[0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00]);

        // Read value (OCTET STRING tag 0x04)
        if vb_offset >= data.len() {
            break;
        }
        let val_tag = data[vb_offset];
        vb_offset += 1;
        let (val_len, new_offset) = read_ber_length(data, vb_offset)?;
        let val_bytes = if new_offset + val_len <= data.len() {
            &data[new_offset..new_offset + val_len]
        } else {
            break;
        };

        if val_tag == 0x04 {
            // OCTET STRING
            let s = String::from_utf8_lossy(val_bytes).trim().to_string();
            if is_sys_descr {
                sys_descr = Some(s);
            } else if is_sys_name {
                sys_name = Some(s);
            }
        }

        vb_offset = vb_end;
    }

    if sys_descr.is_none() && sys_name.is_none() {
        return None;
    }

    Some(SnmpResult {
        ip,
        sys_descr,
        sys_name,
    })
}

fn read_ber_length(data: &[u8], offset: usize) -> Option<(usize, usize)> {
    if offset >= data.len() {
        return None;
    }
    let first = data[offset];
    if first < 0x80 {
        Some((first as usize, offset + 1))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if offset + 1 + num_bytes > data.len() {
            return None;
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | (data[offset + 1 + i] as usize);
        }
        Some((len, offset + 1 + num_bytes))
    }
}

fn skip_ber_tlv(data: &[u8], offset: usize) -> Option<usize> {
    if offset >= data.len() {
        return None;
    }
    let new_offset = offset + 1;
    let (len, new_offset) = read_ber_length(data, new_offset)?;
    Some(new_offset + len)
}

use crate::model::{Device, DeviceType, PortState};
use crate::scanner::banner;

/// Known printer brands to detect in banners and hostnames
const PRINTER_BRANDS: &[(&str, &str)] = &[
    ("ricoh", "Ricoh"),
    ("xerox", "Xerox"),
    ("canon", "Canon"),
    ("epson", "Epson"),
    ("brother", "Brother"),
    ("lexmark", "Lexmark"),
    ("kyocera", "Kyocera"),
    ("konica", "Konica Minolta"),
    ("sharp", "Sharp"),
    ("hp ", "HP"),
    ("hewlett", "HP"),
    ("laserjet", "HP"),
];

/// Classify device type from all available signals
pub fn classify_device(device: &mut Device) {
    // First: extract brand/model from banners (high confidence data)
    extract_from_banners(device);

    // Try hostname-based model extraction for any device missing a model
    if device.model.is_none() {
        if let Some(hostname) = device.hostname.clone() {
            extract_model_from_hostname(device, &hostname);
        }
    }

    // Already classified with high confidence (e.g., from Apple fingerprinting)
    if device.device_type != DeviceType::Unknown && device.confidence > 0.7 {
        return;
    }

    // Port-based heuristics
    let open_ports: Vec<u16> = device.ports.iter()
        .filter(|p| p.state == crate::model::PortState::Open)
        .map(|p| p.port)
        .collect();

    // Router indicators
    if open_ports.contains(&53) && (open_ports.contains(&80) || open_ports.contains(&443)) {
        device.device_type = DeviceType::Router;
        device.confidence = device.confidence.max(0.6);
        return;
    }

    // Printer indicators
    if open_ports.contains(&9100) || open_ports.contains(&631) || open_ports.contains(&515) {
        device.device_type = DeviceType::Printer;
        device.confidence = device.confidence.max(0.7);
        return;
    }

    // NAS indicators
    if open_ports.contains(&5000) || open_ports.contains(&5001) {
        if let Some(ref vendor) = device.vendor {
            if vendor.contains("Synology") || vendor.contains("QNAP") {
                device.device_type = DeviceType::NAS;
                device.confidence = device.confidence.max(0.8);
                return;
            }
        }
    }

    // iPhone sync port
    if open_ports.contains(&62078) {
        device.device_type = DeviceType::Phone;
        device.confidence = device.confidence.max(0.6);
        return;
    }

    // Camera indicators
    if open_ports.contains(&554) && !open_ports.contains(&22) {
        device.device_type = DeviceType::Camera;
        device.confidence = device.confidence.max(0.5);
        return;
    }

    // mDNS service-based classification
    let mut has_airplay = false;
    let mut mdns_manufacturer: Option<String> = None;
    let mut mdns_model: Option<String> = None;

    for svc in &device.mdns_services {
        let stype = svc.service_type.to_lowercase();
        if stype.contains("_printer") || stype.contains("_pdl-datastream") || stype.contains("_ipp") {
            device.device_type = DeviceType::Printer;
            device.confidence = device.confidence.max(0.7);
            return;
        }
        if stype.contains("_airplay") || stype.contains("_raop") {
            has_airplay = true;
        }

        // Extract manufacturer/integrator/model from TXT records
        for (k, v) in &svc.txt_records {
            let kl = k.to_lowercase();
            if kl == "manufacturer" || kl == "integrator" {
                mdns_manufacturer = Some(v.clone());
            }
            if kl == "model" || kl == "md" {
                mdns_model = Some(v.clone());
            }
        }
    }

    // Airplay + any signal of TV = smart TV
    if has_airplay {
        // Check if model name itself indicates a TV
        let model_says_tv = mdns_model.as_ref()
            .map(|m| {
                let ml = m.to_lowercase();
                ml.contains("tv") || ml.contains("smarttv") || ml.contains("smart tv")
            })
            .unwrap_or(false);

        if let Some(ref mfr) = mdns_manufacturer {
            let mfr_lower = mfr.to_lowercase();
            let known_tv_brand = mfr_lower.contains("samsung") || mfr_lower.contains("lg")
                || mfr_lower.contains("sony") || mfr_lower.contains("vizio")
                || mfr_lower.contains("tcl") || mfr_lower.contains("hisense");

            if known_tv_brand || model_says_tv {
                device.device_type = DeviceType::TV;
                device.vendor = Some(mfr.clone());
                if let Some(ref model) = mdns_model {
                    device.model = Some(model.clone());
                }
                device.confidence = device.confidence.max(0.9);
                return;
            }

            // Non-Apple manufacturer + airplay = likely TV even without known brand
            if !mfr_lower.contains("apple") {
                device.device_type = DeviceType::TV;
                device.vendor = Some(mfr.clone());
                if let Some(ref model) = mdns_model {
                    device.model = Some(model.clone());
                }
                device.confidence = device.confidence.max(0.8);
                return;
            }
        }

        // model says TV but no manufacturer
        if model_says_tv {
            device.device_type = DeviceType::TV;
            if let Some(ref model) = mdns_model {
                device.model = Some(model.clone());
            }
            device.confidence = device.confidence.max(0.85);
            return;
        }

        // Airplay without manufacturer — likely Apple TV or Mac
        if device.device_type == DeviceType::Unknown {
            device.device_type = DeviceType::TV;
            device.confidence = device.confidence.max(0.6);
        }
    }

    // mDNS manufacturer without airplay — still useful for vendor identification
    if let Some(ref mfr) = mdns_manufacturer {
        if device.vendor.is_none() || device.vendor.as_deref() == Some("(randomized MAC)") {
            device.vendor = Some(mfr.clone());
        }
    }

    // Vendor-based guesses
    if let Some(ref vendor) = device.vendor {
        let v = vendor.to_lowercase();
        if v.contains("samsung") || v.contains("roku") || v.contains("lg") || v.contains("vizio")
            || v.contains("sony") || v.contains("tcl") || v.contains("hisense")
        {
            // These brands + no other strong signal = likely TV
            if device.device_type == DeviceType::Unknown {
                device.device_type = DeviceType::TV;
                device.confidence = device.confidence.max(0.5);
            }
        } else if v.contains("ring") || v.contains("nest") || v.contains("philips lighting") {
            device.device_type = DeviceType::IoT;
            device.confidence = device.confidence.max(0.6);
        } else if v.contains("ubiquiti") || v.contains("meraki") {
            device.device_type = DeviceType::AccessPoint;
            device.confidence = device.confidence.max(0.6);
        } else if v.contains("raspberry pi") {
            device.device_type = DeviceType::Computer;
            device.confidence = device.confidence.max(0.5);
        }
    }
}

/// Extract brand and model from FTP/HTTP/other banners
fn extract_from_banners(device: &mut Device) {
    for port_info in &device.ports {
        let banner = match &port_info.banner {
            Some(b) => b,
            None => continue,
        };
        let lower = banner.to_lowercase();

        for &(pattern, brand_name) in PRINTER_BRANDS {
            if lower.contains(pattern) {
                device.vendor = Some(brand_name.to_string());
                device.device_type = DeviceType::Printer;
                device.confidence = device.confidence.max(0.9);

                // Extract model: find the brand in the original banner, take the next word(s)
                // e.g., "220 RICOH IM C4510 FTP server" → "IM C4510"
                if device.model.is_none() {
                    if let Some(model) = extract_model_after_brand(banner, pattern) {
                        device.model = Some(model);
                    }
                }
                return;
            }
        }
    }
}

/// Extract model string after the brand name in a banner
fn extract_model_after_brand(banner: &str, brand_pattern: &str) -> Option<String> {
    let lower = banner.to_lowercase();
    let pos = lower.find(brand_pattern)?;
    let after_brand = &banner[pos + brand_pattern.len()..].trim_start();

    // Take words until we hit a known stop word
    let stop_words = ["ftp", "http", "server", "printer", "service", "ready", "version"];
    let mut model_parts = Vec::new();

    for word in after_brand.split_whitespace() {
        let wl = word.to_lowercase();
        if stop_words.iter().any(|s| wl.contains(s)) {
            break;
        }
        model_parts.push(word);
        if model_parts.len() >= 4 {
            break;
        }
    }

    if model_parts.is_empty() {
        None
    } else {
        Some(model_parts.join(" "))
    }
}

/// Apply SSH banner classification to a device. Check all port banners for SSH signatures
/// and update os/device_type hints accordingly.
pub fn apply_ssh_classification(device: &mut Device) {
    for port_info in &device.ports {
        if port_info.state != PortState::Open {
            continue;
        }
        let b = match &port_info.banner {
            Some(b) if b.starts_with("SSH-") => b,
            _ => continue,
        };
        if let Some(classification) = banner::classify_ssh_banner(b) {
            if let Some(ref os_hint) = classification.os_hint {
                if device.os.is_none() {
                    device.os = Some(os_hint.clone());
                }
            }
            if let Some(ref device_hint) = classification.device_hint {
                if device.device_type == DeviceType::Unknown {
                    let hint_lower = device_hint.to_lowercase();
                    if hint_lower.contains("router") {
                        device.device_type = DeviceType::Router;
                    } else if hint_lower.contains("iot") || hint_lower.contains("embedded") {
                        device.device_type = DeviceType::IoT;
                    }
                    device.confidence = device.confidence.max(0.4);
                }
            }
            break; // Only use the first SSH banner found
        }
    }
}

/// Try to extract model info from hostname (e.g., "BackOffice-C4510", "NURSE-M320F")
fn extract_model_from_hostname(device: &mut Device, hostname: &str) {
    // For printers (or devices with printer ports): hostname often contains the model number
    let is_printer = device.device_type == DeviceType::Printer;
    let has_printer_ports = device.ports.iter().any(|p| {
        p.state == crate::model::PortState::Open && (p.port == 9100 || p.port == 631 || p.port == 515)
    });

    if !is_printer && !has_printer_ports {
        return;
    }

    // Look for model-like patterns: letters+digits (e.g., C4510, M320F, IM430)
    for part in hostname.split(|c: char| c == '-' || c == '_' || c == '.') {
        let has_letter = part.chars().any(|c| c.is_ascii_alphabetic());
        let has_digit = part.chars().any(|c| c.is_ascii_digit());
        if has_letter && has_digit && part.len() >= 3 {
            device.model = Some(part.to_string());
            return;
        }
    }
}

use std::collections::HashMap;

include!(concat!(env!("OUT_DIR"), "/apple_models.rs"));

/// Look up Apple model identifier (e.g. "iPhone15,2") -> marketing name
pub fn lookup_model(model_id: &str) -> Option<&'static str> {
    APPLE_MODELS.get(model_id).copied()
}

/// Determine Apple device type from model identifier or mDNS hostname
pub fn classify_apple_device(
    model_id: Option<&str>,
    hostname: Option<&str>,
    mdns_services: &[String],
    txt_records: &HashMap<String, String>,
) -> AppleDeviceInfo {
    let mut info = AppleDeviceInfo::default();

    // 1. Model string from mDNS TXT records
    // Check "model", "am" (used by _raop._tcp), and "md" TXT keys
    if let Some(model) = model_id
        .or_else(|| txt_records.get("model").map(|s| s.as_str()))
        .or_else(|| txt_records.get("am").map(|s| s.as_str()))
    {
        if let Some(name) = lookup_model(model) {
            info.marketing_name = Some(name.to_string());
        }
        if model.starts_with("iPhone") {
            info.device_type = Some("Phone".to_string());
            info.brand = "Apple".to_string();
            info.confidence = 0.95;
        } else if model.starts_with("iPad") {
            info.device_type = Some("Tablet".to_string());
            info.brand = "Apple".to_string();
            info.confidence = 0.95;
        } else if model.starts_with("MacBook") || model.starts_with("Mac") || model.starts_with("iMac") {
            info.device_type = Some("Computer".to_string());
            info.brand = "Apple".to_string();
            info.confidence = 0.95;
        } else if model.starts_with("AppleTV") {
            info.device_type = Some("TV".to_string());
            info.brand = "Apple".to_string();
            info.confidence = 0.95;
        } else if model.starts_with("Watch") {
            info.device_type = Some("IoT".to_string());
            info.brand = "Apple".to_string();
            info.confidence = 0.90;
        } else if model.starts_with("AudioAccessory") {
            info.device_type = Some("IoT".to_string());
            info.brand = "Apple".to_string();
            info.confidence = 0.90;
        }
        return info;
    }

    // 2. Hostname-based detection
    if let Some(host) = hostname {
        let lower = host.to_lowercase();
        if lower.contains("iphone") {
            info.device_type = Some("Phone".to_string());
            info.brand = "Apple".to_string();
            info.confidence = 0.80;
        } else if lower.contains("ipad") {
            info.device_type = Some("Tablet".to_string());
            info.brand = "Apple".to_string();
            info.confidence = 0.80;
        } else if lower.contains("macbook") || lower.contains("imac") || lower.contains("mac-") {
            info.device_type = Some("Computer".to_string());
            info.brand = "Apple".to_string();
            info.confidence = 0.75;
        } else if lower.contains("apple-tv") || lower.contains("appletv") {
            info.device_type = Some("TV".to_string());
            info.brand = "Apple".to_string();
            info.confidence = 0.75;
        }
        if info.confidence > 0.0 {
            return info;
        }
    }

    // 3. mDNS service-based detection
    let apple_services = [
        "_companion-link._tcp",
        "_airplay._tcp",
        "_raop._tcp",
        "_homekit._tcp",
    ];
    let apple_service_count = mdns_services.iter()
        .filter(|s| apple_services.iter().any(|a| s.contains(a)))
        .count();

    if apple_service_count >= 2 {
        info.brand = "Apple".to_string();
        info.confidence = 0.70;
    } else if apple_service_count == 1 {
        info.brand = "Apple".to_string();
        info.confidence = 0.50;
    }

    info
}

#[derive(Debug, Default, Clone)]
pub struct AppleDeviceInfo {
    pub brand: String,
    pub device_type: Option<String>,
    pub marketing_name: Option<String>,
    pub confidence: f32,
}

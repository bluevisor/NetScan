use std::collections::HashMap;

use crate::model::{Device, DeviceType, PortState};

include!(concat!(env!("OUT_DIR"), "/apple_models.rs"));

const APPLE_MOBILE_SERVICE_HINTS: &[&str] = &[
    "_device-info._tcp",
    "_apple-mobdev2._tcp",
    "_apple-mobdev._tcp",
    "_rdlink._tcp",
    "_remotepairing._tcp",
    "_companion-link._tcp",
];

/// Look up Apple model identifier (e.g. "iPhone15,2") -> marketing name
pub fn lookup_model(model_id: &str) -> Option<&'static str> {
    APPLE_MODELS.get(model_id).copied()
}

pub fn should_probe_mobile_services(device: &Device) -> bool {
    if device.model.is_some() {
        return false;
    }

    let has_sync_port = device
        .ports
        .iter()
        .any(|port| port.state == PortState::Open && port.port == 62078);
    let has_mobile_mdns = device
        .mdns_services
        .iter()
        .any(|svc| is_apple_mobile_service(&svc.service_type));
    let vendor_apple = device
        .vendor
        .as_deref()
        .map(|vendor| vendor.contains("Apple"))
        .unwrap_or(false);
    let hostname_looks_apple_mobile = device
        .hostname
        .as_deref()
        .map(|hostname| {
            let lower = hostname.to_lowercase();
            lower.contains("iphone") || lower.contains("ipad")
        })
        .unwrap_or(false);
    let os_looks_apple_mobile = device
        .os
        .as_deref()
        .map(|os| {
            let lower = os.to_lowercase();
            lower.contains("ios") || lower.contains("ipados")
        })
        .unwrap_or(false);

    has_sync_port
        || has_mobile_mdns
        || hostname_looks_apple_mobile
        || os_looks_apple_mobile
        || (vendor_apple
            && matches!(
                device.device_type,
                DeviceType::Unknown | DeviceType::Phone | DeviceType::Tablet
            ))
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
        } else if model.starts_with("MacBook")
            || model.starts_with("Mac")
            || model.starts_with("iMac")
        {
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
        return finalize_apple_guess(info);
    }

    let (has_ios_service, has_rdlink, has_remotepairing, has_companion_link, has_computer_services) =
        mdns_services.iter().fold(
            (false, false, false, false, false),
            |(ios, rdlink, remote, companion, computer), s| {
                (
                    ios || s.contains("_apple-mobdev2._tcp") || s.contains("_apple-mobdev._tcp"),
                    rdlink || s.contains("_rdlink._tcp"),
                    remote || s.contains("_remotepairing._tcp"),
                    companion || s.contains("_companion-link._tcp"),
                    computer
                        || s.contains("_ssh._tcp")
                        || s.contains("_sftp-ssh._tcp")
                        || s.contains("_adisk._tcp")
                        || s.contains("_smb._tcp"),
                )
            },
        );
    let mobile_signal_count = usize::from(has_companion_link)
        + usize::from(has_rdlink)
        + usize::from(has_remotepairing)
        + usize::from(has_ios_service);

    // 2. Hostname-based detection
    if let Some(host) = hostname {
        info = guess_from_hostname(host);
        if info.confidence > 0.0 {
            let boost = match info.device_type.as_deref() {
                Some("Phone") | Some("Tablet") if mobile_signal_count >= 3 => 0.08,
                Some("Phone") | Some("Tablet") if mobile_signal_count >= 1 => 0.04,
                Some("Computer") if has_computer_services => 0.05,
                Some("TV") if has_companion_link => 0.03,
                _ => 0.0,
            };
            info.confidence = (info.confidence + boost).min(0.92);
            return finalize_apple_guess(info);
        }
    }

    // 3. mDNS service-based detection

    if has_ios_service {
        info.brand = "Apple".to_string();
        info.device_type = Some("Phone".to_string());
        info.confidence = 0.80;
        return finalize_apple_guess(info);
    }

    // AirDrop relay — present on both iOS and macOS, but combined with no
    // hostname and no other services it strongly indicates a mobile device
    if has_rdlink && !has_computer_services {
        info.brand = "Apple".to_string();
        info.device_type = Some("Phone".to_string());
        info.confidence = 0.65;
        return finalize_apple_guess(info);
    }

    let apple_services = [
        "_companion-link._tcp",
        "_airplay._tcp",
        "_raop._tcp",
        "_homekit._tcp",
        "_remotepairing._tcp",
        "_device-info._tcp",
    ];
    let apple_service_count = mdns_services
        .iter()
        .filter(|s| apple_services.iter().any(|a| s.contains(a)))
        .count();

    if apple_service_count >= 2 {
        info.brand = "Apple".to_string();
        info.confidence = 0.70;
    } else if apple_service_count == 1 {
        info.brand = "Apple".to_string();
        info.confidence = 0.50;
    }

    finalize_apple_guess(info)
}

#[derive(Debug, Default, Clone)]
pub struct AppleDeviceInfo {
    pub brand: String,
    pub device_type: Option<String>,
    pub marketing_name: Option<String>,
    pub confidence: f32,
}

fn finalize_apple_guess(mut info: AppleDeviceInfo) -> AppleDeviceInfo {
    if info.brand == "Apple"
        && info.marketing_name.is_none()
        && matches!(info.device_type.as_deref(), Some("Phone"))
    {
        info.marketing_name = Some("iPhone".to_string());
    }

    info
}

fn is_apple_mobile_service(service_type: &str) -> bool {
    let lower = service_type.to_lowercase();
    APPLE_MOBILE_SERVICE_HINTS
        .iter()
        .any(|hint| lower.contains(hint))
}

fn guess_from_hostname(hostname: &str) -> AppleDeviceInfo {
    let mut info = AppleDeviceInfo::default();
    let normalized = hostname
        .trim_end_matches(".local")
        .trim_end_matches('.')
        .to_lowercase()
        .replace(['_', '.', ' '], "-");
    let tokens: Vec<&str> = normalized
        .split('-')
        .filter(|part| !part.is_empty())
        .collect();
    let has =
        |needle: &str| tokens.iter().any(|part| *part == needle) || normalized.contains(needle);

    if has("iphone") {
        info.brand = "Apple".to_string();
        info.device_type = Some("Phone".to_string());
        info.marketing_name = Some("iPhone".to_string());
        info.confidence = 0.82;
    } else if has("ipad") {
        info.brand = "Apple".to_string();
        info.device_type = Some("Tablet".to_string());
        info.confidence = 0.82;
        info.marketing_name = Some(
            if has("air") {
                info.confidence = 0.88;
                "iPad Air"
            } else if has("pro") {
                info.confidence = 0.88;
                "iPad Pro"
            } else if has("mini") {
                info.confidence = 0.88;
                "iPad mini"
            } else {
                "iPad"
            }
            .to_string(),
        );
    } else if normalized.contains("macbook-pro") || (has("macbook") && has("pro")) {
        info.brand = "Apple".to_string();
        info.device_type = Some("Computer".to_string());
        info.marketing_name = Some("MacBook Pro".to_string());
        info.confidence = 0.86;
    } else if normalized.contains("macbook-air") || (has("macbook") && has("air")) {
        info.brand = "Apple".to_string();
        info.device_type = Some("Computer".to_string());
        info.marketing_name = Some("MacBook Air".to_string());
        info.confidence = 0.86;
    } else if has("macbook")
        || has("imac")
        || has("mac-mini")
        || (has("mac") && has("mini"))
        || normalized.contains("mac-studio")
        || (has("mac") && has("studio"))
    {
        info.brand = "Apple".to_string();
        info.device_type = Some("Computer".to_string());
        info.marketing_name = Some(
            if has("imac") {
                "iMac"
            } else if normalized.contains("mac-studio") || (has("mac") && has("studio")) {
                "Mac Studio"
            } else if has("mac-mini") || (has("mac") && has("mini")) {
                "Mac mini"
            } else {
                "MacBook"
            }
            .to_string(),
        );
        info.confidence = 0.80;
    } else if normalized.contains("apple-tv") || has("appletv") || (has("apple") && has("tv")) {
        info.brand = "Apple".to_string();
        info.device_type = Some("TV".to_string());
        info.marketing_name = Some("Apple TV".to_string());
        info.confidence = 0.80;
    } else if has("watch") {
        info.brand = "Apple".to_string();
        info.device_type = Some("IoT".to_string());
        info.marketing_name = Some("Apple Watch".to_string());
        info.confidence = 0.78;
    } else if has("homepod") {
        info.brand = "Apple".to_string();
        info.device_type = Some("IoT".to_string());
        info.marketing_name = Some("HomePod".to_string());
        info.confidence = 0.78;
    }

    info
}

#[cfg(test)]
mod tests {
    use super::{classify_apple_device, should_probe_mobile_services};
    use crate::model::{Device, DeviceType, PortInfo, PortState, Protocol};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn hostname_can_guess_ipad_air_family() {
        let services = vec![
            "_companion-link._tcp.local".to_string(),
            "_rdlink._tcp.local".to_string(),
            "_remotepairing._tcp.local".to_string(),
        ];

        let info = classify_apple_device(None, Some("iPad-Air.local"), &services, &HashMap::new());

        assert_eq!(info.brand, "Apple");
        assert_eq!(info.device_type.as_deref(), Some("Tablet"));
        assert_eq!(info.marketing_name.as_deref(), Some("iPad Air"));
        assert!(info.confidence >= 0.90);
    }

    #[test]
    fn precise_model_id_beats_hostname_guess() {
        let info = classify_apple_device(
            Some("iPad13,16"),
            Some("iPad-Air.local"),
            &["_companion-link._tcp.local".to_string()],
            &HashMap::new(),
        );

        assert_eq!(info.brand, "Apple");
        assert_eq!(info.device_type.as_deref(), Some("Tablet"));
        assert_eq!(
            info.marketing_name.as_deref(),
            Some("iPad Air (5th gen, M1)")
        );
        assert_eq!(info.confidence, 0.95);
    }

    #[test]
    fn generic_apple_phone_defaults_to_iphone() {
        let info = classify_apple_device(
            None,
            Some("Jeffreys-Phone.local"),
            &["_apple-mobdev2._tcp.local".to_string()],
            &HashMap::new(),
        );

        assert_eq!(info.brand, "Apple");
        assert_eq!(info.device_type.as_deref(), Some("Phone"));
        assert_eq!(info.marketing_name.as_deref(), Some("iPhone"));
        assert!(info.confidence >= 0.80);
    }

    #[test]
    fn iphone_sync_port_triggers_mobile_probe() {
        let mut device = Device::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 175)));
        device.ports.push(PortInfo {
            port: 62078,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("iphone-sync".to_string()),
            banner: None,
            version: None,
        });

        assert!(should_probe_mobile_services(&device));
    }

    #[test]
    fn known_apple_model_skips_mobile_probe() {
        let mut device = Device::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 131)));
        device.vendor = Some("Apple".to_string());
        device.device_type = DeviceType::Tablet;
        device.model = Some("iPad Air".to_string());

        assert!(!should_probe_mobile_services(&device));
    }
}

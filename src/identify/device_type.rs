use crate::model::{Device, DeviceType};

/// Classify device type from all available signals
pub fn classify_device(device: &mut Device) {
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
    for svc in &device.mdns_services {
        let stype = svc.service_type.to_lowercase();
        if stype.contains("_printer") || stype.contains("_pdl-datastream") || stype.contains("_ipp") {
            device.device_type = DeviceType::Printer;
            device.confidence = device.confidence.max(0.7);
            return;
        }
        if stype.contains("_airplay") || stype.contains("_raop") {
            if stype.contains("_appletv") {
                device.device_type = DeviceType::TV;
                device.confidence = device.confidence.max(0.7);
            }
        }
    }

    // Vendor-based guesses
    if let Some(ref vendor) = device.vendor {
        let v = vendor.to_lowercase();
        if v.contains("roku") {
            device.device_type = DeviceType::TV;
            device.confidence = device.confidence.max(0.7);
        } else if v.contains("ring") || v.contains("nest") || v.contains("philips lighting") {
            device.device_type = DeviceType::IoT;
            device.confidence = device.confidence.max(0.6);
        } else if v.contains("ubiquiti") {
            device.device_type = DeviceType::AccessPoint;
            device.confidence = device.confidence.max(0.6);
        } else if v.contains("raspberry pi") {
            device.device_type = DeviceType::Computer;
            device.confidence = device.confidence.max(0.5);
        }
    }
}

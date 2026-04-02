use std::fmt::Write as _;
use std::process::Stdio;

use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::model::{Device, DeviceType, DiscoveryMethod, PortState};

#[derive(Debug, Clone)]
pub struct LlmGuessConfig {
    pub enabled: bool,
    pub model: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct LlmDeviceGuess {
    pub vendor: Option<String>,
    pub device_type: Option<String>,
    pub model: Option<String>,
    pub os: Option<String>,
    pub confidence: Option<f32>,
    pub reason: Option<String>,
}

const SYSTEM_PROMPT: &str = "You infer consumer LAN device identity from network scan evidence. Never contradict known fields. Only infer missing fields. Prefer safe family guesses over invented exact models. Respond with strict JSON only using keys vendor, device_type, model, os, confidence, reason. device_type must be one of Router, Phone, Tablet, Computer, IoT, NAS, Printer, Camera, TV, AccessPoint, Unknown.";

pub fn needs_llm_guess(device: &Device) -> bool {
    let vendor_missing =
        device.vendor.is_none() || matches!(device.vendor.as_deref(), Some("(randomized MAC)"));
    let model_missing = device.model.is_none();
    let type_missing = device.device_type == DeviceType::Unknown;

    (vendor_missing || model_missing || type_missing) && has_guessable_context(device)
}

pub fn apply_guess(device: &mut Device, guess: LlmDeviceGuess) -> bool {
    let mut changed = false;

    if let Some(vendor) = normalize_text(guess.vendor.as_deref()) {
        if device.vendor.is_none() || matches!(device.vendor.as_deref(), Some("(randomized MAC)")) {
            device.vendor = Some(vendor.to_string());
            changed = true;
        }
    }

    if device.device_type == DeviceType::Unknown {
        if let Some(device_type) = guess
            .device_type
            .as_deref()
            .and_then(parse_device_type)
            .filter(|dt| *dt != DeviceType::Unknown)
        {
            device.device_type = device_type;
            changed = true;
        }
    }

    if device.model.is_none() {
        if let Some(model) = normalize_text(guess.model.as_deref()) {
            device.model = Some(model.to_string());
            changed = true;
        }
    }

    if device.os.is_none() {
        if let Some(os) = normalize_text(guess.os.as_deref()) {
            device.os = Some(os.to_string());
            changed = true;
        }
    }

    if changed {
        let confidence = guess.confidence.unwrap_or(0.45).clamp(0.35, 0.75);
        device.confidence = device.confidence.max(confidence);
        device.add_source(DiscoveryMethod::Llm);
    }

    changed
}

pub async fn guess_device(
    device: &Device,
    config: &LlmGuessConfig,
) -> Result<Option<LlmDeviceGuess>, String> {
    if !config.enabled || !needs_llm_guess(device) {
        return Ok(None);
    }

    let mut child = Command::new("llm")
        .arg("Infer only the missing device fields from the scan evidence on stdin. Return JSON only.")
        .arg("-m")
        .arg(&config.model)
        .arg("-s")
        .arg(SYSTEM_PROMPT)
        .arg("-n")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to launch `llm`: {}", e))?;

    let prompt = build_prompt(device);
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(prompt.as_bytes())
            .await
            .map_err(|e| format!("failed to write to `llm` stdin: {}", e))?;
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("failed while waiting for `llm`: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            format!("`llm` exited with {}", output.status)
        } else {
            format!("`llm` failed: {}", stderr)
        });
    }

    let raw = String::from_utf8_lossy(&output.stdout);
    let json = extract_json_object(&raw)
        .ok_or_else(|| format!("`llm` returned non-JSON output: {}", raw.trim()))?;
    let guess: LlmDeviceGuess = serde_json::from_str(&json)
        .map_err(|e| format!("failed to parse LLM guess JSON: {}", e))?;

    if guess.confidence.unwrap_or(0.0) < 0.35 {
        return Ok(None);
    }

    Ok(Some(guess))
}

fn has_guessable_context(device: &Device) -> bool {
    device.hostname.is_some()
        || device.os.is_some()
        || device.mac.is_some()
        || device.ports.iter().any(|p| p.state == PortState::Open)
        || !device.mdns_services.is_empty()
}

fn build_prompt(device: &Device) -> String {
    let mut prompt = String::new();
    let vendor = device.vendor.as_deref().unwrap_or("(missing)");
    let hostname = device.hostname.as_deref().unwrap_or("(missing)");
    let model = device.model.as_deref().unwrap_or("(missing)");
    let os = device.os.as_deref().unwrap_or("(missing)");
    let mac = device
        .mac
        .map(|m| m.to_string())
        .unwrap_or_else(|| "(missing)".to_string());

    let _ = writeln!(prompt, "Known fields:");
    let _ = writeln!(prompt, "- ip: {}", device.ip);
    let _ = writeln!(prompt, "- mac: {}", mac);
    let _ = writeln!(prompt, "- vendor: {}", vendor);
    let _ = writeln!(prompt, "- hostname: {}", hostname);
    let _ = writeln!(prompt, "- device_type: {}", device.device_type);
    let _ = writeln!(prompt, "- model: {}", model);
    let _ = writeln!(prompt, "- os: {}", os);
    let _ = writeln!(prompt, "- confidence: {:.2}", device.confidence);

    let open_ports: Vec<String> = device
        .ports
        .iter()
        .filter(|p| p.state == PortState::Open)
        .take(12)
        .map(|p| match (&p.service, &p.banner) {
            (Some(service), Some(banner)) => {
                format!("{}:{service} ({})", p.port, truncate(banner, 60))
            }
            (Some(service), None) => format!("{}:{service}", p.port),
            (None, Some(banner)) => format!("{} ({})", p.port, truncate(banner, 60)),
            (None, None) => p.port.to_string(),
        })
        .collect();
    let _ = writeln!(prompt, "- open_ports: {}", join_or_missing(&open_ports));

    let mdns_services: Vec<String> = device
        .mdns_services
        .iter()
        .take(12)
        .map(|svc| {
            let txt_keys: Vec<String> = svc.txt_records.keys().take(6).cloned().collect();
            if txt_keys.is_empty() {
                svc.service_type.clone()
            } else {
                format!("{} [{}]", svc.service_type, txt_keys.join(", "))
            }
        })
        .collect();
    let _ = writeln!(
        prompt,
        "- mdns_services: {}",
        join_or_missing(&mdns_services)
    );

    let source_list: Vec<String> = device.sources.iter().map(|s| s.to_string()).collect();
    let _ = writeln!(
        prompt,
        "- discovery_sources: {}",
        join_or_missing(&source_list)
    );

    let missing_fields = missing_fields(device);
    let _ = writeln!(prompt);
    let _ = writeln!(
        prompt,
        "Only fill these missing fields: {}",
        missing_fields.join(", ")
    );
    let _ = writeln!(
        prompt,
        "Return null for any field you cannot support from the evidence."
    );

    prompt
}

fn missing_fields(device: &Device) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if device.vendor.is_none() || matches!(device.vendor.as_deref(), Some("(randomized MAC)")) {
        fields.push("vendor");
    }
    if device.device_type == DeviceType::Unknown {
        fields.push("device_type");
    }
    if device.model.is_none() {
        fields.push("model");
    }
    if device.os.is_none() {
        fields.push("os");
    }
    fields
}

fn parse_device_type(value: &str) -> Option<DeviceType> {
    let normalized = value
        .trim()
        .to_ascii_lowercase()
        .replace([' ', '-', '/'], "");

    match normalized.as_str() {
        "router" => Some(DeviceType::Router),
        "phone" | "mobile" | "smartphone" => Some(DeviceType::Phone),
        "tablet" => Some(DeviceType::Tablet),
        "computer" | "laptop" | "desktop" | "mac" | "pc" => Some(DeviceType::Computer),
        "iot" | "smarthome" | "wearable" | "speaker" => Some(DeviceType::IoT),
        "nas" => Some(DeviceType::NAS),
        "printer" => Some(DeviceType::Printer),
        "camera" => Some(DeviceType::Camera),
        "tv" | "television" => Some(DeviceType::TV),
        "accesspoint" | "ap" => Some(DeviceType::AccessPoint),
        "unknown" => Some(DeviceType::Unknown),
        _ => None,
    }
}

fn normalize_text(value: Option<&str>) -> Option<&str> {
    let value = value?.trim();
    if value.is_empty()
        || value.eq_ignore_ascii_case("null")
        || value.eq_ignore_ascii_case("unknown")
    {
        None
    } else {
        Some(value)
    }
}

fn extract_json_object(text: &str) -> Option<String> {
    let trimmed = text.trim().trim_matches('`').trim();
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        return Some(trimmed.to_string());
    }

    let start = text.find('{')?;
    let end = text.rfind('}')?;
    (end > start).then(|| text[start..=end].to_string())
}

fn truncate(text: &str, max_len: usize) -> String {
    let mut truncated: String = text.chars().take(max_len).collect();
    if text.chars().count() > max_len {
        truncated.push_str("...");
    }
    truncated
}

fn join_or_missing(values: &[String]) -> String {
    if values.is_empty() {
        "(missing)".to_string()
    } else {
        values.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::{apply_guess, extract_json_object, needs_llm_guess, LlmDeviceGuess};
    use crate::model::{Device, DeviceType};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn fenced_json_is_extracted() {
        let raw = "```json\n{\"vendor\":\"Apple\",\"device_type\":\"Phone\"}\n```";
        assert_eq!(
            extract_json_object(raw).as_deref(),
            Some("{\"vendor\":\"Apple\",\"device_type\":\"Phone\"}")
        );
    }

    #[test]
    fn merge_only_fills_missing_fields() {
        let mut device = Device::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
        device.vendor = Some("Apple".to_string());
        device.device_type = DeviceType::Phone;
        device.confidence = 0.8;

        let changed = apply_guess(
            &mut device,
            LlmDeviceGuess {
                vendor: Some("Samsung".to_string()),
                device_type: Some("TV".to_string()),
                model: Some("iPhone".to_string()),
                os: Some("iOS".to_string()),
                confidence: Some(0.6),
                reason: None,
            },
        );

        assert!(changed);
        assert_eq!(device.vendor.as_deref(), Some("Apple"));
        assert_eq!(device.device_type, DeviceType::Phone);
        assert_eq!(device.model.as_deref(), Some("iPhone"));
        assert_eq!(device.os.as_deref(), Some("iOS"));
        assert_eq!(device.confidence, 0.8);
    }

    #[test]
    fn llm_guess_requires_context() {
        let device = Device::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6)));
        assert!(!needs_llm_guess(&device));
    }
}

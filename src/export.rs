use std::path::PathBuf;

use serde::Serialize;

use crate::scanner::orchestrator::ScanState;

#[derive(Serialize)]
struct ExportData {
    scan_time: String,
    interface: String,
    subnet: String,
    privilege: String,
    device_count: usize,
    devices: Vec<crate::model::Device>,
}

pub fn export_json(state: &ScanState, path: Option<PathBuf>) -> Result<PathBuf, String> {
    let now = chrono::Local::now();
    let path = path.unwrap_or_else(|| {
        PathBuf::from(format!("netscan-{}.json", now.format("%Y-%m-%d-%H%M%S")))
    });

    let data = ExportData {
        scan_time: now.to_rfc3339(),
        interface: state.interface.name.clone(),
        subnet: format!("{}", state.interface.network),
        privilege: format!("{}", state.privilege),
        device_count: state.devices.len(),
        devices: state.devices.values().cloned().collect(),
    };

    let json = serde_json::to_string_pretty(&data)
        .map_err(|e| format!("JSON serialization failed: {}", e))?;

    std::fs::write(&path, json)
        .map_err(|e| format!("Failed to write {}: {}", path.display(), e))?;

    Ok(path)
}

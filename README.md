# NetScan

A pure Rust network security scanner with a modern btop-style TUI. Single binary, zero runtime dependencies.

NetScan performs progressive network discovery — showing initial results within seconds, then deepening scans in the background. It combines active scanning with passive packet sniffing to build a comprehensive view of every device on your network.

![NetScan TUI](https://img.shields.io/badge/rust-stable-orange) ![License](https://img.shields.io/badge/license-MIT-blue)

## Features

### Progressive 3-Phase Scanning
- **Phase 1 (Instant, <2s):** ARP sweep, interface detection, passive sniffer starts, continuous mDNS listener
- **Phase 2 (Fast, 2-15s):** Top 100 ports, mDNS/Bonjour, SSDP/UPnP, NetBIOS, WSD, DNS PTR, SNMP
- **Phase 3 (Deep, background):** Full port scan (1000 → 65535), banner grabbing, OS fingerprinting, SMB enumeration, TLS probing, UPnP XML fetch

### Device Identification
- **MAC OUI lookup** — full IEEE database (~40K vendors), downloaded at build time
- **Apple device fingerprinting** — identifies iPhones, iPads, Macs, Apple TVs even with randomized MAC addresses via mDNS model records, DHCP fingerprinting, and TCP stack analysis
- **Smart TV detection** — Samsung, LG, Sony, Vizio, TCL, Hisense, and other brands via AirPlay + manufacturer TXT records
- **Printer identification** — brand and model extraction from FTP/HTTP banners and hostnames (Ricoh, Xerox, Canon, HP, Brother, etc.)
- **OS fingerprinting** — TTL analysis, DHCP option 55 fingerprinting, SMB negotiate, SSH banner classification
- **Network gear** — LLDP/CDP passive capture, SNMP sysDescr, Cisco Meraki detection

### Passive Sniffer
Runs continuously in the background (requires root), capturing:
- ARP (new devices, spoofing detection)
- DHCP (hostname, OS fingerprint via option 55/60)
- mDNS/Bonjour announcements
- DNS queries and responses
- HTTP Host headers and User-Agent strings
- TLS SNI hostnames from ClientHello
- LLDP/CDP frames from network equipment

### Modern TUI
- btop-inspired dark theme with color-coded panels
- Auto-adjusting column widths based on terminal size and data
- Animated scanning spinners and progress bar
- New device highlight animation
- Per-panel scrolling (up/down keys work within focused panel)
- Live sniffer log with protocol-colored output

## Installation

### From Source

```bash
# Requires Rust toolchain
cargo build --release
```

The binary is at `target/release/netscan`.

## Usage

```bash
# Scan local LAN (non-root — TCP connect scan, no sniffer)
./netscan

# Full scan with all features (root — ARP scan, sniffer, raw sockets)
sudo ./netscan

# Scan specific subnet
sudo ./netscan 192.168.1.0/24

# Use specific network interface
sudo ./netscan -i en0

# Auto-export results to JSON on exit
sudo ./netscan --export results.json

# Disable passive sniffer
sudo ./netscan --no-sniff
```

### Adaptive Privilege Model

NetScan detects whether it's running as root and adapts:

| Feature | Root | Non-root |
|---------|------|----------|
| ARP scanning | Yes | TCP ping sweep fallback |
| SYN scan | Yes | TCP connect scan |
| Passive sniffer | Yes | Disabled |
| LLDP/CDP capture | Yes | Disabled |
| DHCP fingerprinting | Yes | Disabled |
| mDNS/SSDP/NetBIOS | Yes | Yes |
| DNS PTR / SNMP | Yes | Yes |
| Port scanning | Yes | Yes |
| Banner grabbing | Yes | Yes |

## Keyboard Controls

| Key | Action |
|-----|--------|
| `j/k` or `Up/Down` | Navigate within focused panel |
| `Tab` | Cycle focus: Devices → Detail → Sniffer |
| `s` | Toggle sniffer panel |
| `p` | Pause/resume scanning |
| `q` | Quit |
| `Esc` | Open menu (Resume / Export JSON / Quit) |
| `Ctrl+C` | Immediate quit |

## Export

Press `Esc → Export JSON` or use `--export` flag. Output includes:

```json
{
  "scan_time": "2025-03-31T22:30:00Z",
  "interface": "en0",
  "subnet": "192.168.1.0/24",
  "privilege": "root",
  "device_count": 15,
  "devices": [
    {
      "ip": "192.168.1.100",
      "mac": "3a:f2:1b:...",
      "vendor": "Apple",
      "model": "iPhone 15 Pro",
      "device_type": "Phone",
      "hostname": "Johns-iPhone.local",
      "ports": [...],
      "mdns_services": [...],
      "confidence": 0.95
    }
  ]
}
```

## Scanning Techniques

| Technique | Phase | Purpose |
|-----------|-------|---------|
| ARP sweep | 1 | Fast host discovery on LAN |
| mDNS/Bonjour | 1-2 | Apple devices, printers, services |
| SSDP/UPnP | 2 | Smart TVs, routers, IoT |
| NetBIOS | 2 | Windows hostnames |
| WSD | 2 | Windows devices, printers |
| DNS PTR | 2 | Hostnames from local DNS |
| SNMP | 2 | Network gear identification |
| TCP port scan | 2-3 | Open ports (100 → 1000 → 65535) |
| UPnP XML fetch | 3 | Manufacturer/model from device descriptions |
| Banner grabbing | 3 | Service versions, printer models |
| SMB negotiate | 3 | Windows OS version, computer name |
| OS fingerprinting | 3 | TTL-based OS family detection |
| TLS probing | 3 | TLS version, cipher suite |
| LLDP/CDP | Passive | Switch/AP model, firmware |
| DHCP fingerprint | Passive | OS identification via option 55 |
| HTTP/TLS sniffing | Passive | Hostnames, user agents |

## Tech Stack

- **Rust** with `tokio` async runtime
- **ratatui** + **crossterm** for TUI
- **pnet** for raw packet construction and capture
- **socket2** for adaptive raw socket handling
- **clap** for CLI parsing
- **serde** for JSON export
- **phf** for compile-time perfect hash maps (OUI + Apple model tables)

## License

MIT

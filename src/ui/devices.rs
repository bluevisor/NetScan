use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use super::theme;
use crate::model::{Device, DeviceScanState, PortState};
use crate::scanner::orchestrator::ScanState;

/// Column definitions with min widths and priority (higher = dropped first when tight)
struct ColLayout {
    ip: usize,
    mac: usize,
    vendor: usize,
    model: usize,
    dtype: usize,
    ports: usize,
    hostname: usize,
    show_mac: bool,
}

fn compute_columns(width: usize, devices: &[&Device]) -> ColLayout {
    // Fixed columns
    let status_w = 3; // " ● "
    let ip_w = 6;
    let ports_w = 4;
    let dtype_w = 8;

    // Measure actual content widths
    let max_vendor = devices
        .iter()
        .filter_map(|d| d.vendor.as_ref())
        .map(|v| v.len())
        .max()
        .unwrap_or(0)
        .max(6) // min "VENDOR"
        .min(20);

    let max_model = devices
        .iter()
        .filter_map(|d| d.model.as_ref())
        .map(|m| m.len())
        .max()
        .unwrap_or(0)
        .max(5) // min "MODEL"
        .min(28);

    let max_hostname = devices
        .iter()
        .filter_map(|d| d.hostname.as_ref())
        .map(|h| h.len())
        .max()
        .unwrap_or(0)
        .max(8) // min "HOSTNAME"
        .min(30);

    let mac_w: usize = 18;

    // Available space after fixed columns + 1 space padding each
    let fixed = status_w + ip_w + dtype_w + ports_w + 4; // 4 spaces between fixed cols

    let remaining = width.saturating_sub(fixed);

    // Try full layout with MAC
    let full_need = mac_w + max_vendor + max_model + max_hostname + 4; // 4 col gaps
    if remaining >= full_need {
        // Everything fits at natural width
        let leftover = remaining - full_need;
        // Give leftover to hostname
        return ColLayout {
            ip: ip_w,
            mac: mac_w,
            vendor: max_vendor + 1,
            model: max_model + 1,
            dtype: dtype_w,
            ports: ports_w,
            hostname: max_hostname + leftover,
            show_mac: true,
        };
    }

    // Try with MAC but compressed columns
    let min_vendor = 8;
    let min_model = 8;
    let min_hostname = 8;
    let compressed_need = mac_w + min_vendor + min_model + min_hostname + 4;
    if remaining >= compressed_need {
        let budget = remaining - mac_w - 4;
        let (v, m, h) = distribute(budget, max_vendor, max_model, max_hostname);
        return ColLayout {
            ip: ip_w,
            mac: mac_w,
            vendor: v,
            model: m,
            dtype: dtype_w,
            ports: ports_w,
            hostname: h,
            show_mac: true,
        };
    }

    // Drop MAC column
    let no_mac_need = min_vendor + min_model + min_hostname + 3;
    if remaining >= no_mac_need {
        let budget = remaining - 3;
        let (v, m, h) = distribute(budget, max_vendor, max_model, max_hostname);
        return ColLayout {
            ip: ip_w,
            mac: 0,
            vendor: v,
            model: m,
            dtype: dtype_w,
            ports: ports_w,
            hostname: h,
            show_mac: false,
        };
    }

    // Minimal: just vendor + model, no hostname
    let budget = remaining.saturating_sub(2);
    let half = budget / 2;
    ColLayout {
        ip: ip_w,
        mac: 0,
        vendor: half.min(max_vendor + 1),
        model: (budget - half).min(max_model + 1),
        dtype: dtype_w,
        ports: ports_w,
        hostname: 0,
        show_mac: false,
    }
}

/// Distribute budget among 3 columns proportionally, capped at their max
fn distribute(budget: usize, max_a: usize, max_b: usize, max_c: usize) -> (usize, usize, usize) {
    let total_want = max_a + max_b + max_c;
    if total_want == 0 {
        return (budget / 3, budget / 3, budget / 3);
    }
    if budget >= total_want {
        return (max_a + 1, max_b + 1, (budget - max_a - max_b - 2).max(1));
    }
    let a = ((budget as f64 * max_a as f64) / total_want as f64).round() as usize;
    let b = ((budget as f64 * max_b as f64) / total_want as f64).round() as usize;
    let c = budget.saturating_sub(a + b);
    (a.max(1), b.max(1), c.max(1))
}

pub fn render_devices(
    f: &mut Frame,
    area: Rect,
    state: &ScanState,
    selected: usize,
    focused: bool,
    tick: u64,
) {
    let devices = state.sorted_devices();
    let border_style = if focused {
        theme::style_border_focused()
    } else {
        theme::style_border()
    };

    let block = Block::default()
        .title(Span::styled(" Devices ", theme::style_header()))
        .borders(Borders::ALL)
        .border_style(border_style);

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 2 || inner.width < 20 {
        return;
    }

    let cols = compute_columns(inner.width as usize, &devices);

    // Build header
    let mut header_spans = vec![
        Span::styled("   ", theme::style_dim()),
        Span::styled(format!("{:<w$}", "IP", w = cols.ip), theme::style_dim()),
    ];
    if cols.show_mac {
        header_spans.push(Span::styled(
            format!("{:<w$}", "MAC", w = cols.mac),
            theme::style_dim(),
        ));
    }
    header_spans.push(Span::styled(
        format!("{:<w$}", "VENDOR", w = cols.vendor),
        theme::style_dim(),
    ));
    header_spans.push(Span::styled(
        format!("{:<w$}", "MODEL", w = cols.model),
        theme::style_dim(),
    ));
    header_spans.push(Span::styled(
        format!("{:<w$}", "TYPE", w = cols.dtype),
        theme::style_dim(),
    ));
    header_spans.push(Span::styled(
        format!("{:<w$}", "PRT", w = cols.ports),
        theme::style_dim(),
    ));
    if cols.hostname > 0 {
        header_spans.push(Span::styled("HOSTNAME", theme::style_dim()));
    }

    let header_area = Rect { height: 1, ..inner };
    f.render_widget(Paragraph::new(Line::from(header_spans)), header_area);

    // Build rows
    let items: Vec<ListItem> = devices
        .iter()
        .enumerate()
        .map(|(i, dev)| {
            let ip_str = match dev.ip {
                std::net::IpAddr::V4(v4) => format!(".{:<3}", v4.octets()[3]),
                _ => format!("{}", dev.ip),
            };

            let mac_str = match &dev.mac {
                Some(m) if crate::identify::oui::is_randomized_mac(m) => "random".to_string(),
                Some(m) => format!("{}", m),
                None => "??:??:??".to_string(),
            };

            let vendor_str = dev.vendor.as_deref().unwrap_or("");
            let vendor_trunc: String = vendor_str
                .chars()
                .take(cols.vendor.saturating_sub(1))
                .collect();

            let model_str = dev.model.as_deref().unwrap_or("");
            let model_trunc: String = model_str
                .chars()
                .take(cols.model.saturating_sub(1))
                .collect();

            let type_str = format!("{}", dev.device_type);

            let port_count = dev
                .ports
                .iter()
                .filter(|p| p.state == PortState::Open)
                .count();
            let ports_str = if port_count > 0 {
                format!("{}p", port_count)
            } else {
                String::new()
            };

            let spinner_idx = (tick / 3) as usize % theme::SPINNER_FRAMES.len();
            let status = match dev.scan_state {
                DeviceScanState::Discovered => "○",
                DeviceScanState::Scanning => {
                    theme::SPINNER_FRAMES[(spinner_idx + i) % theme::SPINNER_FRAMES.len()]
                }
                DeviceScanState::Done => "●",
            };

            let style = if i == selected {
                theme::style_selected()
            } else if dev.first_seen.elapsed().as_secs() < 2 {
                theme::style_new_device()
            } else {
                theme::style_default()
            };

            let mut spans = vec![
                Span::styled(format!(" {} ", status), Style::default().fg(theme::ACCENT)),
                Span::styled(format!("{:<w$}", ip_str, w = cols.ip), style),
            ];
            if cols.show_mac {
                spans.push(Span::styled(
                    format!("{:<w$}", mac_str, w = cols.mac),
                    Style::default().fg(theme::DIM),
                ));
            }
            spans.push(Span::styled(
                format!("{:<w$}", vendor_trunc, w = cols.vendor),
                Style::default().fg(theme::YELLOW),
            ));
            spans.push(Span::styled(
                format!("{:<w$}", model_trunc, w = cols.model),
                Style::default().fg(theme::GREEN),
            ));
            spans.push(Span::styled(
                format!("{:<w$}", type_str, w = cols.dtype),
                Style::default().fg(theme::ACCENT2),
            ));
            spans.push(Span::styled(
                format!("{:<w$}", ports_str, w = cols.ports),
                Style::default().fg(theme::ACCENT),
            ));
            if cols.hostname > 0 {
                let hostname_str = dev.hostname.as_deref().unwrap_or("");
                let hostname_trunc: String = hostname_str.chars().take(cols.hostname).collect();
                spans.push(Span::styled(
                    hostname_trunc,
                    Style::default().fg(theme::DIM),
                ));
            }

            ListItem::new(Line::from(spans))
        })
        .collect();

    let list_area = Rect {
        y: inner.y + 1,
        height: inner.height.saturating_sub(1),
        ..inner
    };

    let list = List::new(items).highlight_style(theme::style_selected());
    let mut list_state = ListState::default();
    list_state.select(Some(selected));

    f.render_stateful_widget(list, list_area, &mut list_state);
}

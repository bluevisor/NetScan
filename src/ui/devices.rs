use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use crate::model::{DeviceScanState, PortState};
use crate::scanner::orchestrator::ScanState;
use super::theme;

pub fn render_devices(
    f: &mut Frame,
    area: Rect,
    state: &ScanState,
    selected: usize,
    focused: bool,
    tick: u64,
) {
    let devices = state.sorted_devices();

    let items: Vec<ListItem> = devices.iter().enumerate().map(|(i, dev)| {
        let ip_str = match dev.ip {
            std::net::IpAddr::V4(v4) => {
                let octets = v4.octets();
                format!(".{:<3}", octets[3])
            }
            _ => format!("{}", dev.ip),
        };

        let mac_str = match &dev.mac {
            Some(m) => {
                if crate::identify::oui::is_randomized_mac(m) {
                    "random".to_string()
                } else {
                    format!("{}", m)
                }
            }
            None => "??:??:??".to_string(),
        };

        let vendor_str = dev.vendor.as_deref().unwrap_or("");
        let vendor_short: String = vendor_str.chars().take(12).collect();

        let model_str = dev.model.as_deref().unwrap_or("");
        let model_short: String = model_str.chars().take(16).collect();

        let type_str = format!("{}", dev.device_type);

        let port_count = dev.ports.iter().filter(|p| p.state == PortState::Open).count();
        let ports_str = if port_count > 0 { format!("{}p", port_count) } else { String::new() };

        // Scan state indicator
        let spinner_idx = (tick / 3) as usize % theme::SPINNER_FRAMES.len();
        let status = match dev.scan_state {
            DeviceScanState::Discovered => "○",
            DeviceScanState::Scanning => theme::SPINNER_FRAMES[(spinner_idx + i) % theme::SPINNER_FRAMES.len()],
            DeviceScanState::Done => "●",
        };

        let hostname_str = dev.hostname.as_deref().unwrap_or("");
        let hostname_short: String = hostname_str.chars().take(15).collect();

        let style = if i == selected {
            theme::style_selected()
        } else {
            let age = dev.first_seen.elapsed().as_secs();
            if age < 2 {
                theme::style_new_device()
            } else {
                theme::style_default()
            }
        };

        let line = Line::from(vec![
            Span::styled(format!(" {} ", status), Style::default().fg(theme::ACCENT)),
            Span::styled(format!("{:<6}", ip_str), style),
            Span::styled(format!("{:<18}", mac_str), Style::default().fg(theme::DIM)),
            Span::styled(format!("{:<13}", vendor_short), Style::default().fg(theme::YELLOW)),
            Span::styled(format!("{:<17}", model_short), Style::default().fg(theme::GREEN)),
            Span::styled(format!("{:<8}", type_str), Style::default().fg(theme::ACCENT2)),
            Span::styled(format!("{:<4}", ports_str), Style::default().fg(theme::ACCENT)),
            Span::styled(format!("{}", hostname_short), Style::default().fg(theme::DIM)),
        ]);

        ListItem::new(line)
    }).collect();

    let border_style = if focused { theme::style_border_focused() } else { theme::style_border() };

    let header_line = Line::from(vec![
        Span::styled("   ", theme::style_dim()),
        Span::styled(format!("{:<6}", "IP"), theme::style_dim()),
        Span::styled(format!("{:<18}", "MAC"), theme::style_dim()),
        Span::styled(format!("{:<13}", "VENDOR"), theme::style_dim()),
        Span::styled(format!("{:<17}", "MODEL"), theme::style_dim()),
        Span::styled(format!("{:<8}", "TYPE"), theme::style_dim()),
        Span::styled(format!("{:<4}", "PRT"), theme::style_dim()),
        Span::styled("HOSTNAME", theme::style_dim()),
    ]);

    let block = Block::default()
        .title(Span::styled(" Devices ", theme::style_header()))
        .borders(Borders::ALL)
        .border_style(border_style);

    // Render header manually in the first line area
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 2 {
        return;
    }

    // Header row
    let header_area = Rect { height: 1, ..inner };
    f.render_widget(Paragraph::new(header_line), header_area);

    // List area
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

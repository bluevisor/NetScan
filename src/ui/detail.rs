use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use super::theme;
use crate::model::Device;

pub fn render_detail(
    f: &mut Frame,
    area: Rect,
    device: Option<&Device>,
    focused: bool,
    scroll: u16,
) {
    let border_style = if focused {
        theme::style_border_focused()
    } else {
        theme::style_border()
    };
    let block = Block::default()
        .title(Span::styled(" Detail ", theme::style_header()))
        .borders(Borders::ALL)
        .border_style(border_style);

    let device = match device {
        Some(d) => d,
        None => {
            let p = Paragraph::new("No device selected")
                .block(block)
                .style(theme::style_dim());
            f.render_widget(p, area);
            return;
        }
    };

    let mut lines = Vec::new();

    // IP
    lines.push(Line::from(vec![
        Span::styled(" IP:       ", theme::style_dim()),
        Span::styled(format!("{}", device.ip), theme::style_accent()),
    ]));

    // MAC
    let mac_str = device
        .mac
        .map(|m| m.to_string())
        .unwrap_or_else(|| "unknown".into());
    let randomized = device
        .mac
        .map(|m| crate::identify::oui::is_randomized_mac(&m))
        .unwrap_or(false);
    lines.push(Line::from(vec![
        Span::styled(" MAC:      ", theme::style_dim()),
        Span::styled(&mac_str, theme::style_default()),
        if randomized {
            Span::styled(
                " (random)",
                ratatui::style::Style::default().fg(theme::YELLOW),
            )
        } else {
            Span::raw("")
        },
    ]));

    // Vendor
    if let Some(ref vendor) = device.vendor {
        lines.push(Line::from(vec![
            Span::styled(" Vendor:   ", theme::style_dim()),
            Span::styled(vendor, ratatui::style::Style::default().fg(theme::YELLOW)),
        ]));
    }

    // Model
    if let Some(ref model) = device.model {
        lines.push(Line::from(vec![
            Span::styled(" Model:    ", theme::style_dim()),
            Span::styled(model, ratatui::style::Style::default().fg(theme::GREEN)),
        ]));
    }

    // Type
    lines.push(Line::from(vec![
        Span::styled(" Type:     ", theme::style_dim()),
        Span::styled(
            format!("{}", device.device_type),
            ratatui::style::Style::default().fg(theme::ACCENT2),
        ),
    ]));

    // Hostname
    if let Some(ref hostname) = device.hostname {
        lines.push(Line::from(vec![
            Span::styled(" Host:     ", theme::style_dim()),
            Span::styled(hostname, theme::style_default()),
        ]));
    }

    // OS
    if let Some(ref os) = device.os {
        lines.push(Line::from(vec![
            Span::styled(" OS:       ", theme::style_dim()),
            Span::styled(os, theme::style_default()),
        ]));
    }

    // Confidence
    let conf_color = if device.confidence > 0.8 {
        theme::GREEN
    } else if device.confidence > 0.5 {
        theme::YELLOW
    } else {
        theme::RED
    };
    lines.push(Line::from(vec![
        Span::styled(" Conf:     ", theme::style_dim()),
        Span::styled(
            format!("{:.0}%", device.confidence * 100.0),
            ratatui::style::Style::default().fg(conf_color),
        ),
    ]));

    // Sources
    let sources: Vec<String> = device.sources.iter().map(|s| format!("{}", s)).collect();
    lines.push(Line::from(vec![
        Span::styled(" Via:      ", theme::style_dim()),
        Span::styled(sources.join(", "), theme::style_dim()),
    ]));

    lines.push(Line::from(""));

    // Open ports
    let open_ports: Vec<&crate::model::PortInfo> = device
        .ports
        .iter()
        .filter(|p| p.state == crate::model::PortState::Open)
        .collect();

    if !open_ports.is_empty() {
        lines.push(Line::from(Span::styled(
            " OPEN PORTS",
            theme::style_header(),
        )));
        for port in &open_ports {
            let svc = port.service.as_deref().unwrap_or("?");
            let banner = port.banner.as_deref().unwrap_or("");
            let banner_short: String = banner.chars().take(30).collect();

            lines.push(Line::from(vec![
                Span::styled(format!("  {:<6}", port.port), theme::style_accent()),
                Span::styled(
                    format!("{:<14}", svc),
                    ratatui::style::Style::default().fg(theme::GREEN),
                ),
                Span::styled(banner_short, theme::style_dim()),
            ]));
        }
    }

    // mDNS services
    if !device.mdns_services.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(" SERVICES", theme::style_header())));
        for svc in &device.mdns_services {
            lines.push(Line::from(vec![Span::styled(
                format!("  {}", svc.service_type),
                ratatui::style::Style::default().fg(theme::ACCENT),
            )]));
            for (k, v) in &svc.txt_records {
                let v_short: String = v.chars().take(25).collect();
                lines.push(Line::from(vec![
                    Span::styled(format!("    {}=", k), theme::style_dim()),
                    Span::styled(v_short, theme::style_default()),
                ]));
            }
        }
    }

    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: true })
        .scroll((scroll, 0));
    f.render_widget(paragraph, area);
}

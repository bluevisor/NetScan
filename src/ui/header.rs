use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::theme;
use crate::scanner::orchestrator::ScanState;

pub fn render_header(f: &mut Frame, area: Rect, state: &ScanState, tick: u64) {
    let spinner_idx = (tick / 3) as usize % theme::SPINNER_FRAMES.len();
    let spinner = theme::SPINNER_FRAMES[spinner_idx];

    let phase_text = format!("{}", state.phase);
    let is_complete = state.phase == crate::model::ScanPhase::Complete;

    // Progress bar
    let progress_width = 20;
    let progress_ratio = match state.phase {
        crate::model::ScanPhase::Phase1Instant => 0.15,
        crate::model::ScanPhase::Phase2Fast => 0.50,
        crate::model::ScanPhase::Phase3Deep => 0.85,
        crate::model::ScanPhase::Complete => 1.0,
    };
    let filled = (progress_ratio * progress_width as f64) as usize;
    let empty = progress_width - filled;
    let progress_bar = format!(
        "{}{}",
        theme::PROGRESS_FULL.repeat(filled),
        theme::PROGRESS_EMPTY.repeat(empty),
    );

    let device_count = state.devices.len();
    let priv_text = format!("[{}]", state.privilege);
    let iface_text = &state.interface.name;
    let subnet_text = format!("{}", state.interface.network);

    let line = if is_complete {
        Line::from(vec![
            Span::styled(" NETSCAN ", theme::style_header()),
            Span::styled(
                "  \u{2713} ",
                ratatui::style::Style::default().fg(theme::GREEN),
            ),
            Span::styled(
                &progress_bar,
                ratatui::style::Style::default().fg(theme::GREEN),
            ),
            Span::styled(format!("  {}  ", phase_text), theme::style_accent()),
            Span::styled(&priv_text, theme::style_dim()),
            Span::styled(format!("  {}  ", iface_text), theme::style_dim()),
            Span::styled(format!("  {}  ", subnet_text), theme::style_accent()),
            Span::styled(format!("{} hosts", device_count), theme::style_accent()),
        ])
    } else {
        Line::from(vec![
            Span::styled(" NETSCAN ", theme::style_header()),
            Span::styled(
                format!("  {} ", spinner),
                ratatui::style::Style::default().fg(theme::ACCENT),
            ),
            Span::styled(
                &progress_bar,
                ratatui::style::Style::default().fg(theme::ACCENT),
            ),
            Span::styled(format!("  {}  ", phase_text), theme::style_accent()),
            Span::styled(&priv_text, theme::style_dim()),
            Span::styled(format!("  {}  ", iface_text), theme::style_dim()),
            Span::styled(format!("  {}  ", subnet_text), theme::style_accent()),
            Span::styled(format!("{} hosts", device_count), theme::style_accent()),
        ])
    };

    let paragraph = Paragraph::new(line).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(theme::style_border()),
    );

    f.render_widget(paragraph, area);
}

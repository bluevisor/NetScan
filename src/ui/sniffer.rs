use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::model::SnifferEvent;
use super::theme;

pub fn render_sniffer(
    f: &mut Frame,
    area: Rect,
    events: &[SnifferEvent],
    focused: bool,
    visible: bool,
    scroll_back: u16,
) {
    if !visible {
        return;
    }

    let border_style = if focused { theme::style_border_focused() } else { theme::style_border() };
    let block = Block::default()
        .title(Span::styled(" Sniffer ", theme::style_header()))
        .borders(Borders::ALL)
        .border_style(border_style);

    let inner_height = area.height.saturating_sub(2) as usize;

    // scroll_back=0 means latest, higher means further back in history
    let end = if events.len() > scroll_back as usize {
        events.len() - scroll_back as usize
    } else {
        events.len()
    };
    let start = if end > inner_height { end - inner_height } else { 0 };

    let lines: Vec<Line> = events[start..end].iter().map(|event| {
        let elapsed = event.timestamp.elapsed();
        let time_str = format!(
            "{:02}:{:02}:{:02}",
            (elapsed.as_secs() / 3600) % 24,
            (elapsed.as_secs() / 60) % 60,
            elapsed.as_secs() % 60,
        );

        let proto_color = theme::protocol_color(&event.protocol);

        Line::from(vec![
            Span::styled(format!(" {} ", time_str), theme::style_dim()),
            Span::styled(format!("{:<5}", event.protocol), ratatui::style::Style::default().fg(proto_color)),
            Span::styled(&event.summary, theme::style_default()),
        ])
    }).collect();

    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, area);
}

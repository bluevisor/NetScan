use std::collections::HashMap;
use std::net::IpAddr;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Bar, BarChart, BarGroup, Block, Borders, Paragraph, Sparkline};
use ratatui::Frame;

use super::theme;
use crate::model::SnifferEvent;

pub fn render_sniffer(
    f: &mut Frame,
    area: Rect,
    events: &[SnifferEvent],
    focused: bool,
    visible: bool,
    scroll_back: u16,
    filter: &str,
    filter_active: bool,
    ip_filter: Option<IpAddr>,
) {
    if !visible {
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    render_log(f, chunks[0], events, focused, scroll_back, filter, filter_active, ip_filter);
    render_stats(f, chunks[1], events);
}

fn render_log(
    f: &mut Frame,
    area: Rect,
    events: &[SnifferEvent],
    focused: bool,
    scroll_back: u16,
    filter: &str,
    filter_active: bool,
    ip_filter: Option<IpAddr>,
) {
    let border_style = if focused {
        theme::style_border_focused()
    } else {
        theme::style_border()
    };

    let title = match (ip_filter, filter.is_empty()) {
        (Some(ip), true) => format!(" Sniffer [{}] ", ip),
        (Some(ip), false) => format!(" Sniffer [{}  /{}] ", ip, filter),
        (None, false) => format!(" Sniffer [/{}] ", filter),
        (None, true) => " Sniffer ".to_string(),
    };

    let block = Block::default()
        .title(Span::styled(title, theme::style_header()))
        .borders(Borders::ALL)
        .border_style(border_style);

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height == 0 {
        return;
    }

    // Reserve bottom line for filter cursor when active
    let (log_area, filter_area) = if filter_active {
        let sub = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(1)])
            .split(inner);
        (sub[0], Some(sub[1]))
    } else {
        (inner, None)
    };

    // Apply IP filter then text filter
    let filter_lower = filter.to_lowercase();
    let filtered: Vec<&SnifferEvent> = events
        .iter()
        .filter(|e| match ip_filter {
            Some(ip) => e.source_ip == Some(ip) || e.dest_ip == Some(ip),
            None => true,
        })
        .filter(|e| {
            filter.is_empty()
                || e.protocol.to_lowercase().contains(&filter_lower)
                || e.summary.to_lowercase().contains(&filter_lower)
        })
        .collect();

    let inner_height = log_area.height as usize;
    let end = if filtered.len() > scroll_back as usize {
        filtered.len() - scroll_back as usize
    } else {
        filtered.len()
    };
    let start = if end > inner_height { end - inner_height } else { 0 };

    let lines: Vec<Line> = filtered[start..end]
        .iter()
        .map(|event| {
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
                Span::styled(
                    format!("{:<5}", event.protocol),
                    Style::default().fg(proto_color),
                ),
                Span::styled(event.summary.as_str(), theme::style_default()),
            ])
        })
        .collect();

    f.render_widget(Paragraph::new(lines), log_area);

    if let Some(filter_rect) = filter_area {
        let filter_text = format!(" / {}_", filter);
        f.render_widget(
            Paragraph::new(Span::styled(filter_text, theme::style_accent())),
            filter_rect,
        );
    }
}

fn render_stats(f: &mut Frame, area: Rect, events: &[SnifferEvent]) {
    let block = Block::default()
        .title(Span::styled(" Stats ", theme::style_header()))
        .borders(Borders::ALL)
        .border_style(theme::style_border());

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 5 || inner.width < 10 {
        return;
    }

    // Sparkline fills panel width — 1 column = 1 second of history
    let spark_width = inner.width as usize;
    let mut per_second = vec![0u64; spark_width];
    for event in events {
        let secs_ago = event.timestamp.elapsed().as_secs() as usize;
        if secs_ago < spark_width {
            per_second[spark_width - 1 - secs_ago] =
                per_second[spark_width - 1 - secs_ago].saturating_add(1);
        }
    }

    // Protocol counts across last 1000 events
    let mut proto_counts: HashMap<String, u64> = HashMap::new();
    for event in events.iter().rev().take(1000) {
        *proto_counts.entry(event.protocol.clone()).or_insert(0) += 1;
    }
    let mut proto_sorted: Vec<(String, u64)> = proto_counts.into_iter().collect();
    proto_sorted.sort_by(|a, b| b.1.cmp(&a.1));
    proto_sorted.truncate(6);

    let max_proto_count = proto_sorted.first().map(|(_, c)| *c).unwrap_or(1);
    let current_rate: u64 = per_second.iter().rev().take(5).sum::<u64>().saturating_div(5);
    let total = events.len() as u64;
    // Width of the largest count value — all bars pad to this so they left-align
    let val_width = max_proto_count.to_string().len();

    let bar_rows = (proto_sorted.len() as u16).max(1);
    let available = inner.height.saturating_sub(5);
    let bar_chart_height = bar_rows.min(available).max(1);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(bar_chart_height),
            Constraint::Min(0),
        ])
        .split(inner);

    // Rate label spanning the full inner width
    let label_left = format!(" ~{}/s", current_rate);
    let label_right = format!("total: {} ", total);
    let pad = (inner.width as usize).saturating_sub(label_left.len() + label_right.len());
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(label_left, theme::style_dim()),
            Span::raw(" ".repeat(pad)),
            Span::styled(label_right, theme::style_dim()),
        ])),
        chunks[0],
    );

    // Sparkline — now exactly `spark_width` columns wide
    let sparkline = Sparkline::default()
        .data(&per_second)
        .style(Style::default().fg(theme::ACCENT));
    f.render_widget(sparkline, chunks[1]);

    // Protocol label
    f.render_widget(
        Paragraph::new(Span::styled(" Protocol Mix", theme::style_dim())),
        chunks[2],
    );

    // Horizontal bar chart — fixed-width value text aligns all bar left edges
    if !proto_sorted.is_empty() && chunks[3].height > 0 {
        let bars: Vec<Bar> = proto_sorted
            .iter()
            .map(|(proto, count)| {
                let color = theme::protocol_color(proto.as_str());
                Bar::default()
                    .value(*count)
                    .label(Line::from(Span::styled(
                        format!("{:<5}", proto),
                        Style::default().fg(color),
                    )))
                    .text_value(format!("{:>width$}", count, width = val_width))
                    .style(Style::default().fg(color))
                    .value_style(Style::default().fg(theme::FG).add_modifier(Modifier::BOLD))
            })
            .collect();

        let bar_chart = BarChart::default()
            .data(BarGroup::default().bars(&bars))
            .bar_width(1)
            .bar_gap(0)
            .direction(Direction::Horizontal)
            .max(max_proto_count);

        f.render_widget(bar_chart, chunks[3]);
    }
}

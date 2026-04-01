use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem};
use ratatui::Frame;

use super::theme;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MenuAction {
    Resume,
    ExportJson,
    Quit,
}

const MENU_ITEMS: &[(&str, MenuAction)] = &[
    ("  Resume      ", MenuAction::Resume),
    ("  Export JSON  ", MenuAction::ExportJson),
    ("  Quit         ", MenuAction::Quit),
];

pub fn render_menu(f: &mut Frame, selected: usize) {
    let area = f.area();

    // Center the menu
    let menu_width = 24;
    let menu_height = MENU_ITEMS.len() as u16 + 4;
    let x = (area.width.saturating_sub(menu_width)) / 2;
    let y = (area.height.saturating_sub(menu_height)) / 2;

    let menu_area = Rect::new(x, y, menu_width, menu_height);

    // Clear the area behind the menu
    f.render_widget(Clear, menu_area);

    let block = Block::default()
        .title(Span::styled(" Menu ", theme::style_header()))
        .borders(Borders::ALL)
        .border_style(theme::style_border_focused())
        .style(Style::default().bg(ratatui::style::Color::Rgb(20, 20, 50)));

    let items: Vec<ListItem> = MENU_ITEMS.iter().enumerate().map(|(i, (label, _))| {
        let style = if i == selected {
            Style::default()
                .fg(ratatui::style::Color::White)
                .bg(theme::SELECTED_BG)
                .add_modifier(Modifier::BOLD)
        } else {
            theme::style_default()
        };
        ListItem::new(Line::from(Span::styled(*label, style)))
    }).collect();

    let list = List::new(items).block(block);
    f.render_widget(list, menu_area);
}

pub fn menu_item_count() -> usize {
    MENU_ITEMS.len()
}

pub fn menu_action(index: usize) -> MenuAction {
    MENU_ITEMS[index].1
}

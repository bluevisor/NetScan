use ratatui::style::{Color, Modifier, Style};

// Color palette (btop-inspired dark theme)
pub const BG: Color = Color::Rgb(10, 10, 30);
pub const FG: Color = Color::Rgb(200, 200, 220);
pub const ACCENT: Color = Color::Rgb(80, 200, 255);
pub const ACCENT2: Color = Color::Rgb(255, 100, 150);
pub const GREEN: Color = Color::Rgb(80, 255, 120);
pub const YELLOW: Color = Color::Rgb(255, 220, 80);
pub const RED: Color = Color::Rgb(255, 80, 80);
pub const DIM: Color = Color::Rgb(100, 100, 130);
pub const BORDER: Color = Color::Rgb(60, 60, 100);
pub const HIGHLIGHT_BG: Color = Color::Rgb(40, 40, 80);
pub const SELECTED_BG: Color = Color::Rgb(30, 60, 120);

pub fn style_default() -> Style {
    Style::default().fg(FG)
}

pub fn style_accent() -> Style {
    Style::default().fg(ACCENT)
}

pub fn style_dim() -> Style {
    Style::default().fg(DIM)
}

pub fn style_selected() -> Style {
    Style::default().bg(SELECTED_BG).fg(Color::White).add_modifier(Modifier::BOLD)
}

pub fn style_header() -> Style {
    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
}

pub fn style_border() -> Style {
    Style::default().fg(BORDER)
}

pub fn style_border_focused() -> Style {
    Style::default().fg(ACCENT)
}

pub fn style_new_device() -> Style {
    Style::default().fg(GREEN).add_modifier(Modifier::BOLD)
}

pub fn protocol_color(proto: &str) -> Color {
    match proto {
        "ARP" => YELLOW,
        "DNS" => ACCENT,
        "mDNS" => Color::Rgb(150, 200, 255),
        "DHCP" => Color::Rgb(200, 150, 255),
        "HTTP" => GREEN,
        "TLS" => Color::Rgb(255, 180, 100),
        _ => FG,
    }
}

// Spinner animation frames
pub const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

// Progress bar characters
pub const PROGRESS_FULL: &str = "█";
pub const PROGRESS_PARTIAL: &[&str] = &["░", "▒", "▓", "█"];
pub const PROGRESS_EMPTY: &str = "░";

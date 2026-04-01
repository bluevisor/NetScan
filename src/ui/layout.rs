use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::Frame;

use crate::scanner::orchestrator::ScanState;
use super::{detail, devices, header, menu, sniffer};

pub struct UiState {
    pub selected_device: usize,
    pub focused_panel: FocusPanel,
    pub sniffer_visible: bool,
    pub menu_open: bool,
    pub menu_selected: usize,
    pub tick: u64,
    pub detail_scroll: u16,
    pub sniffer_scroll: u16,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FocusPanel {
    Devices,
    Detail,
    Sniffer,
}

impl UiState {
    pub fn new() -> Self {
        Self {
            selected_device: 0,
            focused_panel: FocusPanel::Devices,
            sniffer_visible: true,
            menu_open: false,
            menu_selected: 0,
            tick: 0,
            detail_scroll: 0,
            sniffer_scroll: 0,
        }
    }

    pub fn cycle_focus(&mut self) {
        self.focused_panel = match self.focused_panel {
            FocusPanel::Devices => FocusPanel::Detail,
            FocusPanel::Detail => {
                if self.sniffer_visible {
                    FocusPanel::Sniffer
                } else {
                    FocusPanel::Devices
                }
            }
            FocusPanel::Sniffer => FocusPanel::Devices,
        };
    }

    pub fn scroll_up(&mut self) {
        match self.focused_panel {
            FocusPanel::Detail => {
                self.detail_scroll = self.detail_scroll.saturating_sub(1);
            }
            FocusPanel::Sniffer => {
                self.sniffer_scroll = self.sniffer_scroll.saturating_add(1);
            }
            _ => {}
        }
    }

    pub fn scroll_down(&mut self) {
        match self.focused_panel {
            FocusPanel::Detail => {
                self.detail_scroll = self.detail_scroll.saturating_add(1);
            }
            FocusPanel::Sniffer => {
                self.sniffer_scroll = self.sniffer_scroll.saturating_sub(1);
            }
            _ => {}
        }
    }
}

pub fn render(f: &mut Frame, scan_state: &ScanState, ui: &UiState) {
    let size = f.area();

    // Main layout: header + body + sniffer
    let main_chunks = if ui.sniffer_visible {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),          // Header
                Constraint::Percentage(65),     // Body
                Constraint::Percentage(35),     // Sniffer
            ])
            .split(size)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),           // Header
                Constraint::Min(5),             // Body
            ])
            .split(size)
    };

    // Header
    header::render_header(f, main_chunks[0], scan_state, ui.tick);

    // Body: devices (60%) + detail (40%)
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(70),
            Constraint::Percentage(30),
        ])
        .split(main_chunks[1]);

    // Device list
    devices::render_devices(
        f,
        body_chunks[0],
        scan_state,
        ui.selected_device,
        ui.focused_panel == FocusPanel::Devices,
        ui.tick,
    );

    // Detail panel
    let sorted = scan_state.sorted_devices();
    let selected_device = sorted.get(ui.selected_device).copied();
    detail::render_detail(
        f,
        body_chunks[1],
        selected_device,
        ui.focused_panel == FocusPanel::Detail,
        ui.detail_scroll,
    );

    // Sniffer panel
    if ui.sniffer_visible && main_chunks.len() > 2 {
        sniffer::render_sniffer(
            f,
            main_chunks[2],
            &scan_state.sniffer_events,
            ui.focused_panel == FocusPanel::Sniffer,
            true,
            ui.sniffer_scroll,
        );
    }

    // Menu overlay
    if ui.menu_open {
        menu::render_menu(f, ui.menu_selected);
    }
}

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::export;
use crate::identify::llm::LlmGuessConfig;
use crate::net::interface::InterfaceInfo;
use crate::net::raw::PrivilegeLevel;
use crate::scanner::orchestrator::{self, ScanState, SharedState};
use crate::ui::layout::{self, FocusPanel, UiState};
use crate::ui::menu::{self, MenuAction};

pub struct App {
    interface: InterfaceInfo,
    privilege: PrivilegeLevel,
    target_subnet: Option<String>,
    export_path: Option<std::path::PathBuf>,
    no_sniff: bool,
    llm_guess_config: LlmGuessConfig,
}

impl App {
    pub fn new(
        interface: InterfaceInfo,
        privilege: PrivilegeLevel,
        target_subnet: Option<String>,
        export_path: Option<std::path::PathBuf>,
        no_sniff: bool,
        llm_guess_config: LlmGuessConfig,
    ) -> Self {
        Self {
            interface,
            privilege,
            target_subnet,
            export_path,
            no_sniff,
            llm_guess_config,
        }
    }

    pub async fn run(&self) -> io::Result<()> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.clear()?;

        let total_hosts = crate::net::interface::subnet_hosts(self.interface.network).len();
        let scan_state: SharedState = Arc::new(tokio::sync::Mutex::new(ScanState::new(
            self.interface.clone(),
            self.privilege,
            total_hosts,
        )));

        let shutdown = Arc::new(AtomicBool::new(false));
        let mut ui_state = UiState::new();

        // Start scanner
        let mut scan_handle = {
            let state = scan_state.clone();
            let sd = shutdown.clone();
            let llm_config = self.llm_guess_config.clone();
            tokio::spawn(async move {
                orchestrator::run_scan(state, sd, llm_config).await;
            })
        };

        // Event loop
        let tick_rate = Duration::from_millis(33); // ~30fps

        loop {
            // Draw
            {
                let state = scan_state.lock().await;
                terminal.draw(|f| {
                    layout::render(f, &state, &ui_state);
                })?;
            }

            ui_state.tick += 1;

            // Handle input
            if event::poll(tick_rate)? {
                if let Event::Key(key) = event::read()? {
                    // Ctrl+C always quits
                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        && key.code == KeyCode::Char('c')
                    {
                        break;
                    }

                    if ui_state.sniffer_filter_active {
                        match key.code {
                            KeyCode::Esc | KeyCode::Enter => {
                                ui_state.sniffer_filter_active = false;
                            }
                            KeyCode::Backspace => {
                                if ui_state.sniffer_filter.pop().is_none() {
                                    ui_state.sniffer_filter_active = false;
                                }
                            }
                            KeyCode::Char(c) => {
                                ui_state.sniffer_filter.push(c);
                            }
                            _ => {}
                        }
                    } else if ui_state.menu_open {
                        match key.code {
                            KeyCode::Esc => ui_state.menu_open = false,
                            KeyCode::Up | KeyCode::Char('k') => {
                                if ui_state.menu_selected > 0 {
                                    ui_state.menu_selected -= 1;
                                }
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                if ui_state.menu_selected < menu::menu_item_count() - 1 {
                                    ui_state.menu_selected += 1;
                                }
                            }
                            KeyCode::Enter => match menu::menu_action(ui_state.menu_selected) {
                                MenuAction::Resume => {
                                    ui_state.menu_open = false;
                                }
                                MenuAction::ExportJson => {
                                    let state = scan_state.lock().await;
                                    let _ = export::export_json(&state, self.export_path.clone());
                                    ui_state.menu_open = false;
                                }
                                MenuAction::Quit => break,
                            },
                            _ => {}
                        }
                    } else {
                        match key.code {
                            KeyCode::Esc => {
                                ui_state.menu_open = true;
                                ui_state.menu_selected = 0;
                            }
                            KeyCode::Char('q') => break,
                            KeyCode::Enter => {
                                if ui_state.focused_panel == FocusPanel::Devices {
                                    let selected_ip = {
                                        let mut state = scan_state.lock().await;
                                        let selected_ip = state
                                            .sorted_devices()
                                            .get(ui_state.selected_device)
                                            .map(|device| device.ip);
                                        if let Some(ip) = selected_ip {
                                            if let Some(device) = state.devices.get_mut(&ip) {
                                                if device.scan_state
                                                    != crate::model::DeviceScanState::Scanning
                                                {
                                                    device.scan_state =
                                                        crate::model::DeviceScanState::Scanning;
                                                }
                                            }
                                        }
                                        selected_ip
                                    };

                                    if let Some(ip) = selected_ip {
                                        let state = scan_state.clone();
                                        let llm_config = self.llm_guess_config.clone();
                                        tokio::spawn(async move {
                                            orchestrator::deep_scan_device(state, ip, llm_config)
                                                .await;
                                        });
                                    }
                                }
                            }
                            KeyCode::Char(' ') => {
                                if ui_state.focused_panel == FocusPanel::Devices {
                                    ui_state.sniffer_tracking = !ui_state.sniffer_tracking;
                                    if ui_state.sniffer_tracking {
                                        ui_state.sniffer_visible = true;
                                    }
                                }
                            }
                            KeyCode::Tab => ui_state.cycle_focus(),
                            KeyCode::Char('s') => {
                                ui_state.sniffer_visible = !ui_state.sniffer_visible;
                                if !ui_state.sniffer_visible
                                    && ui_state.focused_panel == FocusPanel::Sniffer
                                {
                                    ui_state.focused_panel = FocusPanel::Devices;
                                }
                            }
                            KeyCode::Char('/') => {
                                if ui_state.focused_panel == FocusPanel::Sniffer
                                    && ui_state.sniffer_visible
                                {
                                    ui_state.sniffer_filter.clear();
                                    ui_state.sniffer_filter_active = true;
                                }
                            }
                            KeyCode::Up | KeyCode::Char('k') => match ui_state.focused_panel {
                                FocusPanel::Devices => {
                                    if ui_state.selected_device > 0 {
                                        ui_state.selected_device -= 1;
                                        ui_state.detail_scroll = 0;
                                    }
                                }
                                _ => ui_state.scroll_up(),
                            },
                            KeyCode::Down | KeyCode::Char('j') => match ui_state.focused_panel {
                                FocusPanel::Devices => {
                                    let count = {
                                        let state = scan_state.lock().await;
                                        state.devices.len()
                                    };
                                    if ui_state.selected_device + 1 < count {
                                        ui_state.selected_device += 1;
                                        ui_state.detail_scroll = 0;
                                    }
                                }
                                _ => ui_state.scroll_down(),
                            },
                            KeyCode::Char('r') => {
                                // Stop current scan, reset state, restart
                                shutdown.store(true, Ordering::Relaxed);
                                scan_handle.abort();
                                let _ = scan_handle.await;
                                shutdown.store(false, Ordering::Relaxed);
                                {
                                    let mut s = scan_state.lock().await;
                                    let total =
                                        crate::net::interface::subnet_hosts(s.interface.network)
                                            .len();
                                    *s = ScanState::new(s.interface.clone(), s.privilege, total);
                                }
                                ui_state = UiState::new();
                                scan_handle = {
                                    let state = scan_state.clone();
                                    let sd = shutdown.clone();
                                    let llm_config = self.llm_guess_config.clone();
                                    tokio::spawn(async move {
                                        orchestrator::run_scan(state, sd, llm_config).await;
                                    })
                                };
                            }
                            KeyCode::Char('p') => {
                                let mut state = scan_state.lock().await;
                                state.paused = !state.paused;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // Cleanup
        shutdown.store(true, Ordering::Relaxed);
        scan_handle.abort();

        // Auto-export if path specified
        if let Some(ref path) = self.export_path {
            let state = scan_state.lock().await;
            let _ = export::export_json(&state, Some(path.clone()));
        }

        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;

        Ok(())
    }
}

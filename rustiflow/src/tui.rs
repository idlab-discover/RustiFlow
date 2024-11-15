use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use log::error;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::{fs, io};
use strum::VariantNames;
use tui::backend::{Backend, CrosstermBackend};
use tui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use tui::style::{Color, Modifier, Style};
use tui::text::{Span, Spans, Text};
use tui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};
use tui::{Frame, Terminal};

use crate::args::{Commands, ConfigFile, ExportConfig, ExportMethodType, FlowType, OutputConfig};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub config: ExportConfig,
    pub output: OutputConfig,
    pub command: Commands,
}

impl Config {
    fn reset() -> Self {
        Config {
            config: ExportConfig {
                features: FlowType::Basic,
                active_timeout: 3600,
                idle_timeout: 120,
                early_export: None,
                threads: None,
                expiration_check_interval: 60,
            },
            output: OutputConfig {
                output: ExportMethodType::Print,
                export_path: None,
                header: false,
                drop_contaminant_features: false,
                performance_mode: false,
            },
            command: Commands::Realtime {
                interface: String::from("eth0"),
                ingress_only: false,
            },
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config::reset()
    }
}

pub async fn launch_tui() -> Result<Option<Config>, Box<dyn Error>> {
    let config = Config::reset();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(config);
    app.focus = AppFocus::ConfigFileInput;

    let res = run_app(&mut terminal, &mut app).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    res
}

struct App {
    config: Config,
    config_file: Option<String>,
    config_file_input: String,
    focus: AppFocus,
    title_bar_state: ListState,
    main_menu_state: ListState,
    flow_type_state: ListState,
    command_state: ListState,
    output_state: ListState,
    active_timeout_input: String,
    idle_timeout_input: String,
    expiration_check_interval_input: String,
    threads_input: String,
    early_export_input: String,
    main_menu_items: Vec<&'static str>,
}

impl App {
    fn new(config: Config) -> App {
        let mut main_menu_state = ListState::default();
        main_menu_state.select(Some(0));

        let mut flow_type_state = ListState::default();
        flow_type_state.select(Some(0));

        let mut command_state = ListState::default();
        command_state.select(Some(0));

        let mut output_state = ListState::default();
        output_state.select(Some(0));

        let mut title_bar_state = ListState::default();
        title_bar_state.select(Some(0));

        let mut config_file_focus = ListState::default();
        config_file_focus.select(Some(0));

        let main_menu_items = vec![
            "Feature Set",
            "Mode",
            "Output Method",
            "Active Timeout",
            "Idle Timeout",
            "Expiration Check Interval",
            "Threads",
            "Early Export",
            "Header",
            "Drop Contaminant Features",
        ];

        App {
            config,
            config_file: None,
            config_file_input: String::new(),
            focus: AppFocus::Menu,
            title_bar_state,
            main_menu_state,
            flow_type_state,
            command_state,
            output_state,
            active_timeout_input: String::new(),
            idle_timeout_input: String::new(),
            threads_input: String::new(),
            early_export_input: String::new(),
            expiration_check_interval_input: String::new(),
            main_menu_items,
        }
    }
}

#[derive(Clone, Copy)]
enum AppFocus {
    TitleBar,
    Menu,
    FlowType,
    ActiveTimeoutInput,
    IdleTimeoutInput,
    ExpirationCheckIntervalInput,
    CommandSelection,
    OutputSelection,
    CommandArgumentInput,
    OutputArgumentInput,
    IngressOnlyInput,
    PerformanceModeInput,
    ThreadsInput,
    EarlyExportInput,
    HeaderInput,
    DropContaminantFeaturesInput,
    ConfigFileInput,
    ConfigFileSaveInput,
}

async fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<Option<Config>, Box<dyn Error>> {
    loop {
        terminal.draw(|f| ui_main_screen(f, app))?;

        if crossterm::event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match app.focus {
                    AppFocus::TitleBar => {
                        if let Some(config) = handle_title_bar_input(key, app)? {
                            return Ok(Some(config));
                        }
                    }
                    AppFocus::Menu => handle_menu_input(key, app)?,
                    AppFocus::FlowType => handle_flow_type_input(key, app)?,
                    AppFocus::ActiveTimeoutInput
                    | AppFocus::IdleTimeoutInput
                    | AppFocus::ExpirationCheckIntervalInput
                    | AppFocus::ThreadsInput
                    | AppFocus::EarlyExportInput => {
                        handle_numeric_input(key, app, app.focus.clone())?
                    }
                    AppFocus::CommandSelection | AppFocus::OutputSelection => {
                        handle_selection_input(key, app, app.focus.clone())?
                    }
                    AppFocus::CommandArgumentInput => handle_command_argument_input(key, app)?,
                    AppFocus::OutputArgumentInput => handle_output_argument_input(key, app)?,
                    AppFocus::IngressOnlyInput
                    | AppFocus::PerformanceModeInput
                    | AppFocus::HeaderInput
                    | AppFocus::DropContaminantFeaturesInput => {
                        handle_boolean_input(key, app, app.focus.clone())?
                    }
                    AppFocus::ConfigFileInput => {
                        handle_config_file_input(key, app)?;
                    }
                    AppFocus::ConfigFileSaveInput => {
                        handle_config_file_save_input(key, app)?;
                    }
                }
            }
        }
    }
}

fn handle_title_bar_input(key: KeyEvent, app: &mut App) -> Result<Option<Config>, Box<dyn Error>> {
    match key.code {
        KeyCode::Left => {
            let i = match app.title_bar_state.selected() {
                Some(i) if i > 0 => i - 1,
                _ => 0,
            };
            app.title_bar_state.select(Some(i));
        }
        KeyCode::Right => {
            let i = match app.title_bar_state.selected() {
                Some(i) if i < 3 => i + 1,
                _ => 3,
            };
            app.title_bar_state.select(Some(i));
        }
        KeyCode::Enter => match app.title_bar_state.selected() {
            Some(0) => {
                // Start
                return Ok(Some(app.config.clone()));
            }
            Some(1) => {
                // Quit
                return Err("User quit".into());
            }
            Some(2) => {
                // Save config to file
                app.focus = AppFocus::ConfigFileSaveInput;
            }
            Some(3) => {
                // Reset config
                app.config = Config::reset();
            }
            _ => {}
        },
        KeyCode::Down => {
            app.focus = AppFocus::Menu;
        }
        _ => {}
    }
    Ok(None)
}

fn handle_menu_input(key: KeyEvent, app: &mut App) -> Result<(), Box<dyn Error>> {
    match key.code {
        KeyCode::Up => {
            if let Some(0) = app.main_menu_state.selected() {
                app.focus = AppFocus::TitleBar;
            } else {
                let i = app.main_menu_state.selected().unwrap_or(0);
                app.main_menu_state.select(Some(i.saturating_sub(1)));
            }
        }
        KeyCode::Down => {
            let i = match app.main_menu_state.selected() {
                Some(i) if i < app.main_menu_items.len() - 1 => i + 1,
                _ => app.main_menu_items.len() - 1,
            };
            app.main_menu_state.select(Some(i));
        }
        KeyCode::Enter | KeyCode::Right => match app.main_menu_state.selected() {
            Some(0) => app.focus = AppFocus::FlowType,
            Some(1) => app.focus = AppFocus::CommandSelection,
            Some(2) => app.focus = AppFocus::OutputSelection,
            Some(3) => app.focus = AppFocus::ActiveTimeoutInput,
            Some(4) => app.focus = AppFocus::IdleTimeoutInput,
            Some(5) => app.focus = AppFocus::ExpirationCheckIntervalInput,
            Some(6) => app.focus = AppFocus::ThreadsInput,
            Some(7) => app.focus = AppFocus::EarlyExportInput,
            Some(8) => app.focus = AppFocus::HeaderInput,
            Some(9) => app.focus = AppFocus::DropContaminantFeaturesInput,
            _ => {}
        },
        KeyCode::Esc => {
            return Err("User quit".into());
        }
        _ => {}
    }
    Ok(())
}

fn handle_flow_type_input(key: KeyEvent, app: &mut App) -> Result<(), Box<dyn Error>> {
    match key.code {
        KeyCode::Up => {
            let i = match app.flow_type_state.selected() {
                Some(i) if i > 0 => i - 1,
                _ => 0,
            };
            app.flow_type_state.select(Some(i));
        }
        KeyCode::Down => {
            let i = match app.flow_type_state.selected() {
                Some(i) if i < FlowType::VARIANTS.len() - 1 => i + 1,
                _ => FlowType::VARIANTS.len() - 1,
            };
            app.flow_type_state.select(Some(i));
        }
        KeyCode::Enter => {
            if let Some(i) = app.flow_type_state.selected() {
                let selected = FlowType::VARIANTS[i];
                app.config.config.features = selected.parse().unwrap();
                app.focus = AppFocus::Menu;
            }
        }
        KeyCode::Left | KeyCode::Esc => {
            app.focus = AppFocus::Menu;
        }
        _ => {}
    }
    Ok(())
}

fn handle_numeric_input(
    key: KeyEvent,
    app: &mut App,
    focus: AppFocus,
) -> Result<(), Box<dyn Error>> {
    match key.code {
        KeyCode::Char(c) if c.is_digit(10) => {
            let input = match focus {
                AppFocus::ActiveTimeoutInput => &mut app.active_timeout_input,
                AppFocus::IdleTimeoutInput => &mut app.idle_timeout_input,
                AppFocus::ExpirationCheckIntervalInput => &mut app.expiration_check_interval_input,
                AppFocus::ThreadsInput => &mut app.threads_input,
                AppFocus::EarlyExportInput => &mut app.early_export_input,
                _ => unreachable!(),
            };
            input.push(c);
        }
        KeyCode::Backspace => {
            let input = match focus {
                AppFocus::ActiveTimeoutInput => &mut app.active_timeout_input,
                AppFocus::IdleTimeoutInput => &mut app.idle_timeout_input,
                AppFocus::ExpirationCheckIntervalInput => &mut app.expiration_check_interval_input,
                AppFocus::ThreadsInput => &mut app.threads_input,
                AppFocus::EarlyExportInput => &mut app.early_export_input,
                _ => unreachable!(),
            };
            input.pop();
        }
        KeyCode::Enter => {
            let input = match focus {
                AppFocus::ActiveTimeoutInput => &mut app.active_timeout_input,
                AppFocus::IdleTimeoutInput => &mut app.idle_timeout_input,
                AppFocus::ExpirationCheckIntervalInput => &mut app.expiration_check_interval_input,
                AppFocus::ThreadsInput => &mut app.threads_input,
                AppFocus::EarlyExportInput => &mut app.early_export_input,
                _ => unreachable!(),
            };
            if let Ok(value) = input.parse::<u64>() {
                match focus {
                    AppFocus::ActiveTimeoutInput => app.config.config.active_timeout = value,
                    AppFocus::IdleTimeoutInput => app.config.config.idle_timeout = value,
                    AppFocus::ExpirationCheckIntervalInput => {
                        app.config.config.expiration_check_interval = value
                    }
                    AppFocus::ThreadsInput => {
                        app.config.config.threads =
                            if value == 0 { None } else { Some(value as u8) }
                    }
                    AppFocus::EarlyExportInput => {
                        app.config.config.early_export = if value == 0 { None } else { Some(value) }
                    }
                    _ => {}
                }
                input.clear();
                app.focus = AppFocus::Menu;
            }
        }
        KeyCode::Left | KeyCode::Esc => {
            let input = match focus {
                AppFocus::ActiveTimeoutInput => &mut app.active_timeout_input,
                AppFocus::IdleTimeoutInput => &mut app.idle_timeout_input,
                AppFocus::ExpirationCheckIntervalInput => &mut app.expiration_check_interval_input,
                AppFocus::ThreadsInput => &mut app.threads_input,
                AppFocus::EarlyExportInput => &mut app.early_export_input,
                _ => unreachable!(),
            };
            input.clear();
            if let AppFocus::ThreadsInput = focus {
                app.config.config.threads = None;
            }
            if let AppFocus::EarlyExportInput = focus {
                app.config.config.early_export = None;
            }
            app.focus = AppFocus::Menu;
        }
        _ => {}
    }
    Ok(())
}

fn handle_boolean_input(
    key: KeyEvent,
    app: &mut App,
    focus: AppFocus,
) -> Result<(), Box<dyn Error>> {
    match key.code {
        KeyCode::Left | KeyCode::Right => match focus {
            AppFocus::IngressOnlyInput => {
                if let Commands::Realtime { ingress_only, .. } = &mut app.config.command {
                    *ingress_only = !*ingress_only;
                }
            }
            AppFocus::PerformanceModeInput => {
                if let ExportMethodType::Csv = &app.config.output.output {
                    app.config.output.performance_mode = !app.config.output.performance_mode;
                }
            }
            AppFocus::HeaderInput => {
                app.config.output.header = !app.config.output.header;
            }
            AppFocus::DropContaminantFeaturesInput => {
                app.config.output.drop_contaminant_features =
                    !app.config.output.drop_contaminant_features;
            }
            _ => {}
        },
        KeyCode::Enter => {
            app.focus = AppFocus::Menu;
        }
        KeyCode::Esc => {
            match focus {
                AppFocus::IngressOnlyInput => {
                    if let Commands::Realtime { ingress_only, .. } = &mut app.config.command {
                        *ingress_only = false;
                    }
                }
                AppFocus::PerformanceModeInput => {
                    if let ExportMethodType::Csv = &app.config.output.output {
                        app.config.output.performance_mode = false;
                    }
                }
                AppFocus::HeaderInput => {
                    app.config.output.header = false;
                }
                AppFocus::DropContaminantFeaturesInput => {
                    app.config.output.drop_contaminant_features = false;
                }
                _ => {}
            }
            app.focus = AppFocus::Menu;
        }
        _ => {}
    }
    Ok(())
}

fn handle_selection_input(
    key: KeyEvent,
    app: &mut App,
    focus: AppFocus,
) -> Result<(), Box<dyn Error>> {
    let (state, max_index) = match focus {
        AppFocus::CommandSelection => (&mut app.command_state, 1),
        AppFocus::OutputSelection => (&mut app.output_state, 1),
        _ => return Ok(()),
    };
    match key.code {
        KeyCode::Up => {
            let i = match state.selected() {
                Some(i) if i > 0 => i - 1,
                _ => 0,
            };
            state.select(Some(i));
        }
        KeyCode::Down => {
            let i = match state.selected() {
                Some(i) if i < max_index => i + 1,
                _ => max_index,
            };
            state.select(Some(i));
        }
        KeyCode::Enter => match focus {
            AppFocus::CommandSelection => match state.selected() {
                Some(0) => {
                    app.config.command = Commands::Realtime {
                        interface: String::new(),
                        ingress_only: false,
                    };
                    app.focus = AppFocus::CommandArgumentInput;
                }
                Some(1) => {
                    app.config.command = Commands::Pcap {
                        path: String::new(),
                    };
                    app.focus = AppFocus::CommandArgumentInput;
                }
                _ => {}
            },
            AppFocus::OutputSelection => match state.selected() {
                Some(0) => {
                    app.config.output.output = ExportMethodType::Print;
                    app.config.output.export_path = None;
                    app.focus = AppFocus::Menu;
                }
                Some(1) => {
                    app.config.output.output = ExportMethodType::Csv;
                    app.config.output.export_path = Some(String::new());
                    app.focus = AppFocus::OutputArgumentInput;
                }
                _ => {}
            },
            _ => {}
        },
        KeyCode::Left | KeyCode::Esc => {
            app.focus = AppFocus::Menu;
        }
        _ => {}
    }
    Ok(())
}

fn handle_command_argument_input(key: KeyEvent, app: &mut App) -> Result<(), Box<dyn Error>> {
    match key.code {
        KeyCode::Char(c) => match &mut app.config.command {
            Commands::Realtime { interface, .. } => {
                interface.push(c);
            }
            Commands::Pcap { path } => {
                path.push(c);
            }
        },
        KeyCode::Backspace => match &mut app.config.command {
            Commands::Realtime { interface, .. } => {
                interface.pop();
            }
            Commands::Pcap { path } => {
                path.pop();
            }
        },
        KeyCode::Enter => match &app.config.command {
            Commands::Realtime { .. } => {
                app.focus = AppFocus::IngressOnlyInput;
            }
            Commands::Pcap { .. } => {
                app.focus = AppFocus::Menu;
            }
        },
        KeyCode::Left | KeyCode::Esc => {
            match &mut app.config.command {
                Commands::Realtime {
                    interface,
                    ingress_only,
                } => {
                    interface.clear();
                    *ingress_only = false;
                }
                Commands::Pcap { path } => {
                    path.clear();
                }
            }
            app.focus = AppFocus::Menu;
        }
        _ => {}
    }
    Ok(())
}

fn handle_output_argument_input(key: KeyEvent, app: &mut App) -> Result<(), Box<dyn Error>> {
    match key.code {
        KeyCode::Char(c) => {
            if let Some(ref mut export_path) = app.config.output.export_path {
                export_path.push(c);
            }
        }
        KeyCode::Backspace => {
            if let Some(ref mut export_path) = app.config.output.export_path {
                export_path.pop();
            }
        }
        KeyCode::Enter => {
            app.focus = AppFocus::PerformanceModeInput;
        }
        KeyCode::Left | KeyCode::Esc => {
            if let Some(ref mut export_path) = app.config.output.export_path {
                export_path.clear();
            }
            app.focus = AppFocus::Menu;
        }
        _ => {}
    }
    Ok(())
}

fn handle_config_file_input(key: KeyEvent, app: &mut App) -> Result<(), Box<dyn Error>> {
    match key.code {
        KeyCode::Char(c) => {
            app.config_file_input.push(c); // Add character to input
        }
        KeyCode::Backspace => {
            app.config_file_input.pop(); // Remove last character from input
        }
        KeyCode::Enter => {
            // Attempt to load the configuration file
            if fs::metadata(&app.config_file_input).is_ok() {
                app.config_file = Some(app.config_file_input.clone());
                let config = match confy::load_path::<ConfigFile>(app.config_file_input.clone()) {
                    Ok(config_file) => Config {
                        config: config_file.config,
                        output: config_file.output,
                        command: Commands::Realtime {
                            interface: String::from("eth0"),
                            ingress_only: false,
                        },
                    },
                    Err(_) => Config::reset(),
                };
                app.config = config;
                app.focus = AppFocus::Menu;
            } else {
                app.focus = AppFocus::Menu;
            }
        }
        _ => {}
    }
    Ok(())
}

fn handle_config_file_save_input(key: KeyEvent, app: &mut App) -> Result<(), Box<dyn Error>> {
    match key.code {
        KeyCode::Char(c) => {
            app.config_file_input.push(c);
        }
        KeyCode::Backspace => {
            app.config_file_input.pop();
        }
        KeyCode::Enter => {
            let config_file_name = app.config_file_input.clone();

            if let Err(e) = confy::store_path(
                &config_file_name,
                ConfigFile {
                    config: app.config.config.clone(),
                    output: app.config.output.clone(),
                },
            ) {
                error!(
                    "Error saving configuration to file: {} \nError: {} \nPlease try again.",
                    config_file_name, e
                );
            } else {
                app.config_file = Some(config_file_name);
            }

            app.focus = AppFocus::Menu;
        }
        _ => {}
    }
    Ok(())
}

fn ui_main_screen<B: Backend>(f: &mut Frame<B>, app: &App) {
    let size = f.size();

    let background = Block::default().style(Style::default().bg(Color::Black));

    // Render the background block over the entire terminal area
    f.render_widget(background, size);

    if matches!(app.focus, AppFocus::ConfigFileInput) {
        render_config_file_input(f, app, centered_rect(80, 15, size));
        return; // Skip the rest of the UI rendering for other elements
    }

    if matches!(app.focus, AppFocus::ConfigFileSaveInput) {
        render_config_file_save(f, app, centered_rect(80, 15, size));
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
        .split(size);

    // Title Bar
    let title_bar_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(chunks[0]);

    let rustiflow_art = "
    █▀█ █ █ █▀ ▀█▀ █ █▀▀ █   █▀█ █ █ █
    █▀▄ █▄█ ▄█  █  █ █▀  █▄▄ █▄█ ▀▄▀▄▀";

    let art_paragraph = Paragraph::new(rustiflow_art)
        .style(Style::default().fg(Color::Yellow))
        .alignment(Alignment::Left);

    f.render_widget(art_paragraph, title_bar_layout[0]);

    render_title_buttons(f, app, title_bar_layout[1]);

    // Split the rest of the screen into three columns
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage(38), // Left column: Menu
                Constraint::Percentage(25), // Middle column: Content
                Constraint::Percentage(37), // Right column: Current Selections
            ]
            .as_ref(),
        )
        .split(chunks[1]);

    // Left Column: Menu
    render_menu(f, app, columns[0]);

    // Middle Column: Content based on menu selection
    render_content(f, app, columns[1]);

    // Right Column: Current Selections
    render_current_selections(f, app, columns[2]);

    // Popups
    render_popups(f, app, size);
}

fn render_title_buttons<B: Backend>(f: &mut Frame<B>, app: &App, area: Rect) {
    let buttons_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage(24),
                Constraint::Length(1),
                Constraint::Percentage(24),
                Constraint::Length(1),
                Constraint::Percentage(24),
                Constraint::Length(1),
                Constraint::Percentage(24),
            ]
            .as_ref(),
        )
        .split(area);

    let start_button = create_button(
        " Start ",
        app.title_bar_state.selected() == Some(0) && matches!(app.focus, AppFocus::TitleBar),
        Color::Green,
    );

    let quit_button = create_button(
        " Quit ",
        app.title_bar_state.selected() == Some(1) && matches!(app.focus, AppFocus::TitleBar),
        Color::Red,
    );

    let save_button = create_button(
        " Save ",
        app.title_bar_state.selected() == Some(2) && matches!(app.focus, AppFocus::TitleBar),
        Color::Blue,
    );

    let reset_button = create_button(
        " Reset ",
        app.title_bar_state.selected() == Some(3) && matches!(app.focus, AppFocus::TitleBar),
        Color::Yellow,
    );

    f.render_widget(start_button, buttons_layout[0]);
    f.render_widget(quit_button, buttons_layout[2]);
    f.render_widget(save_button, buttons_layout[4]);
    f.render_widget(reset_button, buttons_layout[6]);
}

fn create_button<'a>(label: &'a str, selected: bool, color: Color) -> Paragraph<'a> {
    Paragraph::new(label)
        .style(if selected {
            Style::default().fg(color).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(color)
        })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(if selected {
                    Style::default().fg(color).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(color).add_modifier(Modifier::DIM)
                }),
        )
        .alignment(Alignment::Center)
}

fn render_menu<B: Backend>(f: &mut Frame<B>, app: &App, area: Rect) {
    let menu_items: Vec<ListItem> = app
        .main_menu_items
        .iter()
        .map(|item| ListItem::new(*item))
        .collect();

    let menu = List::new(menu_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(
                    Style::default()
                        .fg(if matches!(app.focus, AppFocus::Menu) {
                            Color::Yellow
                        } else {
                            Color::Cyan
                        })
                        .add_modifier(Modifier::BOLD),
                )
                .title("Menu"),
        )
        .highlight_style(
            Style::default()
                .fg(if matches!(app.focus, AppFocus::Menu) {
                    Color::Yellow
                } else {
                    Color::Reset
                })
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(menu, area, &mut app.main_menu_state.clone());
}

fn render_content<B: Backend>(f: &mut Frame<B>, app: &App, area: Rect) {
    match app.main_menu_state.selected() {
        Some(0) => {
            let items: Vec<ListItem> = FlowType::VARIANTS
                .iter()
                .map(|s| ListItem::new(*s))
                .collect();
            render_selectable_list(
                f,
                area,
                items,
                "Feature Set",
                matches!(app.focus, AppFocus::FlowType),
                &app.flow_type_state,
            );
        }
        Some(1) => {
            let items = vec![ListItem::new("Realtime"), ListItem::new("Pcap")];
            render_selectable_list(
                f,
                area,
                items,
                "Select Mode",
                matches!(app.focus, AppFocus::CommandSelection),
                &app.command_state,
            );
        }
        Some(2) => {
            let items = vec![ListItem::new("Print"), ListItem::new("Csv")];
            render_selectable_list(
                f,
                area,
                items,
                "Select Output Method",
                matches!(app.focus, AppFocus::OutputSelection),
                &app.output_state,
            );
        }
        Some(3) => {
            render_input_paragraph(
                f,
                area,
                app.active_timeout_input.as_ref(),
                "Enter Active Timeout (seconds)",
                matches!(app.focus, AppFocus::ActiveTimeoutInput),
            );
        }
        Some(4) => {
            render_input_paragraph(
                f,
                area,
                app.idle_timeout_input.as_ref(),
                "Enter Idle Timeout (seconds)",
                matches!(app.focus, AppFocus::IdleTimeoutInput),
            );
        }
        Some(5) => {
            render_input_paragraph(
                f,
                area,
                app.expiration_check_interval_input.as_ref(),
                "Enter Expiration Check Interval (seconds)",
                matches!(app.focus, AppFocus::ExpirationCheckIntervalInput),
            );
        }
        Some(6) => {
            render_input_paragraph(
                f,
                area,
                app.threads_input.as_ref(),
                "Enter Threads (0 for auto)",
                matches!(app.focus, AppFocus::ThreadsInput),
            );
        }
        Some(7) => {
            render_input_paragraph(
                f,
                area,
                app.early_export_input.as_ref(),
                "Enter Early Export (seconds)",
                matches!(app.focus, AppFocus::EarlyExportInput),
            );
        }
        Some(8) => {
            render_boolean_choice(f, area, app.config.output.header);
        }
        Some(9) => {
            render_boolean_choice(f, area, app.config.output.drop_contaminant_features);
        }
        _ => {}
    }
}

fn render_selectable_list<B: Backend>(
    f: &mut Frame<B>,
    area: Rect,
    items: Vec<ListItem>,
    title: &str,
    focus: bool,
    state: &ListState,
) {
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(
                    Style::default()
                        .fg(if focus { Color::Yellow } else { Color::Cyan })
                        .add_modifier(Modifier::BOLD),
                ),
        )
        .highlight_style(
            Style::default()
                .fg(if focus { Color::Yellow } else { Color::Reset })
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(list, area, &mut state.clone());
}

fn render_input_paragraph<B: Backend>(
    f: &mut Frame<B>,
    area: Rect,
    input: &str,
    title: &str,
    focus: bool,
) {
    let paragraph = Paragraph::new(input)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(
                    Style::default()
                        .fg(if focus { Color::Yellow } else { Color::Cyan })
                        .add_modifier(Modifier::BOLD),
                ),
        )
        .style(Style::default().fg(Color::Yellow));

    f.render_widget(paragraph, area);
}

fn render_boolean_choice<B: Backend>(f: &mut Frame<B>, area: Rect, is_true_selected: bool) {
    let true_button = create_button(" True ", is_true_selected, Color::Green);
    let false_button = create_button(" False ", !is_true_selected, Color::Red);

    let buttons_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(area);

    f.render_widget(true_button, buttons_layout[0]);
    f.render_widget(false_button, buttons_layout[1]);
}

fn render_current_selections<B: Backend>(f: &mut Frame<B>, app: &App, area: Rect) {
    let mut selections = vec![
        ListItem::new(Spans::from(vec![
            Span::raw("Feature Set: "),
            Span::styled(
                format!("{:?}", app.config.config.features),
                Style::default().fg(Color::Yellow),
            ),
        ])),
        ListItem::new(Spans::from(vec![
            Span::raw("Output Method: "),
            Span::styled(
                format!("{:?}", app.config.output.output),
                Style::default().fg(Color::Yellow),
            ),
        ])),
        ListItem::new(Spans::from(vec![
            Span::raw("Output Path: "),
            Span::styled(
                format!("{:?}", app.config.output.export_path),
                Style::default().fg(Color::Yellow),
            ),
        ])),
        ListItem::new(Spans::from(vec![
            Span::raw("Performance Mode: "),
            Span::styled(
                format!("{:?}", app.config.output.performance_mode),
                Style::default().fg(Color::Yellow),
            ),
        ])),
        ListItem::new(Spans::from(vec![
            Span::raw("Active Timeout: "),
            Span::styled(
                format!("{}", app.config.config.active_timeout),
                Style::default().fg(Color::Yellow),
            ),
        ])),
        ListItem::new(Spans::from(vec![
            Span::raw("Idle Timeout: "),
            Span::styled(
                format!("{}", app.config.config.idle_timeout),
                Style::default().fg(Color::Yellow),
            ),
        ])),
        ListItem::new(Text::from(vec![
            Spans::from(vec![Span::raw("Expiration Check")]),
            Spans::from(vec![
                Span::raw("Interval: "),
                Span::styled(
                    format!("{}", app.config.config.expiration_check_interval),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
        ])),
        ListItem::new(Spans::from(vec![
            Span::raw("Threads: "),
            Span::styled(
                format!("{:?}", app.config.config.threads),
                Style::default().fg(Color::Yellow),
            ),
        ])),
        ListItem::new(Spans::from(vec![
            Span::raw("Early Export: "),
            Span::styled(
                format!("{:?}", app.config.config.early_export),
                Style::default().fg(Color::Yellow),
            ),
        ])),
        ListItem::new(Spans::from(vec![
            Span::raw("Header: "),
            Span::styled(
                format!("{}", app.config.output.header),
                Style::default().fg(Color::Yellow),
            ),
        ])),
        ListItem::new(Text::from(vec![
            Spans::from(vec![Span::raw("Drop Contaminant")]),
            Spans::from(vec![
                Span::raw("Features: "),
                Span::styled(
                    format!("{}", app.config.output.drop_contaminant_features),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
        ])),
    ];

    // Build the Mode entry dynamically
    let mode_item = match &app.config.command {
        Commands::Realtime {
            interface,
            ingress_only,
        } => {
            let mut text = Text::from(Spans::from(vec![
                Span::raw("Mode: "),
                Span::styled("Realtime", Style::default().fg(Color::Yellow)),
            ]));

            text.extend(vec![Spans::from(vec![
                Span::raw("Interface: "),
                Span::styled(interface, Style::default().fg(Color::Yellow)),
            ])]);

            text.extend(vec![Spans::from(vec![
                Span::raw("Ingress only: "),
                Span::styled(
                    format!("{}", ingress_only),
                    Style::default().fg(Color::Yellow),
                ),
            ])]);

            ListItem::new(text)
        }
        Commands::Pcap { path } => {
            let mut text = Text::from(Spans::from(vec![
                Span::raw("Mode: "),
                Span::styled("Pcap", Style::default().fg(Color::Yellow)),
            ]));

            text.extend(vec![Spans::from(vec![
                Span::raw("Path: "),
                Span::styled(path, Style::default().fg(Color::Yellow)),
            ])]);

            ListItem::new(text)
        }
    };

    selections.insert(1, mode_item);

    let selections_list = List::new(selections)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title("Current Selections"),
        )
        .style(Style::default());

    f.render_widget(selections_list, area);
}

fn render_popups<B: Backend>(f: &mut Frame<B>, app: &App, size: Rect) {
    if matches!(app.focus, AppFocus::CommandArgumentInput) {
        let (input_text, title) = match &app.config.command {
            Commands::Realtime { interface, .. } => (interface.as_str(), "Enter Interface"),
            Commands::Pcap { path } => (path.as_str(), "Enter Pcap File Path"),
        };
        render_popup_input(f, size, input_text, title);
    }

    if matches!(app.focus, AppFocus::OutputArgumentInput) {
        let input_text = app.config.output.export_path.as_deref().unwrap_or("");
        render_popup_input(f, size, input_text, "Enter Output Path");
    }

    if matches!(app.focus, AppFocus::IngressOnlyInput) {
        let is_true_selected = match &app.config.command {
            Commands::Realtime { ingress_only, .. } => *ingress_only,
            _ => false,
        };

        let popup_area = centered_rect(50, 25, size);
        f.render_widget(Clear, popup_area);

        let boolean_input_block = Block::default()
            .title("Ingress Only?")
            .borders(Borders::ALL)
            .style(Style::default().bg(Color::Black))
            .border_style(Style::default().fg(Color::Yellow));

        let inner_area = boolean_input_block.inner(popup_area);

        f.render_widget(boolean_input_block, popup_area);

        render_boolean_choice(f, inner_area, is_true_selected);
    }

    if matches!(app.focus, AppFocus::PerformanceModeInput) {
        let is_true_selected = match &app.config.output.output {
            ExportMethodType::Csv => app.config.output.performance_mode,
            _ => false,
        };

        let popup_area = centered_rect(50, 25, size);
        f.render_widget(Clear, popup_area);

        let boolean_input_block = Block::default()
            .title("Performance mode (no graph)?")
            .borders(Borders::ALL)
            .style(Style::default().bg(Color::Black))
            .border_style(Style::default().fg(Color::Yellow));

        let inner_area = boolean_input_block.inner(popup_area);

        f.render_widget(boolean_input_block, popup_area);

        render_boolean_choice(f, inner_area, is_true_selected);
    }
}

fn render_popup_input<B: Backend>(f: &mut Frame<B>, size: Rect, input_text: &str, title: &str) {
    let command_input_block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::Yellow));

    let paragraph = Paragraph::new(input_text)
        .block(command_input_block)
        .style(Style::default().fg(Color::White));

    // Center the block in the middle of the screen
    let popup_area = centered_rect(50, 15, size);
    f.render_widget(Clear, popup_area);
    f.render_widget(
        Block::default().style(Style::default().bg(Color::Black)),
        popup_area,
    );
    f.render_widget(paragraph, popup_area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}

fn render_config_file_input<B: Backend>(f: &mut Frame<B>, app: &App, area: Rect) {
    let config_file_input = Paragraph::new(app.config_file_input.as_ref())
        .block(
            Block::default()
                .title("Enter Configuration File Path or press ENTER to start clean")
                .borders(Borders::ALL)
                .border_style(
                    Style::default()
                        .fg(if matches!(app.focus, AppFocus::ConfigFileInput) {
                            Color::Yellow
                        } else {
                            Color::Cyan
                        })
                        .add_modifier(Modifier::BOLD),
                ),
        )
        .style(Style::default().fg(Color::Yellow));

    f.render_widget(config_file_input, area);
}

fn render_config_file_save<B: Backend>(f: &mut Frame<B>, app: &App, area: Rect) {
    let config_file_save = Paragraph::new(app.config_file_input.as_ref())
        .block(
            Block::default()
                .title("Enter Configuration File Path to Save")
                .borders(Borders::ALL)
                .border_style(
                    Style::default()
                        .fg(if matches!(app.focus, AppFocus::ConfigFileSaveInput) {
                            Color::Yellow
                        } else {
                            Color::Cyan
                        })
                        .add_modifier(Modifier::BOLD),
                ),
        )
        .style(Style::default().fg(Color::Yellow));

    f.render_widget(config_file_save, area);
}

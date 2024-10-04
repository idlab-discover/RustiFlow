mod args;
mod flow_table;
mod flows;
mod output;
mod packet_features;
mod pcap;
mod realtime;

use crate::flows::{cic_flow::CicFlow, ntl_flow::NTLFlow};
use crate::pcap::read_pcap_file;
use crate::realtime::handle_realtime;

use args::{Cli, Commands, ConfigFile, ExportConfig, ExportMethodType, FlowType, OutputConfig};
use clap::Parser;
use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use flows::{
    basic_flow::BasicFlow, cidds_flow::CiddsFlow, custom_flow::CustomFlow, flow::Flow,
    nf_flow::NfFlow,
};
use log::{debug, error};
use output::OutputWriter;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::io;
use std::time::Instant;
use strum::VariantNames;
use tokio::sync::mpsc;
use tui::backend::{Backend, CrosstermBackend};
use tui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use tui::style::{Color, Modifier, Style};
use tui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};
use tui::{Frame, Terminal};

// Define your Config struct
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub config: ExportConfig,
    pub output: OutputConfig,
    pub command: Commands,
}

impl Default for Config {
    fn default() -> Self {
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
            },
            command: Commands::Realtime {
                interface: String::from("eth0"),
                ingress_only: false,
            },
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    if std::env::args().len() == 1 {
        // No arguments provided, launch TUI
        let config = launch_tui().await.unwrap_or_else(|e| {
            error!("Error: {:?}", e);
            std::process::exit(1);
        });
        run_with_config(config).await;
    } else {
        let cli = Cli::parse();

        // If a config file is provided, load it
        let config: Config = if let Some(config_path) = cli.config_file {
            // Try to load config from file
            match confy::load_path::<ConfigFile>(config_path) {
                Ok(cfg_file) => Config {
                    config: cfg_file.config,
                    output: cfg_file.output,
                    command: cli.command,
                },
                Err(e) => {
                    error!("Error loading configuration file: {:?}", e);
                    return;
                }
            }
        } else {
            // No config file: build config from CLI arguments
            Config {
                config: ExportConfig {
                    features: cli.features.unwrap(),
                    active_timeout: cli.active_timeout,
                    idle_timeout: cli.idle_timeout,
                    early_export: cli.early_export,
                    threads: cli.threads,
                    expiration_check_interval: cli.expiration_check_interval,
                },
                output: OutputConfig {
                    output: cli.output.unwrap(),
                    export_path: cli.export_path,
                    header: cli.header,
                    drop_contaminant_features: cli.drop_contaminant_features,
                },
                command: cli.command,
            }
        };

        run_with_config(config).await;
    }
}

async fn run_with_config(config: Config) {
    // Start the selected command
    match config.command {
        Commands::Realtime { interface, ingress_only } => {
            macro_rules! execute_realtime {
                ($flow_ty:ty) => {{
                    // Create output writer and initialize it
                    let mut output_writer = OutputWriter::<$flow_ty>::new(
                        config.output.output,
                        config.output.header,
                        config.output.drop_contaminant_features,
                        config.output.export_path,
                    );

                    // Synchronous initialization to ensure headers are written
                    output_writer.init();

                    // Create channel for exporting flows
                    let (sender, mut receiver) = mpsc::channel::<$flow_ty>(1000);

                    // Start the output writer in a separate task
                    let output_task = tokio::spawn(async move {
                        while let Some(flow) = receiver.recv().await {
                            if let Err(e) = output_writer.write_flow(flow) {
                                error!("Error writing flow: {:?}", e);
                            }
                        }

                        // Ensure that all remaining flows are flushed properly before ending
                        output_writer.flush_and_close().unwrap_or_else(|e| {
                            error!("Error flushing and closing the writer: {:?}", e);
                        });
                        debug!("OutputWriter task finished");
                    });

                    let start = Instant::now();
                    if let Err(err) = handle_realtime::<$flow_ty>(
                        &interface,
                        sender,
                        config.config.threads.unwrap_or(num_cpus::get() as u8),
                        config.config.active_timeout,
                        config.config.idle_timeout,
                        config.config.early_export,
                        config.config.expiration_check_interval,
                        ingress_only,
                    )
                    .await
                    {
                        error!("Error: {:?}", err);
                    }

                    // Wait for the output task to finish
                    output_task.await.unwrap_or_else(|e| {
                        error!("Error waiting for output task: {:?}", e);
                    });

                    let end = Instant::now();
                    debug!(
                        "Duration: {:?} milliseconds",
                        end.duration_since(start).as_millis()
                    );
                }};
            }

            match config.config.features {
                FlowType::Basic => execute_realtime!(BasicFlow),
                FlowType::CIC => execute_realtime!(CicFlow),
                FlowType::CIDDS => execute_realtime!(CiddsFlow),
                FlowType::Nfstream => execute_realtime!(NfFlow),
                FlowType::NTL => execute_realtime!(NTLFlow),
                FlowType::Custom => execute_realtime!(CustomFlow),
            }
        }
        Commands::Pcap { path } => {
            macro_rules! execute_offline {
                ($flow_ty:ty) => {{
                    // Create output writer and initialize it
                    let mut output_writer = OutputWriter::<$flow_ty>::new(
                        config.output.output,
                        config.output.header,
                        config.output.drop_contaminant_features,
                        config.output.export_path,
                    );

                    // Synchronous initialization to ensure headers are written
                    output_writer.init();

                    // Create channel for exporting flows
                    let (sender, mut receiver) = mpsc::channel::<$flow_ty>(1000);

                    // Start the output writer in a separate task
                    let output_task = tokio::spawn(async move {
                        while let Some(flow) = receiver.recv().await {
                            if let Err(e) = output_writer.write_flow(flow) {
                                error!("Error writing flow: {:?}", e);
                            }
                        }

                        // Ensure that all remaining flows are flushed properly before ending
                        output_writer.flush_and_close().unwrap_or_else(|e| {
                            error!("Error flushing and closing the writer: {:?}", e);
                        });
                        debug!("OutputWriter task finished");
                    });

                    let start = Instant::now();

                    if let Err(err) = read_pcap_file::<$flow_ty>(
                        &path,
                        sender,
                        config.config.threads.unwrap_or(num_cpus::get() as u8),
                        config.config.active_timeout,
                        config.config.idle_timeout,
                        config.config.early_export,
                        config.config.expiration_check_interval,
                    )
                    .await
                    {
                        error!("Error: {:?}", err);
                    }

                    // Wait for the output task to finish
                    output_task.await.unwrap_or_else(|e| {
                        error!("Error waiting for output task: {:?}", e);
                    });

                    let end = Instant::now();
                    debug!(
                        "Duration: {:?} milliseconds",
                        end.duration_since(start).as_millis()
                    );
                }};
            }

            match config.config.features {
                FlowType::Basic => execute_offline!(BasicFlow),
                FlowType::CIC => execute_offline!(CicFlow),
                FlowType::CIDDS => execute_offline!(CiddsFlow),
                FlowType::Nfstream => execute_offline!(NfFlow),
                FlowType::NTL => execute_offline!(NTLFlow),
                FlowType::Custom => execute_offline!(CustomFlow),
            }
        }
    }
}

async fn launch_tui() -> Result<Config, Box<dyn Error>> {
    // setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let mut app = App::new();

    // Run the app
    let res = run_app(&mut terminal, &mut app).await;

    // Restore terminal
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
    focus: AppFocus,
    title_bar_state: ListState,
    main_menu_state: ListState,
    flow_type_state: ListState,
    command_state: ListState,
    output_state: ListState,
    active_timeout_input: String,
    idle_timeout_input: String,
}

impl App {
    fn new() -> App {
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

        App {
            config: Config::default(),
            focus: AppFocus::Menu,
            title_bar_state,
            main_menu_state,
            flow_type_state,
            command_state,
            output_state,
            active_timeout_input: String::new(),
            idle_timeout_input: String::new(),
        }
    }
}

enum AppFocus {
    Menu,
    TitleBar,
    FlowType,
    ActiveTimeoutInput,
    IdleTimeoutInput,
    CommandSelection,
    OutputSelection,
    CommandArgumentInput,
    OutputArgumentInput,
    IngressOnlyInput,
    // Add other focus states as needed
}

async fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<Config, Box<dyn Error>> {
    loop {
        terminal.draw(|f| ui_main_screen(f, app))?;

        if crossterm::event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match app.focus {
                    AppFocus::TitleBar => {
                        match key.code {
                            KeyCode::Left => {
                                let i = match app.title_bar_state.selected() {
                                    Some(i) => {
                                        if i == 0 {
                                            0
                                        } else {
                                            i - 1
                                        }
                                    }
                                    None => 0,
                                };
                                app.title_bar_state.select(Some(i));
                            }
                            KeyCode::Right => {
                                let i = match app.title_bar_state.selected() {
                                    Some(i) => {
                                        if i >= 1 {
                                            1
                                        } else {
                                            i + 1
                                        }
                                    }
                                    None => 0,
                                };
                                app.title_bar_state.select(Some(i));
                            }
                            KeyCode::Enter => {
                                match app.title_bar_state.selected() {
                                    Some(0) => {
                                        // Start
                                        return Ok(app.config.clone());
                                    }
                                    Some(1) => {
                                        // Quit
                                        return Err("User quit".into());
                                    }
                                    _ => {}
                                }
                            }
                            KeyCode::Down => {
                                app.focus = AppFocus::Menu;
                            }
                            _ => {}
                        }
                    }
                    AppFocus::Menu => {
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
                                    Some(i) => {
                                        if i >= 4 {
                                            4
                                        } else {
                                            i + 1
                                        }
                                    }
                                    None => 0,
                                };
                                app.main_menu_state.select(Some(i));
                            }
                            KeyCode::Enter | KeyCode::Right => {
                                match app.main_menu_state.selected() {
                                    Some(0) => app.focus = AppFocus::FlowType,
                                    Some(1) => app.focus = AppFocus::CommandSelection,
                                    Some(2) => app.focus = AppFocus::OutputSelection,
                                    Some(3) => app.focus = AppFocus::ActiveTimeoutInput,
                                    Some(4) => app.focus = AppFocus::IdleTimeoutInput,
                                    _ => {}
                                }
                            }
                            KeyCode::Esc => {
                                return Err("User quit".into());
                            }
                            _ => {}
                        }
                    }
                    AppFocus::FlowType => match key.code {
                        KeyCode::Up => {
                            let i = match app.flow_type_state.selected() {
                                Some(i) => {
                                    if i == 0 {
                                        0
                                    } else {
                                        i - 1
                                    }
                                }
                                None => 0,
                            };
                            app.flow_type_state.select(Some(i));
                        }
                        KeyCode::Down => {
                            let i = match app.flow_type_state.selected() {
                                Some(i) => {
                                    if i >= FlowType::VARIANTS.len() - 1 {
                                        FlowType::VARIANTS.len() - 1
                                    } else {
                                        i + 1
                                    }
                                }
                                None => 0,
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
                    },
                    AppFocus::ActiveTimeoutInput => match key.code {
                        KeyCode::Char(c) if c.is_digit(10) => {
                            app.active_timeout_input.push(c);
                        }
                        KeyCode::Backspace => {
                            app.active_timeout_input.pop();
                        }
                        KeyCode::Enter => {
                            if let Ok(timeout) = app.active_timeout_input.parse::<u64>() {
                                app.config.config.active_timeout = timeout;
                                app.active_timeout_input.clear();
                                app.focus = AppFocus::Menu;
                            }
                        }
                        KeyCode::Left | KeyCode::Esc => {
                            app.active_timeout_input.clear();
                            app.focus = AppFocus::Menu;
                        }
                        _ => {}
                    },
                    AppFocus::IdleTimeoutInput => match key.code {
                        KeyCode::Char(c) if c.is_digit(10) => {
                            app.idle_timeout_input.push(c);
                        }
                        KeyCode::Backspace => {
                            app.idle_timeout_input.pop();
                        }
                        KeyCode::Enter => {
                            if let Ok(timeout) = app.idle_timeout_input.parse::<u64>() {
                                app.config.config.idle_timeout = timeout;
                                app.idle_timeout_input.clear();
                                app.focus = AppFocus::Menu;
                            }
                        }
                        KeyCode::Left | KeyCode::Esc => {
                            app.idle_timeout_input.clear();
                            app.focus = AppFocus::Menu;
                        }
                        _ => {}
                    },
                    AppFocus::CommandSelection => match key.code {
                        KeyCode::Up => {
                            let i = match app.command_state.selected() {
                                Some(i) => {
                                    if i == 0 {
                                        0
                                    } else {
                                        i - 1
                                    }
                                }
                                None => 0,
                            };
                            app.command_state.select(Some(i));
                        }
                        KeyCode::Down => {
                            let i = match app.command_state.selected() {
                                Some(i) => {
                                    if i >= 1 {
                                        1
                                    } else {
                                        i + 1
                                    }
                                }
                                None => 0,
                            };
                            app.command_state.select(Some(i));
                        }
                        KeyCode::Enter => match app.command_state.selected() {
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
                        KeyCode::Left | KeyCode::Esc => {
                            app.focus = AppFocus::Menu;
                        }
                        _ => {}
                    },
                    AppFocus::OutputSelection => match key.code {
                        KeyCode::Up => {
                            let i = match app.output_state.selected() {
                                Some(i) => {
                                    if i == 0 {
                                        0
                                    } else {
                                        i - 1
                                    }
                                }
                                None => 0,
                            };
                            app.output_state.select(Some(i));
                        }
                        KeyCode::Down => {
                            let i = match app.output_state.selected() {
                                Some(i) => {
                                    if i >= 1 {
                                        1
                                    } else {
                                        i + 1
                                    }
                                }
                                None => 0,
                            };
                            app.output_state.select(Some(i));
                        }
                        KeyCode::Enter => match app.output_state.selected() {
                            Some(0) => {
                                app.config.output.output = ExportMethodType::Print;
                                app.config.output.export_path = None;
                            }
                            Some(1) => {
                                app.config.output.output = ExportMethodType::Csv;
                                app.config.output.export_path = Some(String::new());
                                app.focus = AppFocus::OutputArgumentInput;
                            }
                            _ => {}
                        },
                        KeyCode::Left | KeyCode::Esc => {
                            app.focus = AppFocus::Menu;
                        }
                        _ => {}
                    },
                    AppFocus::CommandArgumentInput => match key.code {
                        KeyCode::Char(c) => match &mut app.config.command {
                            Commands::Realtime { interface, ingress_only: _ } => {
                                interface.push(c);
                            }
                            Commands::Pcap { path } => {
                                path.push(c);
                            }
                        },
                        KeyCode::Backspace => match &mut app.config.command {
                            Commands::Realtime { interface, ingress_only: _ } => {
                                interface.pop();
                            }
                            Commands::Pcap { path } => {
                                path.pop();
                            }
                        },
                        KeyCode::Enter => match &mut app.config.command {
                            Commands::Realtime { interface: _, ingress_only: _ } => {
                                app.focus = AppFocus::IngressOnlyInput;
                            }
                            Commands::Pcap { path: _ } => {
                                app.focus = AppFocus::Menu;
                            }
                            
                        }
                        KeyCode::Left | KeyCode::Esc => {
                            match &mut app.config.command {
                                Commands::Realtime { interface, ingress_only} => {
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
                    },
                    AppFocus::OutputArgumentInput => match key.code {
                        KeyCode::Char(c) => match &mut app.config.output.output {
                            ExportMethodType::Csv => {
                                if let Some(ref mut export_path) = app.config.output.export_path {
                                    export_path.push(c);
                                }
                            },
                            _ => {}
                        },
                        KeyCode::Backspace => match &mut app.config.output.output {
                            ExportMethodType::Csv => {
                                if let Some(ref mut export_path) = app.config.output.export_path {
                                    export_path.pop();
                                }
                            },
                            _ => {}
                        },
                        KeyCode::Enter => {
                            app.focus = AppFocus::Menu;
                        }
                        KeyCode::Left | KeyCode::Esc => {
                            match &mut app.config.output.output {
                                ExportMethodType::Csv => {
                                    if let Some(ref mut export_path) = app.config.output.export_path {
                                        export_path.clear();
                                    }
                                },
                                _ => {}
                            }
                            app.focus = AppFocus::Menu;
                        }
                        _ => {}
                    },
                    AppFocus::IngressOnlyInput => match key.code {
                        KeyCode::Left | KeyCode::Right => {
                            if let Commands::Realtime { ingress_only, .. } = &mut app.config.command {
                                *ingress_only = !*ingress_only;
                            }
                        }
                        KeyCode::Enter => {
                            app.focus = AppFocus::Menu;
                        }
                        KeyCode::Esc => {
                            if let Commands::Realtime { ingress_only, .. } = &mut app.config.command {
                                *ingress_only = false;
                            }
                            app.focus = AppFocus::Menu;
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

fn ui_main_screen<B: Backend>(f: &mut Frame<B>, app: &App) {
    let size = f.size();

    // Create a block with the desired background color
    let background = Block::default().style(Style::default().bg(Color::Black));

    // Render the background block over the entire terminal area
    f.render_widget(background, size);

    // Split the layout into vertical chunks
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(3), // Adjust height for the title bar
                Constraint::Min(0),    // Rest of the screen
            ]
            .as_ref(),
        )
        .split(size);

    // Title Bar
    let title_bar_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage(60), // Height for the RUSTIFLOW art
                Constraint::Percentage(40), // Height for the buttons
            ]
            .as_ref(),
        )
        .split(chunks[0]);

    // Render RUSTIFLOW art
    let rustiflow_art = "
    █▀█ █ █ █▀ ▀█▀ █ █▀▀ █   █▀█ █ █ █
    █▀▄ █▄█ ▄█  █  █ █▀  █▄▄ █▄█ ▀▄▀▄▀";

    let art_paragraph = Paragraph::new(rustiflow_art)
        .style(Style::default().fg(Color::Yellow))
        .alignment(Alignment::Left);

    f.render_widget(art_paragraph, title_bar_layout[0]);

    // Render Start and Quit buttons
    let buttons_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage(40),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Percentage(40),
            ]
            .as_ref(),
        )
        .split(title_bar_layout[1]);

    let start_button = Paragraph::new(" Start ")
        .style(
            if app.title_bar_state.selected() == Some(0) && matches!(app.focus, AppFocus::TitleBar)
            {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Green)
            },
        )
        .block(Block::default().borders(Borders::ALL).border_style(
            if app.title_bar_state.selected() == Some(0) && matches!(app.focus, AppFocus::TitleBar)
            {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::DIM)
            },
        ))
        .alignment(Alignment::Center);

    let quit_button = Paragraph::new(" Quit ")
        .style(
            if app.title_bar_state.selected() == Some(1) && matches!(app.focus, AppFocus::TitleBar)
            {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Red)
            },
        )
        .block(Block::default().borders(Borders::ALL).border_style(
            if app.title_bar_state.selected() == Some(1) && matches!(app.focus, AppFocus::TitleBar)
            {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Red).add_modifier(Modifier::DIM)
            },
        ))
        .alignment(Alignment::Center);

    f.render_widget(start_button, buttons_layout[1]);
    f.render_widget(quit_button, buttons_layout[2]);

    // Split the rest of the screen into three columns
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage(30), // Left column: Menu
                Constraint::Percentage(40), // Middle column: Content
                Constraint::Percentage(30), // Right column: Current Selections
            ]
            .as_ref(),
        )
        .split(chunks[1]);

    // Left Column: Menu
    let menu_items = vec![
        ListItem::new("Select Feature Set"),
        ListItem::new("Select Mode"),
        ListItem::new("Set Output Method"),
        ListItem::new("Set Active Timeout"),
        ListItem::new("Set Idle Timeout"),
    ];
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

    f.render_stateful_widget(menu, columns[0], &mut app.main_menu_state.clone());

    // Middle Column: Content
    let middle_block = Block::default()
        .borders(Borders::ALL)
        .title("Options")
        .border_style(
            Style::default()
                .fg(if matches!(app.focus, AppFocus::FlowType) {
                    Color::Yellow
                } else {
                    Color::Cyan
                })
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(middle_block, columns[1]);

    match app.main_menu_state.selected() {
        Some(0) => {
            // Select Feature Set
            let items: Vec<ListItem> = FlowType::VARIANTS
                .iter()
                .map(|s| ListItem::new(*s))
                .collect();

            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title("Feature Set"))
                .highlight_style(
                    Style::default()
                        .fg(if matches!(app.focus, AppFocus::FlowType) {
                            Color::Yellow
                        } else {
                            Color::Reset
                        })
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol(">> ");

            f.render_stateful_widget(list, columns[1], &mut app.flow_type_state.clone());
        }
        Some(1) => {
            // Select Command
            let items = vec![ListItem::new("Realtime"), ListItem::new("Pcap")];
            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title("Select Mode").border_style(
                    Style::default()
                        .fg(if matches!(app.focus, AppFocus::CommandSelection) {
                            Color::Yellow
                        } else {
                            Color::Cyan
                        })
                        .add_modifier(Modifier::BOLD),
                ))
                .highlight_style(
                    Style::default()
                        .fg(if matches!(app.focus, AppFocus::CommandSelection) {
                            Color::Yellow
                        } else {
                            Color::Reset
                        })
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol(">> ");

            f.render_stateful_widget(list, columns[1], &mut app.command_state.clone());
        }
        Some(2) => {
            // Select Output
            let items = vec![ListItem::new("Print"), ListItem::new("Csv")];
            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title("Select Output Method").border_style(
                    Style::default()
                        .fg(if matches!(app.focus, AppFocus::OutputSelection) {
                            Color::Yellow
                        } else {
                            Color::Cyan
                        })
                        .add_modifier(Modifier::BOLD),
                ))
                .highlight_style(
                    Style::default()
                        .fg(if matches!(app.focus, AppFocus::OutputSelection) {
                            Color::Yellow
                        } else {
                            Color::Reset
                        })
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol(">> ");

            f.render_stateful_widget(list, columns[1], &mut app.output_state.clone());
        }
        Some(3) => {
            // Set Active Timeout
            let paragraph = Paragraph::new(app.active_timeout_input.as_ref())
                .block(
                    Block::default()
                        .title("Enter Active Timeout (seconds)")
                        .borders(Borders::ALL)
                        .border_style(
                            Style::default()
                                .fg(if matches!(app.focus, AppFocus::ActiveTimeoutInput) {
                                    Color::Yellow
                                } else {
                                    Color::Cyan
                                })
                                .add_modifier(Modifier::BOLD),
                        ),
                )
                .style(Style::default().fg(Color::Yellow));

            f.render_widget(paragraph, columns[1]);
        }
        Some(4) => {
            // Set Idle Timeout
            let paragraph = Paragraph::new(app.idle_timeout_input.as_ref())
                .block(
                    Block::default()
                        .title("Enter Idle Timeout (seconds)")
                        .borders(Borders::ALL)
                        .border_style(
                            Style::default()
                                .fg(if matches!(app.focus, AppFocus::IdleTimeoutInput) {
                                    Color::Yellow
                                } else {
                                    Color::Cyan
                                })
                                .add_modifier(Modifier::BOLD),
                        ),
                )
                .style(Style::default().fg(Color::Yellow));

            f.render_widget(paragraph, columns[1]);
        }
        _ => {}
    }

    // Right Column: Current Selections
    let selections = vec![
        ListItem::new(format!("Feature Set: {:?}", app.config.config.features)),
        ListItem::new(format!("Mode: {}", app.config.command.to_string())),
        ListItem::new(format!("Output Method: {:?}", app.config.output.output)),
        ListItem::new(format!("Output Path: {:?}", app.config.output.export_path)),
        ListItem::new(format!(
            "Active Timeout: {}",
            app.config.config.active_timeout
        )),
        ListItem::new(format!("Idle Timeout: {}", app.config.config.idle_timeout)),
        ListItem::new(format!("Threads: {:?}", app.config.config.threads)),
        ListItem::new(format!("Early Export: {:?}", app.config.config.early_export)),
        ListItem::new(format!("Header: {}", app.config.output.header)),
        ListItem::new(format!(
            "Drop Contaminant\nFeatures: {}",
            app.config.output.drop_contaminant_features
        )),
    ];
    let selections_list = List::new(selections)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title("Current Selections"),
        )
        .style(Style::default());

    f.render_widget(selections_list, columns[2]);

    if matches!(app.focus, AppFocus::CommandArgumentInput) {
        let command_input_block = Block::default()
            .title(match &app.config.command {
                Commands::Realtime { .. } => "Enter Interface",
                Commands::Pcap { .. } => "Enter Pcap File Path",
            })
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Yellow));
    
        let input_text = match &app.config.command {
            Commands::Realtime { interface, ingress_only: _ } => interface.as_str(),
            Commands::Pcap { path } => path.as_str(),
        };
    
        let paragraph = Paragraph::new(input_text)
            .block(command_input_block)
            .style(Style::default().fg(Color::White));
    
        // Center the block in the middle of the screen
        let popup_area = centered_rect(50, 15, size);
        f.render_widget(Clear, popup_area);
        f.render_widget(Block::default().style(Style::default().bg(Color::Black)), popup_area);
        f.render_widget(paragraph, popup_area);
    }

    if matches!(app.focus, AppFocus::OutputArgumentInput) {
        let command_input_block = Block::default()
            .title("Enter Output Path")
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Yellow));
    
        let input_text = app.config.output.export_path.as_deref().unwrap_or("");
    
        let paragraph = Paragraph::new(input_text)
            .block(command_input_block)
            .style(Style::default().fg(Color::White));
    
        // Center the block in the middle of the screen
        let popup_area = centered_rect(50, 15, size);
        f.render_widget(Clear, popup_area);
        f.render_widget(Block::default().style(Style::default().bg(Color::Black)), popup_area);
        f.render_widget(paragraph, popup_area);
    }

    if matches!(app.focus, AppFocus::IngressOnlyInput) {
        let boolean_input_block = Block::default()
        .title("Ingress Only?")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::Yellow));
    
    // Render two buttons: True and False
    let is_true_selected = match &app.config.command {
        Commands::Realtime { ingress_only, .. } => *ingress_only,
        _ => false, // default to false for other commands
    };

    // Button styles
    let true_button = Paragraph::new(" True ")
        .style(
            if is_true_selected {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Green)
            }
        )
        .block(Block::default().borders(Borders::ALL).border_style(
            if is_true_selected {
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Green).add_modifier(Modifier::DIM)
            }
        ));

    let false_button = Paragraph::new(" False ")
        .style(
            if !is_true_selected {
                Style::default()
                    .fg(Color::Red)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Red)
            }
        )
        .block(Block::default().borders(Borders::ALL).border_style(
            if !is_true_selected {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Red).add_modifier(Modifier::DIM)
            }
        ));

    // Layout for buttons: Center them in the middle of the screen
    let popup_area = centered_rect(50, 15, size);
    let buttons_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(popup_area);

    // Clear the popup area and render the buttons
    f.render_widget(Clear, popup_area);
    f.render_widget(boolean_input_block, popup_area);
    f.render_widget(true_button, buttons_layout[0]);
    f.render_widget(false_button, buttons_layout[1]);
    }
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
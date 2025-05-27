// In idlab-discover/rustiflow/RustiFlow-bd550ae2db5923b49c3bfea5223945b1889a077b/rustiflow/src/tui.rs

// Assuming you are switching to ratatui or making it compatible
// Replace tui::... with ratatui::... if you adopt ratatui fully
// For this example, I'll use the ratatui imports from your new code snippet for the new functions.
// You'll need to make sure the rest of the file (existing TUI) is compatible.

use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use log::error;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::{fs, io}; // fs might be needed for directory validation in TUI
use strum::VariantNames; // if FlowType uses it

// Use ratatui for new components
use ratatui::backend::{Backend, CrosstermBackend as RatatuiCrosstermBackend}; // Alias if needed
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Spans, Text}; // Ratatui uses Line instead of Spans directly in some cases
use ratatui::widgets::{Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph};
use ratatui::{Frame as RatatuiFrame, Terminal as RatatuiTerminal};


// Existing imports (adjust as needed)
use tui::backend::Backend as TuiBackend; // Keep original if mixing
use tui::layout::{/* existing */};
use tui::style::{/* existing */};
use tui::text::{/* existing */};
use tui::widgets::{/* existing */};
use tui::{Frame as TuiFrame, Terminal as TuiTerminal};


use crate::args::{Cli, Commands, ConfigFile, ExportConfig, ExportMethodType, FlowType, OutputConfig}; // FlowType is our FeatureSet

// --- New Structs and Enums from your provided code ---
#[derive(Debug, Clone, Default)] // Added Default
pub struct BatchProcessingState {
    pub input_directory: String,
    pub output_directory: String,
    pub feature_set: FlowType, // Using existing FlowType
    pub worker_count: usize,
    pub recursive: bool,
    pub active_timeout: u64,
    pub idle_timeout: u64,
    pub current_field: BatchField,
    pub processing: bool,
    pub progress: Option<BatchProgress>,
}

#[derive(Debug, Clone, PartialEq)] // Added PartialEq
pub enum BatchField {
    InputDirectory,
    OutputDirectory,
    FeatureSet,
    WorkerCount,
    Recursive,
    ActiveTimeout,
    IdleTimeout,
    StartProcessing,
}

impl Default for BatchField { // Added Default
    fn default() -> Self { BatchField::InputDirectory }
}


#[derive(Debug, Clone, Default)] // Added Default
pub struct BatchProgress {
    pub total_files: usize,
    pub processed_files: usize,
    pub success_count: usize,
    pub error_count: usize,
    pub current_file: String,
    pub estimated_remaining: String, // This would need a calculation logic
}

impl BatchProcessingState {
    pub fn new() -> Self {
        Self {
            input_directory: String::new(),
            output_directory: String::new(),
            feature_set: FlowType::Nfstream, // Default feature set
            worker_count: num_cpus::get(),
            recursive: false,
            active_timeout: 3600,
            idle_timeout: 120,
            current_field: BatchField::InputDirectory,
            processing: false,
            progress: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum AppTransition {
    ToMainMenu, // Or to the previous screen
    ToDirectoryPicker { field: String }, // Hypothetical screen for picking dirs
    ToNumberInput { field: String, current_value: usize, min: usize, max: usize }, // Hypothetical
    StartBatchProcessing,
    ToBatchProcessingSetup, // For navigating to the batch setup screen
}

// TUIError would need to be defined, e.g.:
#[derive(Debug)]
pub enum TUIError {
    Io(io::Error),
    Crossterm(crossterm::ErrorKind),
    Other(String),
}
impl From<io::Error> for TUIError { fn from(err: io::Error) -> Self { TUIError::Io(err) } }
impl From<crossterm::ErrorKind> for TUIError { fn from(err: crossterm::ErrorKind) -> Self { TUIError::Crossterm(err) } }
// --- End of New Structs and Enums ---


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub config: ExportConfig,
    pub output: OutputConfig,
    pub command: Commands,
}
// ... (Config impl Default, reset, etc. remain) ...

// Modify AppFocus
#[derive(Clone, Copy, PartialEq, Debug)] // Added Debug
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
    BatchProcessingSetup, // New Focus
    BatchProcessingProgress, // New Focus (if it's a separate focus state)
    // Add other states if needed by ToDirectoryPicker, ToNumberInput
}


// Modify App struct
struct App {
    config: Config,
    config_file: Option<String>,
    config_file_input: String,
    focus: AppFocus,
    title_bar_state: ListState,
    main_menu_state: ListState,
    flow_type_state: ListState, // Corresponds to FeatureSet selection in general TUI
    command_state: ListState,
    output_state: ListState,
    active_timeout_input: String,
    idle_timeout_input: String,
    expiration_check_interval_input: String,
    threads_input: String,
    early_export_input: String,
    main_menu_items: Vec<&'static str>,
    batch_processing_state: BatchProcessingState, // New state field
}

impl App {
    fn new(config: Config) -> App {
        // ... (existing initializations) ...
        let mut main_menu_items = vec![
            "Feature Set", "Mode", "Output Method", "Active Timeout", "Idle Timeout",
            "Expiration Check Interval", "Threads", "Early Export", "Header",
            "Drop Contaminant Features",
            "Batch PCAP Processing", // New Menu Item
        ];

        App {
            // ... (existing assignments) ...
            main_menu_items,
            batch_processing_state: BatchProcessingState::new(), // Initialize new state
            focus: AppFocus::ConfigFileInput, // Or whatever the initial focus is
            // Initialize other fields as before
            config,
            config_file: None,
            config_file_input: String::new(),
            title_bar_state: { let mut s = ListState::default(); s.select(Some(0)); s },
            main_menu_state: { let mut s = ListState::default(); s.select(Some(0)); s },
            flow_type_state: { let mut s = ListState::default(); s.select(Some(0)); s },
            command_state: { let mut s = ListState::default(); s.select(Some(0)); s },
            output_state: { let mut s = ListState::default(); s.select(Some(0)); s },
            active_timeout_input: String::new(),
            idle_timeout_input: String::new(),
            expiration_check_interval_input: String::new(),
            threads_input: String::new(),
            early_export_input: String::new(),

        }
    }
}

// Update launch_tui to potentially handle AppTransition
pub async fn launch_tui() -> Result<Option<Config>, Box<dyn Error>> {
    // ... (setup terminal as before, using RatatuiTerminal or TuiTerminal) ...
    // For Ratatui:
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = RatatuiCrosstermBackend::new(stdout); // Use Ratatui backend
    let mut terminal = RatatuiTerminal::new(backend)?;


    let mut app = App::new(Config::default()); // Or load from somewhere
    app.focus = AppFocus::ConfigFileInput; // Initial focus

    loop { // Main TUI loop
        terminal.draw(|f| ui_main_screen(f, &app))?;

        if crossterm::event::poll(std::time::Duration::from_millis(100))? {
            let event = event::read()?;
            let transition = match app.focus {
                AppFocus::BatchProcessingSetup => {
                    // Pass ratatui::event::Event if that's what handle_batch_processing_events expects
                    handle_batch_processing_events(event, &mut app.batch_processing_state)?
                }
                // ... (other focus handlers) ...
                AppFocus::Menu => { // Example: navigating from main menu to batch setup
                    if let Event::Key(key) = event {
                         match key.code {
                            KeyCode::Enter => {
                                if let Some(selected_index) = app.main_menu_state.selected() {
                                    if app.main_menu_items[selected_index] == "Batch PCAP Processing" {
                                        app.focus = AppFocus::BatchProcessingSetup;
                                    }
                                    // ... other menu items
                                }
                            }
                            // other key handling for menu
                            _ => handle_menu_input(key, &mut app).unwrap_or_else(|e| error!("Menu input error: {:?}", e)),
                         }
                    }
                    None // No transition by default
                }
                _ => {
                    // Placeholder for existing event handling logic
                    // This would call handle_title_bar_input, handle_menu_input, etc.
                    // For brevity, not reproducing all existing handlers here.
                    // You'll need to adapt them to return Option<AppTransition>.
                    // If they return a Result<Option<Config>, Box<dyn Error>>,
                    // wrap it: Ok(res.map(|_| AppTransition::ToMainMenu)) or similar based on outcome.
                    // For errors, propagate them.
                     if let Event::Key(key_event) = event {
                        match app.focus {
                            AppFocus::TitleBar => {
                                if let Some(config) = handle_title_bar_input(key_event, &mut app)? {
                                     // This indicates 'Start' was pressed
                                    // If Config is returned, it means TUI should close and pass config to main logic
                                    // For now, this structure doesn't handle returning Config from batch mode directly.
                                    // This would typically exit the launch_tui function.
                                    // How batch processing integrates with returning a single Config needs clarification.
                                    // For now, let's assume batch processing runs internally and then might return to main menu.
                                    return Ok(Some(config));
                                }
                            }
                            AppFocus::Menu => handle_menu_input(key_event, &mut app)?,
                            AppFocus::FlowType => handle_flow_type_input(key_event, &mut app)?,
                            AppFocus::ActiveTimeoutInput | AppFocus::IdleTimeoutInput | AppFocus::ExpirationCheckIntervalInput | AppFocus::ThreadsInput | AppFocus::EarlyExportInput => {
                               handle_numeric_input(key_event, &mut app, app.focus.clone())?;
                            }
                            AppFocus::CommandSelection | AppFocus::OutputSelection => {
                               handle_selection_input(key_event, &mut app, app.focus.clone())?;
                            }
                            AppFocus::CommandArgumentInput => handle_command_argument_input(key_event, &mut app)?,
                            AppFocus::OutputArgumentInput => handle_output_argument_input(key_event, &mut app)?,
                            AppFocus::IngressOnlyInput | AppFocus::PerformanceModeInput | AppFocus::HeaderInput | AppFocus::DropContaminantFeaturesInput => {
                                handle_boolean_input(key_event, &mut app, app.focus.clone())?;
                            }
                            AppFocus::ConfigFileInput => {
                                handle_config_file_input(key_event, &mut app)?;
                            }
                            AppFocus::ConfigFileSaveInput => {
                                handle_config_file_save_input(key_event, &mut app)?;
                            }
                            _ => {}
                        }
                    }
                    None // Default no transition
                }
            };

            if let Some(trans) = transition {
                match trans {
                    AppTransition::ToMainMenu => app.focus = AppFocus::Menu, // Or previous focus
                    AppTransition::ToBatchProcessingSetup => app.focus = AppFocus::BatchProcessingSetup,
                    AppTransition::StartBatchProcessing => {
                        // --- TRIGGER BATCH PROCESSING LOGIC HERE ---
                        // This would call a function similar to the main() of your batch CLI script,
                        // but adapted to run within this async Tokio context if needed.
                        // For now, just set focus to progress.
                        app.batch_processing_state.processing = true;
                        app.focus = AppFocus::BatchProcessingProgress; // Or stay in BatchProcessingSetup and change render
                        // Example: You might spawn a Tokio task here to run the batch job
                        // and use channels to update app.batch_processing_state.progress.
                        println!("Batch processing would start here with state: {:?}", app.batch_processing_state);
                        // Simulate processing and returning to setup screen
                        // In a real app, this would be asynchronous.
                        // For now, we'll just switch focus to show the idea.
                        // If batch processing is blocking, TUI will freeze. It should be async.
                    }
                    // Handle ToDirectoryPicker, ToNumberInput if you implement those screens
                    _ => {}
                }
            }
        }
         // Check if batch processing is done (simulated)
        if app.focus == AppFocus::BatchProcessingProgress && app.batch_processing_state.processing {
            // In a real app, a separate task would update `app.batch_processing_state.processing` to false
            // and fill `app.batch_processing_state.progress`.
            // For this example, let's assume it finishes and goes back to setup or main menu.
            // For now, let the user manually exit the "progress" screen if it were a real one.
            // Or, if processing is "done":
            // app.batch_processing_state.processing = false;
            // app.focus = AppFocus::BatchProcessingSetup; // or AppFocus::Menu
        }

    } // end loop

    // ... (cleanup terminal as before) ...
    // For Ratatui
    // disable_raw_mode()?;
    // execute!(
    //     terminal.backend_mut(),
    //     LeaveAlternateScreen,
    //     DisableMouseCapture
    // )?;
    // terminal.show_cursor()?;
    // Ok(None) // Default if TUI exits without starting a command
}

// Update ui_main_screen
// Ensure Frame type matches the terminal (TuiFrame or RatatuiFrame)
fn ui_main_screen<B: Backend>(f: &mut RatatuiFrame<B>, app: &App) { // Changed to RatatuiFrame
    let size = f.size();
    // Background
    let background = Block::default().style(Style::default().bg(Color::Black));
    f.render_widget(background, size);


    match app.focus {
        AppFocus::BatchProcessingSetup => {
            render_batch_processing_setup(f, &app.batch_processing_state);
            return;
        }
        AppFocus::BatchProcessingProgress if app.batch_processing_state.processing => {
             if let Some(progress) = &app.batch_processing_state.progress {
                render_batch_progress(f, progress);
            } else {
                // Placeholder if progress is None but processing is true
                let p = Paragraph::new("Processing... (progress details not yet available)")
                    .block(Block::default().borders(Borders::ALL).title("Processing"));
                f.render_widget(p, centered_rect(60, 20, size));
            }
            return;
        }
        // ... (existing screens like ConfigFileInput) ...
        AppFocus::ConfigFileInput => {
            render_config_file_input(f, app, centered_rect(80, 15, size));
            return;
        }
        AppFocus::ConfigFileSaveInput => {
            render_config_file_save(f, app, centered_rect(80, 15, size));
            return;
        }
        _ => {
            // Render existing main UI
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
                .split(size);

            let title_bar_layout = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                .split(chunks[0]);

            let rustiflow_art = ""





            let columns = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(38),
                    Constraint::Percentage(25),
                    Constraint::Percentage(37),
                ].as_ref())
                .split(chunks[1]);

            render_menu(f, app, columns[0]);
            render_content(f, app, columns[1]);
            render_current_selections(f, app, columns[2]);
            render_popups(f, app, size);
        }
    }
}

// --- Add the new rendering and event handling functions from your snippet ---
// Make sure to adjust them to use the `App` struct and `FlowType` correctly.
// Also, ensure they use the same `Backend` and `Frame` types as the rest of your TUI.
// The following are the functions you provided, slightly adapted to fit.

// Render the batch processing setup screen
pub fn render_batch_processing_setup<B: Backend>( // Use RatatuiFrame for consistency with ui_main_screen
    f: &mut RatatuiFrame<B>,
    state: &BatchProcessingState,
) {
    let size = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(size);

    let title = Paragraph::new("Batch PCAP Processing Setup")
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    let form_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), Constraint::Length(3), Constraint::Length(3),
            Constraint::Length(3), Constraint::Length(3), Constraint::Length(3),
            Constraint::Length(3),
        ].as_ref())
        .split(chunks[1]);

    let input_style = if matches!(state.current_field, BatchField::InputDirectory) {
        Style::default().fg(Color::Yellow)
    } else { Style::default() };
    let input_dir = Paragraph::new(state.input_directory.as_str())
        .style(input_style)
        .block(Block::default().borders(Borders::ALL).title("Input Directory (Enter to Edit)"));
    f.render_widget(input_dir, form_chunks[0]);

    let output_style = if matches!(state.current_field, BatchField::OutputDirectory) {
        Style::default().fg(Color::Yellow)
    } else { Style::default() };
    let output_dir = Paragraph::new(state.output_directory.as_str())
        .style(output_style)
        .block(Block::default().borders(Borders::ALL).title("Output Directory (Enter to Edit)"));
    f.render_widget(output_dir, form_chunks[1]);

    let feature_style = if matches!(state.current_field, BatchField::FeatureSet) {
        Style::default().fg(Color::Yellow)
    } else { Style::default() };
    let feature_text = format!("{:?}", state.feature_set); // Using FlowType
    let feature_set_widget = Paragraph::new(feature_text) // Renamed variable
        .style(feature_style)
        .block(Block::default().borders(Borders::ALL).title("Feature Set (Enter to Cycle)"));
    f.render_widget(feature_set_widget, form_chunks[2]);

    let worker_style = if matches!(state.current_field, BatchField::WorkerCount) {
        Style::default().fg(Color::Yellow)
    } else { Style::default() };
    let worker_text = format!("{}", state.worker_count);
    let worker_count_widget = Paragraph::new(worker_text) // Renamed variable
        .style(worker_style)
        .block(Block::default().borders(Borders::ALL).title("Worker Threads (+/- or Enter to Edit)"));
    f.render_widget(worker_count_widget, form_chunks[3]);

    let options_style = if matches!(state.current_field, BatchField::Recursive) {
        Style::default().fg(Color::Yellow)
    } else { Style::default() };
    let recursive_text = if state.recursive { "Yes" } else { "No" };
    let options = Paragraph::new(format!("Recursive Search: {}", recursive_text))
        .style(options_style)
        .block(Block::default().borders(Borders::ALL).title("Options (Enter/Tab to Toggle)"));
    f.render_widget(options, form_chunks[4]);

    let timeout_style_active = if matches!(state.current_field, BatchField::ActiveTimeout) { Style::default().fg(Color::Yellow)} else {Style::default()};
    let timeout_style_idle = if matches!(state.current_field, BatchField::IdleTimeout) { Style::default().fg(Color::Yellow)} else {Style::default()};

    let timeout_spans = Spans::from(vec![
        Span::styled(format!("Active: {}s", state.active_timeout), timeout_style_active),
        Span::raw(", "),
        Span::styled(format!("Idle: {}s", state.idle_timeout), timeout_style_idle),
    ]);
    let timeouts = Paragraph::new(timeout_spans)
        .block(Block::default().borders(Borders::ALL).title("Timeouts (+/- to Adjust)"));

    f.render_widget(timeouts, form_chunks[5]);


    let start_style = if matches!(state.current_field, BatchField::StartProcessing) {
        Style::default().fg(Color::Black).bg(Color::Green)
    } else { Style::default().fg(Color::Green) };
    let start_button = Paragraph::new("[ Start Processing ]")
        .style(start_style)
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(start_button, form_chunks[6]);

    let instructions = Paragraph::new("↑↓: Navigate | Enter: Edit/Select/Cycle | Tab: Toggle Recursive | +/-: Adjust Workers/Timeouts | Esc: Back to Main Menu")
        .style(Style::default().fg(Color::Gray));
    f.render_widget(instructions, chunks[2]);
}


pub fn render_batch_progress<B: Backend>( // Use RatatuiFrame
    f: &mut RatatuiFrame<B>,
    progress: &BatchProgress,
) {
    let size = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3), Constraint::Length(3), Constraint::Length(7), // Increased for more stats
            Constraint::Length(3), Constraint::Min(0),
        ])
        .split(size);

    let title = Paragraph::new("Processing PCAP Files...")
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    let progress_ratio = if progress.total_files > 0 {
        progress.processed_files as f64 / progress.total_files as f64
    } else { 0.0 };
    let progress_bar = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title("Overall Progress"))
        .gauge_style(Style::default().fg(Color::Green).bg(Color::DarkGray))
        .percent((progress_ratio * 100.0) as u16)
        .label(format!("{}/{} files", progress.processed_files, progress.total_files));
    f.render_widget(progress_bar, chunks[1]);

    let stats_text = vec![
        Line::from(Span::raw(format!("Total Files: {}", progress.total_files))),
        Line::from(Span::raw(format!("Processed:   {}", progress.processed_files))),
        Line::from(Span::styled(format!("Succeeded:   {}", progress.success_count), Style::default().fg(Color::Green))),
        Line::from(Span::styled(format!("Failed:      {}", progress.error_count), Style::default().fg(Color::Red))),
        Line::from(Span::raw(format!("Est. Time Remaining: {}", progress.estimated_remaining))), // Needs logic
    ];
    let stats = Paragraph::new(stats_text)
        .block(Block::default().borders(Borders::ALL).title("Statistics"));
    f.render_widget(stats, chunks[2]);

    let current_file_text = if progress.current_file.is_empty() && progress.processed_files == progress.total_files && progress.total_files > 0 {
        "Completed!".to_string()
    } else {
        progress.current_file.clone()
    };
    let current_file = Paragraph::new(current_file_text)
        .block(Block::default().borders(Borders::ALL).title("Processing File"));
    f.render_widget(current_file, chunks[3]);
    
    // Placeholder for Log area
    let log_area = Paragraph::new("Log messages would appear here...\nUse 'Ctrl+C' to attempt to stop processing.")
        .block(Block::default().borders(Borders::ALL).title("Log (Not Implemented)"));
    f.render_widget(log_area, chunks[4]);
}

// Event handling for batch processing screen
// The Event type might need to be crossterm::event::Event
pub fn handle_batch_processing_events(
    event: crossterm::event::Event, // Explicitly crossterm event
    state: &mut BatchProcessingState,
) -> Result<Option<AppTransition>, TUIError> {
    if let Event::Key(key) = event {
        if state.processing { // If processing, only allow Esc or Ctrl-C (handled by OS/main loop)
            if key.code == KeyCode::Esc {
                 // Potentially offer to cancel processing, for now, just logs or does nothing
                log::warn!("Attempted to ESC during batch processing. Ctrl-C to force quit.");
            }
            return Ok(None);
        }

        match key.code {
            KeyCode::Esc => Ok(Some(AppTransition::ToMainMenu)),
            KeyCode::Up => {
                state.current_field = match state.current_field {
                    BatchField::InputDirectory => BatchField::StartProcessing,
                    BatchField::OutputDirectory => BatchField::InputDirectory,
                    BatchField::FeatureSet => BatchField::OutputDirectory,
                    BatchField::WorkerCount => BatchField::FeatureSet,
                    BatchField::Recursive => BatchField::WorkerCount,
                    BatchField::ActiveTimeout => BatchField::Recursive,
                    BatchField::IdleTimeout => BatchField::ActiveTimeout,
                    BatchField::StartProcessing => BatchField::IdleTimeout,
                };
                Ok(None)
            }
            KeyCode::Down => {
                state.current_field = match state.current_field {
                    BatchField::InputDirectory => BatchField::OutputDirectory,
                    BatchField::OutputDirectory => BatchField::FeatureSet,
                    BatchField::FeatureSet => BatchField::WorkerCount,
                    BatchField::WorkerCount => BatchField::Recursive,
                    BatchField::Recursive => BatchField::ActiveTimeout,
                    BatchField::ActiveTimeout => BatchField::IdleTimeout,
                    BatchField::IdleTimeout => BatchField::StartProcessing,
                    BatchField::StartProcessing => BatchField::InputDirectory,
                };
                Ok(None)
            }
            KeyCode::Enter => {
                match state.current_field {
                    BatchField::InputDirectory | BatchField::OutputDirectory => {
                        // Here you would typically trigger a sub-TUI for path input
                        // For now, we assume path is typed directly (needs App modification)
                        // Or, signal to open a proper input box / directory picker
                         log::info!("Path input for {:?} not fully implemented in this snippet.", state.current_field);
                         Ok(Some(AppTransition::ToDirectoryPicker { // Placeholder
                             field: if state.current_field == BatchField::InputDirectory { "input_directory".to_string() } else { "output_directory".to_string()},
                         }))
                    }
                    BatchField::FeatureSet => {
                        // Cycle through FlowType variants
                        let variants = FlowType::VARIANTS; // Needs strum::VariantNames
                        if let Some(pos) = variants.iter().position(|&s| s == state.feature_set.to_string().to_lowercase().as_str()) {
                            let next_pos = (pos + 1) % variants.len();
                            state.feature_set = variants[next_pos].parse().unwrap_or_default(); // Needs FromStr for FlowType
                        }
                        Ok(None)
                    }
                    BatchField::WorkerCount => {
                         log::info!("Worker count input not fully implemented here.");
                         Ok(Some(AppTransition::ToNumberInput {
                            field: "worker_count".to_string(),
                            current_value: state.worker_count,
                            min: 1,
                            max: num_cpus::get() * 2,
                         }))
                    }
                    BatchField::Recursive => {
                        state.recursive = !state.recursive;
                        Ok(None)
                    }
                    BatchField::StartProcessing => {
                        if validate_batch_inputs(state).is_ok() {
                            Ok(Some(AppTransition::StartBatchProcessing))
                        } else {
                            // Error should be displayed to the user, e.g. via a popup or message area
                            error!("Validation failed: {:?}", validate_batch_inputs(state).err().unwrap());
                            Ok(None)
                        }
                    }
                    _ => Ok(None),
                }
            }
            KeyCode::Tab => {
                if state.current_field == BatchField::Recursive {
                    state.recursive = !state.recursive;
                }
                Ok(None)
            }
             KeyCode::Char('+') | KeyCode::Right => {
                match state.current_field {
                    BatchField::WorkerCount => {
                        if state.worker_count < num_cpus::get() * 2 { state.worker_count += 1; }
                    }
                    BatchField::ActiveTimeout => state.active_timeout += 300,
                    BatchField::IdleTimeout => state.idle_timeout += 30,
                    _ => {}
                }
                Ok(None)
            }
            KeyCode::Char('-') | KeyCode::Left => {
                match state.current_field {
                    BatchField::WorkerCount => {
                        if state.worker_count > 1 { state.worker_count -= 1; }
                    }
                    BatchField::ActiveTimeout => {
                        if state.active_timeout > 300 { state.active_timeout -= 300; } else { state.active_timeout = 0; }
                    }
                    BatchField::IdleTimeout => {
                        if state.idle_timeout > 30 { state.idle_timeout -= 30; } else { state.idle_timeout = 0; }
                    }
                    _ => {}
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    } else {
        Ok(None) // Not a key event
    }
}

fn validate_batch_inputs(state: &BatchProcessingState) -> Result<(), String> {
    if state.input_directory.is_empty() { return Err("Input directory is required".to_string()); }
    if state.output_directory.is_empty() { return Err("Output directory is required".to_string()); }
    if !Path::new(&state.input_directory).exists() { return Err(format!("Input directory '{}' does not exist", state.input_directory)); }
    if !Path::new(&state.input_directory).is_dir() { return Err(format!("Input path '{}' is not a directory", state.input_directory));}
    // Output directory will be created, but good to check if path is reasonable if needed
    if state.worker_count == 0 { return Err("Worker count must be at least 1".to_string()); }
    Ok(())
}

// ... (rest of your existing tui.rs code, like handle_menu_input, render_menu, etc.)
// Ensure that all input handlers and UI rendering functions are compatible with the
// App struct and the chosen TUI library (tui-rs or ratatui).
// The functions like `handle_title_bar_input`, `handle_menu_input`, etc.
// should be adapted to fit into the new event loop structure if `launch_tui` is changed significantly.
// They might need to return `Result<Option<AppTransition>, TUIError>` as well.

// Remember to add num_cpus = "1.0" to your Cargo.toml dependencies.
// And strum = { version = "0.24", features = ["derive"] } for FlowType cycling.


// In idlab-discover/rustiflow/RustiFlow-bd550ae2db5923b49c3bfea5223945b1889a077b/rustiflow/src/main.rs
// ... other imports ...

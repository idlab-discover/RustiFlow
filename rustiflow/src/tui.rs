use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::path::Path;
use std::{fs, io, sync::Arc}; // fs for path validation, Arc for shared state
use strum::{EnumString, VariantNames}; // For FlowType iteration

// Ratatui imports
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Spans, Text};
use ratatui::widgets::{Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph};
use ratatui::{Frame, Terminal};

// Tokio imports for async tasks and channels
use tokio::sync::{mpsc, Mutex}; // Mutex for shared progress, mpsc for communication
use tokio::task::JoinHandle;

// Project-specific imports
use crate::args::{Cli, Commands, ConfigFile, ExportConfig, ExportMethodType, FlowType, OutputConfig};
// This function would be in main.rs or another module, responsible for the actual batch work.
// For this tui.rs, we'll define a placeholder signature.
// use crate::batch_logic::run_actual_batch_processing; // Placeholder

// --- Structs and Enums for TUI State ---

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
                features: FlowType::default(), // Assuming FlowType has Default
                active_timeout: 3600,
                idle_timeout: 120,
                early_export: None,
                threads: Some(num_cpus::get() as u8),
                expiration_check_interval: 60,
            },
            output: OutputConfig {
                output: ExportMethodType::Print, // Default output
                export_path: None,
                header: false,
                drop_contaminant_features: false,
                performance_mode: false,
            },
            command: Commands::Realtime { // Default command
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

// --- Batch Processing Specific Structs and Enums ---
#[derive(Debug, Clone)]
pub struct BatchProcessingState {
    pub input_directory: String,
    pub output_directory: String,
    pub feature_set: FlowType,
    pub worker_count: usize,
    pub recursive: bool,
    pub active_timeout: u64,
    pub idle_timeout: u64,
    pub current_field: BatchField,
    pub processing: bool,
    pub progress: Arc<Mutex<BatchProgress>>, // Shared progress state
    pub validation_error: Option<String>, // For displaying validation errors
}

#[derive(Debug, Clone, PartialEq)]
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

impl Default for BatchField {
    fn default() -> Self {
        BatchField::InputDirectory
    }
}

#[derive(Debug, Clone, Default)]
pub struct BatchProgress {
    pub total_files: usize,
    pub processed_files: usize,
    pub success_count: usize,
    pub error_count: usize,
    pub current_file: String,
    pub estimated_remaining: String,
    pub last_error_message: Option<String>,
}

impl BatchProcessingState {
    pub fn new() -> Self {
        Self {
            input_directory: std::env::current_dir().map_or(String::new(), |p| p.to_string_lossy().into_owned()),
            output_directory: std::env::current_dir().map_or(String::new(), |p| p.join("rustiflow_output").to_string_lossy().into_owned()),
            feature_set: FlowType::default(),
            worker_count: num_cpus::get(),
            recursive: false,
            active_timeout: 3600,
            idle_timeout: 120,
            current_field: BatchField::InputDirectory,
            processing: false,
            progress: Arc::new(Mutex::new(BatchProgress::default())),
            validation_error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum AppTransition {
    ToMainMenu,
    ToBatchSetupScreen,
    StartBatchProcessing,
    // These are for more complex input handling, not fully implemented in this snippet
    ToDirectoryPicker { field: String, current_path: String },
    ToTextInput { field: String, current_value: String, title: String },
    ToNumberInput { field: String, current_value: usize, min: usize, max: usize, title: String },
}

#[derive(Debug)]
pub enum TUIError {
    Io(io::Error),
    Crossterm(crossterm::ErrorKind),
    Other(String),
    ChannelClosed,
}
impl From<io::Error> for TUIError { fn from(err: io::Error) -> Self { TUIError::Io(err) } }
impl From<crossterm::ErrorKind> for TUIError { fn from(err: crossterm::ErrorKind) -> Self { TUIError::Crossterm(err) } }
impl<T> From<mpsc::error::SendError<T>> for TUIError {
    fn from(_: mpsc::error::SendError<T>) -> Self {
        TUIError::ChannelClosed
    }
}


// --- Main App Struct and Focus Enum ---
#[derive(Clone, Copy, PartialEq, Debug)]
enum AppFocus {
    TitleBar,
    Menu,
    // General config fields
    FlowTypeSelection, // For selecting app.config.config.features
    ActiveTimeoutInput,
    IdleTimeoutInput,
    ExpirationCheckIntervalInput,
    CommandSelection, // For app.config.command
    OutputSelection,  // For app.config.output.output
    CommandArgumentInput, // For interface/pcap path
    OutputArgumentInput,  // For CSV export path
    IngressOnlyInput,
    PerformanceModeInput,
    ThreadsInput,
    EarlyExportInput,
    HeaderInput,
    DropContaminantFeaturesInput,
    ConfigFileInput,
    ConfigFileSaveInput,
    // Batch processing
    BatchSetupScreen,
    BatchProgressScreen,
    // Generic input popups (if implemented)
    TextInputPopup,
    NumberInputPopup,
    DirectoryPickerPopup,
}

struct App {
    config: Config, // General application config
    config_file: Option<String>,
    config_file_input: String, // For loading/saving config file path
    focus: AppFocus,
    title_bar_state: ListState,
    main_menu_state: ListState,
    // States for general config UI elements
    flow_type_selection_state: ListState, // For app.config.config.features
    command_selection_state: ListState,   // For app.config.command
    output_selection_state: ListState,    // For app.config.output.output
    // Input buffers for general config
    active_timeout_input_buffer: String,
    idle_timeout_input_buffer: String,
    expiration_check_interval_input_buffer: String,
    threads_input_buffer: String,
    early_export_input_buffer: String,
    command_argument_input_buffer: String, // For interface/pcap path
    output_argument_input_buffer: String,  // For CSV export path
    // Batch processing state
    batch_processing_state: BatchProcessingState,
    // For generic text input popup
    text_input_popup_title: String,
    text_input_popup_buffer: String,
    text_input_popup_target_field: Option<BatchField>, // To know which batch field to update
    // Batch processing task
    batch_task_handle: Option<JoinHandle<()>>,
    progress_rx: Option<mpsc::Receiver<BatchProgress>>, // Receives progress from batch task
    main_menu_items: Vec<&'static str>,
}

impl App {
    fn new(config: Config) -> App {
        let main_menu_items = vec![
            "Feature Set", "Mode", "Output Method", "Active Timeout", "Idle Timeout",
            "Expiration Check Interval", "Threads", "Early Export", "Header",
            "Drop Contaminant Features", "Batch PCAP Processing",
        ];

        App {
            config,
            config_file: None,
            config_file_input: String::new(),
            focus: AppFocus::ConfigFileInput,
            title_bar_state: { let mut s = ListState::default(); s.select(Some(0)); s },
            main_menu_state: { let mut s = ListState::default(); s.select(Some(0)); s },
            flow_type_selection_state: { let mut s = ListState::default(); s.select(Some(0)); s },
            command_selection_state: { let mut s = ListState::default(); s.select(Some(0)); s },
            output_selection_state: { let mut s = ListState::default(); s.select(Some(0)); s },
            active_timeout_input_buffer: String::new(),
            idle_timeout_input_buffer: String::new(),
            expiration_check_interval_input_buffer: String::new(),
            threads_input_buffer: String::new(),
            early_export_input_buffer: String::new(),
            command_argument_input_buffer: String::new(),
            output_argument_input_buffer: String::new(),
            batch_processing_state: BatchProcessingState::new(),
            text_input_popup_title: String::new(),
            text_input_popup_buffer: String::new(),
            text_input_popup_target_field: None,
            batch_task_handle: None,
            progress_rx: None,
            main_menu_items,
        }
    }
}


// --- TUI Entry Point and Main Loop ---
pub async fn launch_tui(
    // This function would be passed from main.rs
    // It's responsible for the actual batch processing logic.
    // For now, we use a placeholder type.
    batch_processor: fn(BatchProcessingState, mpsc::Sender<BatchProgress>) -> JoinHandle<()>,
) -> Result<Option<Config>, Box<dyn Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(Config::default()); // Start with default config

    let mut final_config: Option<Config> = None; // To store config if user "Starts"

    'main_loop: loop {
        // Draw UI
        terminal.draw(|f| ui_main_screen(f, &app))?;

        // Event handling with tokio::select for async progress updates
        tokio::select! {
            // Listen for progress updates from the batch task
            Some(progress_update) = async {
                if let Some(rx) = app.progress_rx.as_mut() {
                    rx.recv().await
                } else {
                    // Sleep a bit if no receiver to prevent busy loop on this branch
                    tokio::time::sleep(std::time::Duration::from_millis(1000)).await; // Infinite pending future
                    None
                }
            } => {
                if let Ok(mut progress_guard) = app.batch_processing_state.progress.try_lock() {
                    *progress_guard = progress_update;
                } else {
                    warn!("Could not lock progress for update from batch task.");
                }
            },

            // Check if batch task has finished
            task_finished = async {
                if let Some(handle) = &mut app.batch_task_handle {
                    // Use poll_join here or a mechanism to check completion without blocking
                    // For simplicity, let's assume we can check if it's finished.
                    // A more robust way is for the task to send a "completion" message.
                    // For now, this branch won't be hit effectively without more complex task management.
                    // Let's assume the task sends a final progress update that signals completion.
                    // Or, user Escapes from progress screen.
                    false // Placeholder
                } else {
                    false
                }
            } => {
                if task_finished {
                    app.batch_task_handle = None;
                    app.progress_rx = None;
                    app.batch_processing_state.processing = false;
                    app.focus = AppFocus::BatchSetupScreen; // Go back to setup
                }
            },

            // Listen for user input
            event_ready = tokio::task::spawn_blocking(|| crossterm::event::poll(std::time::Duration::from_millis(100))) => {
                match event_ready {
                    Ok(Ok(true)) => { // Event is ready
                        let event = event::read()?;
                        let mut transition: Option<AppTransition> = None;

                        // Handle generic input popup first if active
                        if app.focus == AppFocus::TextInputPopup {
                            if let Event::Key(key) = event {
                                match key.code {
                                    KeyCode::Enter => {
                                        if let Some(target_field) = &app.text_input_popup_target_field {
                                            match target_field {
                                                BatchField::InputDirectory => app.batch_processing_state.input_directory = app.text_input_popup_buffer.clone(),
                                                BatchField::OutputDirectory => app.batch_processing_state.output_directory = app.text_input_popup_buffer.clone(),
                                                _ => {}
                                            }
                                        }
                                        app.focus = AppFocus::BatchSetupScreen; // Return to batch setup
                                        app.text_input_popup_target_field = None;
                                    }
                                    KeyCode::Esc => {
                                        app.focus = AppFocus::BatchSetupScreen;
                                        app.text_input_popup_target_field = None;
                                    }
                                    KeyCode::Char(c) => app.text_input_popup_buffer.push(c),
                                    KeyCode::Backspace => { app.text_input_popup_buffer.pop(); }
                                    _ => {}
                                }
                            }
                        } else { // Handle other focus states
                            match app.focus {
                                AppFocus::BatchSetupScreen => {
                                    transition = handle_batch_processing_events(event, &mut app.batch_processing_state)?;
                                }
                                AppFocus::BatchProgressScreen => {
                                    if let Event::Key(key) = event {
                                        if key.code == KeyCode::Esc {
                                            // Stop batch task (if running) and return to setup
                                            if let Some(handle) = app.batch_task_handle.take() {
                                                handle.abort(); // Attempt to abort
                                            }
                                            app.batch_processing_state.processing = false;
                                            app.progress_rx = None;
                                            // Reset progress
                                             match app.batch_processing_state.progress.try_lock() {
                                                Ok(mut p) => *p = BatchProgress::default(),
                                                Err(_) => warn!("Could not reset progress on Esc from progress screen."),
                                             }
                                            app.focus = AppFocus::BatchSetupScreen;
                                        }
                                    }
                                }
                                AppFocus::TitleBar => {
                                    if let Event::Key(key_event) = event {
                                        if let Some(config_to_run) = handle_title_bar_input(key_event, &mut app)? {
                                            final_config = Some(config_to_run);
                                            break 'main_loop; // Exit TUI and run the command
                                        }
                                    }
                                }
                                AppFocus::Menu => {
                                    if let Event::Key(key_event) = event {
                                        transition = handle_menu_input(key_event, &mut app)?;
                                    }
                                }
                                // ... (Simplified handlers for other general config options) ...
                                AppFocus::ConfigFileInput => if let Event::Key(k) = event { handle_config_file_input(k, &mut app)?; },
                                AppFocus::ConfigFileSaveInput => if let Event::Key(k) = event { handle_config_file_save_input(k, &mut app)?; },
                                AppFocus::OutputSelection => if let Event::Key(k) = event { handle_output_selection_input(k, &mut app); },
                                AppFocus::OutputArgumentInput => if let Event::Key(k) = event { handle_output_argument_input(k, &mut app); },
                                // Add more specific handlers here if needed, or a generic one
                                // For other general config text inputs (ActiveTimeout, IdleTimeout, etc.)
                                // a generic handler could be used, or specific ones if validation is complex.
                                // For now, let's assume they are handled by a generic key press if not covered above.
                                AppFocus::ActiveTimeoutInput | AppFocus::IdleTimeoutInput |
                                AppFocus::ExpirationCheckIntervalInput | AppFocus::ThreadsInput |
                                AppFocus::EarlyExportInput | AppFocus::CommandArgumentInput => {
                                    if let Event::Key(key_event) = event {
                                        handle_generic_text_input(key_event, app);
                                    }
                                }
                                // Boolean toggles and FlowType/Command selection are often handled directly in handle_menu_input
                                // or would need their own handlers if input is taken in a popup.
                                AppFocus::FlowTypeSelection => { /* Needs dedicated handler or handled by popup logic */ }
                                AppFocus::CommandSelection => { /* Needs dedicated handler or handled by popup logic */ }

                                _ => { // Default for other general config states or unhandled popups
                                    if let Event::Key(key) = event {
                                        if key.code == KeyCode::Esc && app.focus != AppFocus::ConfigFileInput {
                                            app.focus = AppFocus::Menu;
                                        }
                                        // Other generic input handling could go here if needed
                                    }
                                }
                            }
                        }


                        // Handle transitions
                        if let Some(trans) = transition {
                            match trans {
                                AppTransition::ToMainMenu => app.focus = AppFocus::Menu,
                                AppTransition::ToBatchSetupScreen => app.focus = AppFocus::BatchSetupScreen,
                                AppTransition::StartBatchProcessing => {
                                    app.batch_processing_state.processing = true;
                                    app.batch_processing_state.validation_error = None; // Clear previous errors
                                    app.focus = AppFocus::BatchProgressScreen;

                                    // Reset progress before starting
                                    if let Ok(mut p) = app.batch_processing_state.progress.try_lock() {
                                        *p = BatchProgress::default();
                                        p.total_files = 0; // Will be updated by the task
                                    } else {
                                        warn!("Could not lock progress to reset before batch start.");
                                        // Potentially handle this error more gracefully
                                    }


                                    let (progress_tx, progress_rx_channel) = mpsc::channel(100);
                                    app.progress_rx = Some(progress_rx_channel);

                                    // Clone necessary state for the task
                                    let state_for_task = app.batch_processing_state.clone(); // BatchProcessingState needs to be Clone

                                    // Spawn the actual batch processing task
                                    app.batch_task_handle = Some(batch_processor(state_for_task, progress_tx));
                                }
                                AppTransition::ToTextInput { field, current_value, title } => {
                                    app.text_input_popup_title = title;
                                    app.text_input_popup_buffer = current_value;
                                    app.text_input_popup_target_field = Some(field.parse().unwrap_or_default()); // Assuming field can be parsed to BatchField
                                    app.focus = AppFocus::TextInputPopup;
                                }
                                // Handle other transitions like ToDirectoryPicker, ToNumberInput if fully implemented
                                _ => {}
                            }
                        }
                    }
                    Ok(Ok(false)) => { /* Poll timed out, no event */ }
                    Ok(Err(e)) => return Err(Box::new(TUIError::Crossterm(e))), // Crossterm error
                    Err(e) => return Err(Box::new(TUIError::Other(format!("Task join error: {}", e)))), // Tokio task join error
                }
            }
        } // end tokio::select!
    } // end 'main_loop: loop

    // Cleanup
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(final_config)
}


// --- UI Rendering Functions ---
fn ui_main_screen<B: Backend>(f: &mut Frame<B>, app: &App) {
    let size = f.size();
    let background = Block::default().style(Style::default().bg(Color::Black));
    f.render_widget(background, size);

    match app.focus {
        AppFocus::BatchSetupScreen => {
            render_batch_processing_setup(f, &app.batch_processing_state);
        }
        AppFocus::BatchProgressScreen => {
            // Lock is fallible, handle gracefully if lock can't be acquired immediately
            if let Ok(progress_guard) = app.batch_processing_state.progress.try_lock() {
                 render_batch_progress(f, &progress_guard);
            } else {
                // Fallback or loading state if progress is contended
                let p = Paragraph::new("Waiting for progress update...")
                    .block(Block::default().borders(Borders::ALL).title("Processing"));
                f.render_widget(p, centered_rect(60, 20, size));
            }
        }
        AppFocus::TextInputPopup => {
            // First render the underlying screen (e.g., BatchSetupScreen)
            // This part is tricky as it requires knowing the "previous" focus.
            // For simplicity, let's assume BatchSetupScreen was the previous.
            render_batch_processing_setup(f, &app.batch_processing_state); // Render background
            render_text_input_popup(f, &app.text_input_popup_title, &app.text_input_popup_buffer, size);
        }
        AppFocus::ConfigFileInput => {
            render_config_file_input_popup(f, &app.config_file_input, size);
            return;
        }
        AppFocus::ConfigFileSaveInput => {
            render_config_file_save_popup(f, &app.config_file_input, size);
            return;
        }
        _ => { // General config UI
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
                .split(size);

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

            let columns = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(38),
                    Constraint::Percentage(25),
                    Constraint::Percentage(37),
                ].as_ref())
                .split(chunks[1]);

            render_menu(f, app, columns[0]);
            render_content_general_config(f, app, columns[1]); // Renamed for clarity
            render_current_selections_general_config(f, app, columns[2]); // Renamed
            render_popups_general_config(f, app, size); // Renamed
        }
    }
}

// Placeholder for a generic text input popup
fn render_text_input_popup<B: Backend>(f: &mut Frame<B>, title: &str, current_text: &str, screen_size: Rect) {
    let popup_area = centered_rect(60, 20, screen_size);
    f.render_widget(Clear, popup_area); // Clear the area

    let block = Block::default()
        .title(title.to_string())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow))
        .style(Style::default().bg(Color::DarkGray)); // Popup background

    let text_widget = Paragraph::new(current_text)
        .style(Style::default().fg(Color::White))
        .block(block);

    f.render_widget(text_widget, popup_area);
}


// --- Batch Processing UI Rendering and Event Handling ---
pub fn render_batch_processing_setup<B: Backend>(
    f: &mut Frame<B>,
    state: &BatchProcessingState,
) {
    let size = f.size();
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3), // Title
                Constraint::Min(0),    // Form
                Constraint::Length(1), // Validation Error (if any)
                Constraint::Length(3), // Instructions
            ]
            .as_ref(),
        )
        .split(size);

    let title = Paragraph::new("Batch PCAP Processing Setup")
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)));
    f.render_widget(title, main_chunks[0]);

    let form_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), Constraint::Length(3), Constraint::Length(3),
            Constraint::Length(3), Constraint::Length(3), Constraint::Length(3),
            Constraint::Length(3),
        ].as_ref())
        .split(main_chunks[1]);

    let focused_style = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
    let default_style = Style::default().fg(Color::White);
    let border_style_focused = Style::default().fg(Color::Yellow);
    let border_style_default = Style::default().fg(Color::DarkGray);

    // Input Directory
    let input_dir_block = Block::default().borders(Borders::ALL).title("Input Directory (Enter to Edit)")
        .border_style(if state.current_field == BatchField::InputDirectory { border_style_focused } else { border_style_default });
    let input_dir_text = Paragraph::new(state.input_directory.as_str())
        .style(if state.current_field == BatchField::InputDirectory { focused_style } else { default_style })
        .block(input_dir_block);
    f.render_widget(input_dir_text, form_chunks[0]);

    // Output Directory
    let output_dir_block = Block::default().borders(Borders::ALL).title("Output Directory (Enter to Edit)")
        .border_style(if state.current_field == BatchField::OutputDirectory { border_style_focused } else { border_style_default });
    let output_dir_text = Paragraph::new(state.output_directory.as_str())
        .style(if state.current_field == BatchField::OutputDirectory { focused_style } else { default_style })
        .block(output_dir_block);
    f.render_widget(output_dir_text, form_chunks[1]);

    // Feature Set
    let feature_set_block = Block::default().borders(Borders::ALL).title("Feature Set (Enter to Cycle)")
        .border_style(if state.current_field == BatchField::FeatureSet { border_style_focused } else { border_style_default });
    let feature_text = format!("{:?}", state.feature_set);
    let feature_set_widget = Paragraph::new(feature_text)
        .style(if state.current_field == BatchField::FeatureSet { focused_style } else { default_style })
        .block(feature_set_block);
    f.render_widget(feature_set_widget, form_chunks[2]);

    // Worker Count
    let worker_count_block = Block::default().borders(Borders::ALL).title("Worker Threads (+/-)")
        .border_style(if state.current_field == BatchField::WorkerCount { border_style_focused } else { border_style_default });
    let worker_text = format!("{}", state.worker_count);
    let worker_count_widget = Paragraph::new(worker_text)
        .style(if state.current_field == BatchField::WorkerCount { focused_style } else { default_style })
        .block(worker_count_block);
    f.render_widget(worker_count_widget, form_chunks[3]);

    // Recursive Option
    let recursive_block = Block::default().borders(Borders::ALL).title("Options (Enter/Tab to Toggle)")
        .border_style(if state.current_field == BatchField::Recursive { border_style_focused } else { border_style_default });
    let recursive_text = if state.recursive { "Recursive: Yes" } else { "Recursive: No" };
    let options_widget = Paragraph::new(recursive_text)
        .style(if state.current_field == BatchField::Recursive { focused_style } else { default_style })
        .block(recursive_block);
    f.render_widget(options_widget, form_chunks[4]);

    // Timeouts
    let timeout_block = Block::default().borders(Borders::ALL).title("Timeouts (+/- to Adjust)")
        .border_style(
            if state.current_field == BatchField::ActiveTimeout || state.current_field == BatchField::IdleTimeout {
                border_style_focused
            } else {
                border_style_default
            }
        );
    let timeout_spans = Spans::from(vec![
        Span::styled("Active: ", if state.current_field == BatchField::ActiveTimeout { focused_style } else { default_style }),
        Span::styled(format!("{}s", state.active_timeout), if state.current_field == BatchField::ActiveTimeout { focused_style } else { default_style }),
        Span::raw(", "),
        Span::styled("Idle: ", if state.current_field == BatchField::IdleTimeout { focused_style } else { default_style }),
        Span::styled(format!("{}s", state.idle_timeout), if state.current_field == BatchField::IdleTimeout { focused_style } else { default_style }),
    ]);
    let timeouts_widget = Paragraph::new(timeout_spans).block(timeout_block);
    f.render_widget(timeouts_widget, form_chunks[5]);

    // Start Processing Button
    let start_button_style = if state.current_field == BatchField::StartProcessing {
        Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Green)
    };
    let start_button = Paragraph::new("[ Start Processing ]")
        .style(start_button_style)
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).border_style(if state.current_field == BatchField::StartProcessing {border_style_focused} else {Style::default().fg(Color::Green)}));
    f.render_widget(start_button, form_chunks[6]);

    // Validation Error Message
    if let Some(err_msg) = &state.validation_error {
        let error_p = Paragraph::new(err_msg.as_str())
            .style(Style::default().fg(Color::Red))
            .alignment(Alignment::Center);
        f.render_widget(error_p, main_chunks[2]);
    }


    let instructions = Paragraph::new("↑↓: Navigate | Enter: Edit/Select/Cycle | Tab: Toggle Recursive | +/-: Adjust Workers/Timeouts | Esc: Back to Main Menu")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    f.render_widget(instructions, main_chunks[3]);
}

pub fn render_batch_progress<B: Backend>(
    f: &mut Frame<B>,
    progress: &BatchProgress, // Changed to take a direct reference
) {
    let size = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Length(3), // Progress Bar
            Constraint::Length(7), // Statistics
            Constraint::Length(3), // Current File
            Constraint::Min(0),    // Log Area (placeholder)
            Constraint::Length(1), // Error Message
        ])
        .split(size);

    let title = Paragraph::new("Processing PCAP Files...")
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)));
    f.render_widget(title, chunks[0]);

    let progress_ratio = if progress.total_files > 0 {
        progress.processed_files as f64 / progress.total_files as f64
    } else { 0.0 };
    let progress_bar = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title("Overall Progress"))
        .gauge_style(Style::default().fg(Color::Green).bg(Color::DarkGray))
        .percent((progress_ratio * 100.0).min(100.0) as u16) // Ensure percent doesn't exceed 100
        .label(format!("{}/{} files", progress.processed_files, progress.total_files));
    f.render_widget(progress_bar, chunks[1]);

    let stats_text = vec![
        Line::from(Span::raw(format!("Total Files: {}", progress.total_files))),
        Line::from(Span::raw(format!("Processed:   {}", progress.processed_files))),
        Line::from(Span::styled(format!("Succeeded:   {}", progress.success_count), Style::default().fg(Color::Green))),
        Line::from(Span::styled(format!("Failed:      {}", progress.error_count), Style::default().fg(Color::Red))),
        Line::from(Span::raw(format!("Est. Time Remaining: {}", progress.estimated_remaining))),
    ];
    let stats = Paragraph::new(stats_text)
        .block(Block::default().borders(Borders::ALL).title("Statistics"));
    f.render_widget(stats, chunks[2]);

    let current_file_text = if progress.current_file.is_empty() && progress.processed_files == progress.total_files && progress.total_files > 0 {
        "Completed!".to_string()
    } else {
        progress.current_file.clone()
    };
    let current_file_widget = Paragraph::new(current_file_text)
        .block(Block::default().borders(Borders::ALL).title("Processing File"));
    f.render_widget(current_file_widget, chunks[3]);

    let log_area_text = if progress.processed_files == progress.total_files && progress.total_files > 0 {
        format!("Batch finished. Success: {}, Errors: {}.\nPress Esc to return.", progress.success_count, progress.error_count)
    } else {
        "Log messages (not fully implemented).\nPress Esc to attempt to cancel and return to setup.".to_string()
    };
    let log_area = Paragraph::new(log_area_text)
        .block(Block::default().borders(Borders::ALL).title("Status / Log"));
    f.render_widget(log_area, chunks[4]);

    if let Some(err_msg) = &progress.last_error_message {
        let error_p = Paragraph::new(err_msg.as_str())
            .style(Style::default().fg(Color::Red))
            .alignment(Alignment::Center);
        f.render_widget(error_p, chunks[5]);
    }
}

pub fn handle_batch_processing_events(
    event: crossterm::event::Event,
    state: &mut BatchProcessingState,
) -> Result<Option<AppTransition>, TUIError> {
    if let Event::Key(key) = event {
        // If processing, only allow Esc (handled by main loop to abort task)
        if state.processing {
            if key.code == KeyCode::Esc {
                warn!("Batch processing in progress. Main loop handles Esc to abort task.");
            }
            return Ok(None);
        }
        // Clear previous validation error on any key press if not processing
        state.validation_error = None;

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
            KeyCode::Down | KeyCode::Tab => { // Tab also navigates down
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
                    BatchField::InputDirectory => {
                        Ok(Some(AppTransition::ToTextInput {
                            field: "input_directory".to_string(), // This needs to map back to BatchField
                            current_value: state.input_directory.clone(),
                            title: "Input Directory Path".to_string(),
                        }))
                    }
                    BatchField::OutputDirectory => {
                         Ok(Some(AppTransition::ToTextInput {
                            field: "output_directory".to_string(),
                            current_value: state.output_directory.clone(),
                            title: "Output Directory Path".to_string(),
                        }))
                    }
                    BatchField::FeatureSet => {
                        let variants_str = FlowType::VARIANTS;
                        let current_pos = variants_str.iter().position(|&s| s.eq_ignore_ascii_case(&state.feature_set.to_string()));
                        if let Some(pos) = current_pos {
                            let next_pos = (pos + 1) % variants_str.len();
                            if let Ok(ft) = FlowType::from_str(variants_str[next_pos]) { // Requires FromStr for FlowType
                                state.feature_set = ft;
                            }
                        }
                        Ok(None)
                    }
                    BatchField::Recursive => {
                        state.recursive = !state.recursive;
                        Ok(None)
                    }
                    BatchField::StartProcessing => {
                        match validate_batch_inputs(state) {
                            Ok(_) => {
                                state.validation_error = None;
                                Ok(Some(AppTransition::StartBatchProcessing))
                            }
                            Err(e) => {
                                state.validation_error = Some(e);
                                Ok(None)
                            }
                        }
                    }
                    // WorkerCount, ActiveTimeout, IdleTimeout are adjusted with +/-
                    _ => Ok(None),
                }
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
                        if state.active_timeout >= 300 { state.active_timeout -= 300; } else { state.active_timeout = 0; }
                    }
                    BatchField::IdleTimeout => {
                        if state.idle_timeout >= 30 { state.idle_timeout -= 30; } else { state.idle_timeout = 0; }
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
    if state.input_directory.is_empty() { return Err("Input directory cannot be empty.".to_string()); }
    if !Path::new(&state.input_directory).exists() { return Err(format!("Input directory '{}' does not exist.", state.input_directory)); }
    if !Path::new(&state.input_directory).is_dir() { return Err(format!("Input path '{}' is not a directory.", state.input_directory)); }
    if state.output_directory.is_empty() { return Err("Output directory cannot be empty.".to_string()); }
    // Note: Output directory is created if it doesn't exist by the batch logic.
    // Further validation (e.g., writability) could be added here or handled by the batch task.
    if state.worker_count == 0 { return Err("Worker count must be at least 1.".to_string()); }
    if state.worker_count > num_cpus::get() * 4 { return Err(format!("Worker count exceeds reasonable limit (max {}).", num_cpus::get() * 4));}
    Ok(())
}

// --- Helper functions and existing TUI components (abbreviated) ---
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

// --- Rendering for general config (abbreviated, from original tui.rs) ---
fn render_title_buttons<B: Backend>(f: &mut Frame<B>, app: &App, area: Rect) {
    let buttons_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage(24), Constraint::Length(1), Constraint::Percentage(24),
                Constraint::Length(1), Constraint::Percentage(24), Constraint::Length(1),
                Constraint::Percentage(24),
            ].as_ref()
        ).split(area);

    let start_button = create_button(" Start ", app.title_bar_state.selected() == Some(0) && app.focus == AppFocus::TitleBar, Color::Green);
    let quit_button = create_button(" Quit ", app.title_bar_state.selected() == Some(1) && app.focus == AppFocus::TitleBar, Color::Red);
    let save_button = create_button(" Save ", app.title_bar_state.selected() == Some(2) && app.focus == AppFocus::TitleBar, Color::Blue);
    let reset_button = create_button(" Reset ", app.title_bar_state.selected() == Some(3) && app.focus == AppFocus::TitleBar, Color::Yellow);

    f.render_widget(start_button, buttons_layout[0]);
    f.render_widget(quit_button, buttons_layout[2]);
    f.render_widget(save_button, buttons_layout[4]);
    f.render_widget(reset_button, buttons_layout[6]);
}

fn create_button<'a>(label: &'a str, selected: bool, color: Color) -> Paragraph<'a> {
    Paragraph::new(label)
        .style(if selected { Style::default().fg(color).add_modifier(Modifier::BOLD) } else { Style::default().fg(color) })
        .block(
            Block::default().borders(Borders::ALL)
                .border_style(if selected { Style::default().fg(color).add_modifier(Modifier::BOLD) } else { Style::default().fg(color).add_modifier(Modifier::DIM) })
        )
        .alignment(Alignment::Center)
}

fn render_menu<B: Backend>(f: &mut Frame<B>, app: &App, area: Rect) {
    let menu_items: Vec<ListItem> = app.main_menu_items.iter().map(|item| ListItem::new(*item)).collect();
    let menu_list_widget = List::new(menu_items) // Renamed variable
        .block(
            Block::default().borders(Borders::ALL)
                .border_style(Style::default().fg(if app.focus == AppFocus::Menu { Color::Yellow } else { Color::Cyan }).add_modifier(Modifier::BOLD))
                .title("Menu")
        )
        .highlight_style(Style::default().fg(if app.focus == AppFocus::Menu { Color::Yellow } else { Color::White }).add_modifier(Modifier::BOLD))
        .highlight_symbol(">> ");
    f.render_stateful_widget(menu_list_widget, area, &mut app.main_menu_state.clone()); // Use cloned state
}

fn render_content_general_config<B: Backend>(f: &mut Frame<B>, app: &App, area: Rect) {
    // This function would render content based on app.main_menu_state.selected()
    // For brevity, not reproducing the full logic from the original file.
    // It would call render_selectable_list, render_input_paragraph, render_boolean_choice etc.
    // for general configuration items.
    // We need to ensure that when "Output Method" is selected in the menu,
    // and focus shifts to AppFocus::OutputSelection, the correct list is rendered.
    // This is typically handled in render_popups_general_config or a similar function.
    let placeholder = Paragraph::new("General config content area")
        .block(Block::default().borders(Borders::ALL).title("Details"));
    f.render_widget(placeholder, area);
}

fn render_current_selections_general_config<B: Backend>(f: &mut Frame<B>, app: &App, area: Rect) {
    let config = &app.config;
    let mut lines = vec![
        Line::from(Span::styled("Current Configuration:", Style::default().add_modifier(Modifier::BOLD))),
    ];

    // Feature Set
    lines.push(Line::from(format!("  Feature Set: {:?}", config.config.features)));

    // Mode (Command)
    let command_str = match &config.command {
        Commands::Realtime { interface, ingress_only } => format!("Realtime (Interface: {}, Ingress Only: {})", interface, ingress_only),
        Commands::Pcap { path } => format!("Pcap (Path: {})", path),
        Commands::BatchPcap => "Batch PCAP Processing".to_string(),
    };
    lines.push(Line::from(format!("  Mode: {}", command_str)));

    // Output Method
    let output_method_str = match config.output.output {
        ExportMethodType::Print => "Print to Console",
        ExportMethodType::Csv => "CSV File",
        ExportMethodType::Pandas => "Pandas (Parquet File)",
        ExportMethodType::Polars => "Polars (Parquet File)",
    };
    lines.push(Line::from(format!("  Output Method: {}", output_method_str)));
    if config.output.export_path.is_some() &&
       (config.output.output == ExportMethodType::Csv ||
        config.output.output == ExportMethodType::Pandas ||
        config.output.output == ExportMethodType::Polars) {
        lines.push(Line::from(format!("    Export Path: {}", config.output.export_path.as_deref().unwrap_or("N/A"))));
    }
    if config.output.output == ExportMethodType::Csv {
        lines.push(Line::from(format!("    Performance Mode (No TUI graph for CSV): {}", config.output.performance_mode)));
    }


    lines.push(Line::from(format!("  Active Timeout: {}s", config.config.active_timeout)));
    lines.push(Line::from(format!("  Idle Timeout: {}s", config.config.idle_timeout)));
    lines.push(Line::from(format!("  Expiration Check: {}s", config.config.expiration_check_interval)));
    lines.push(Line::from(format!("  Threads: {}", config.config.threads.map_or("Auto".to_string(), |t| t.to_string()))));
    lines.push(Line::from(format!("  Early Export: {}", config.config.early_export.map_or("Disabled".to_string(), |e| format!("{}s", e)))));
    lines.push(Line::from(format!("  Header: {}", config.output.header)));
    lines.push(Line::from(format!("  Drop Contaminant Features: {}", config.output.drop_contaminant_features)));

    if let Some(file_path) = &app.config_file {
        lines.push(Line::from(Span::raw(" "))); // Spacer
        lines.push(Line::from(Span::styled(format!("Loaded from: {}", file_path), Style::default().fg(Color::DarkGray))));
    }


    let text_widget = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Current Selections"))
        .wrap(ratatui::widgets::Wrap { trim: true });
    f.render_widget(text_widget, area);
}


fn render_popups_general_config<B: Backend>(f: &mut Frame<B>, app: &App, screen_size: Rect) {
    // This function would render popups for general configuration input.
    // Example: if app.focus == AppFocus::CommandArgumentInput ...
    match app.focus {
        AppFocus::FlowTypeSelection => {
            let items: Vec<ListItem> = FlowType::value_variants()
                .iter()
                .map(|variant| ListItem::new(format!("{:?}", variant)))
                .collect();
            render_selection_popup(f, "Select Feature Set", items, &app.flow_type_selection_state, screen_size);
        }
        AppFocus::CommandSelection => {
            let items = vec![
                ListItem::new("Realtime Capture"),
                ListItem::new("Pcap File"),
            ];
            render_selection_popup(f, "Select Mode", items, &app.command_selection_state, screen_size);
        }
        AppFocus::OutputSelection => {
            let items: Vec<ListItem> = ExportMethodType::value_variants()
                .iter()
                .map(|variant| {
                    let display_name = match variant {
                        ExportMethodType::Print => "Print to Console",
                        ExportMethodType::Csv => "CSV File",
                        ExportMethodType::Pandas => "Pandas (Parquet File)",
                        ExportMethodType::Polars => "Polars (Parquet File)",
                    };
                    ListItem::new(display_name)
                })
                .collect();
            render_selection_popup(f, "Select Output Method", items, &app.output_selection_state, screen_size);
        }
        // ... other popups for text input, number input etc. ...
        AppFocus::ActiveTimeoutInput => render_text_input_popup(f, "Active Timeout (seconds)", &app.active_timeout_input_buffer, screen_size),
        AppFocus::IdleTimeoutInput => render_text_input_popup(f, "Idle Timeout (seconds)", &app.idle_timeout_input_buffer, screen_size),
        AppFocus::ExpirationCheckIntervalInput => render_text_input_popup(f, "Expiration Check Interval (seconds)", &app.expiration_check_interval_input_buffer, screen_size),
        AppFocus::ThreadsInput => render_text_input_popup(f, "Worker Threads (number, or empty for auto)", &app.threads_input_buffer, screen_size),
        AppFocus::EarlyExportInput => render_text_input_popup(f, "Early Export Interval (seconds, or empty for disabled)", &app.early_export_input_buffer, screen_size),
        AppFocus::CommandArgumentInput => {
            let title = match app.config.command {
                Commands::Realtime { .. } => "Network Interface (e.g., eth0)",
                Commands::Pcap { .. } => "PCAP File Path",
                _ => "Argument",
            };
            render_text_input_popup(f, title, &app.command_argument_input_buffer, screen_size);
        }
        AppFocus::OutputArgumentInput => {
             let title = match app.config.output.output {
                ExportMethodType::Csv => "CSV Export File Path",
                ExportMethodType::Pandas => "Pandas Parquet Export File Path",
                ExportMethodType::Polars => "Polars Parquet Export File Path",
                _ => "Export Path", // Should not be reachable if logic is correct
            };
            render_text_input_popup(f, title, &app.output_argument_input_buffer, screen_size);
        }
        _ => {} // No popup for other focus states handled by main screen
    }
}


// Helper function to render a generic selection popup (used for FlowType, Command, OutputMethod)
fn render_selection_popup<B: Backend>(
    f: &mut Frame<B>,
    title: &str,
    items: Vec<ListItem>,
    list_state: &ListState, // Pass ListState as a reference
    screen_size: Rect,
) {
    let popup_area = centered_rect(60, 50, screen_size); // Adjust size as needed
    f.render_widget(Clear, popup_area);

    let list_widget = List::new(items)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow))
                .style(Style::default().bg(Color::DarkGray)),
        )
        .highlight_style(Style::default().fg(Color::Black).bg(Color::LightGreen).add_modifier(Modifier::BOLD))
        .highlight_symbol(">> ");

    f.render_stateful_widget(list_widget, popup_area, &mut list_state.clone()); // Clone state for rendering
}


fn render_config_file_input_popup<B: Backend>(f: &mut Frame<B>, input_buffer: &str, screen_size: Rect) {
    let popup_area = centered_rect(70, 20, screen_size);
    f.render_widget(Clear, popup_area);
    let block = Block::default()
        .title("Load Config File (Enter path or press Enter for new)")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow))
        .style(Style::default().bg(Color::DarkGray));
    let p = Paragraph::new(input_buffer)
        .style(Style::default().fg(Color::White))
        .block(block);
    f.render_widget(p, popup_area);
}

fn render_config_file_save_popup<B: Backend>(f: &mut Frame<B>, input_buffer: &str, screen_size: Rect) {
    let popup_area = centered_rect(70, 20, screen_size);
    f.render_widget(Clear, popup_area);
     let block = Block::default()
        .title("Save Config File (Enter path and press Enter)")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow))
        .style(Style::default().bg(Color::DarkGray));
    let p = Paragraph::new(input_buffer)
        .style(Style::default().fg(Color::White))
        .block(block);
    f.render_widget(p, popup_area);
}


// --- Event Handlers for general config (abbreviated) ---
fn handle_title_bar_input<B: Backend>(key: KeyEvent, app: &mut App) -> Result<Option<Config>, TUIError> {
    match key.code {
        KeyCode::Left => {
            let i = match app.title_bar_state.selected() { Some(i) if i > 0 => i - 1, _ => 0 };
            app.title_bar_state.select(Some(i));
        }
        KeyCode::Right => {
            let i = match app.title_bar_state.selected() { Some(i) if i < 3 => i + 1, _ => 3 };
            app.title_bar_state.select(Some(i));
        }
        KeyCode::Enter => match app.title_bar_state.selected() {
            Some(0) => return Ok(Some(app.config.clone())), // Start
            Some(1) => return Err(TUIError::Other("User quit".to_string())), // Quit
            Some(2) => app.focus = AppFocus::ConfigFileSaveInput, // Save
            Some(3) => app.config = Config::reset(), // Reset
            _ => {}
        },
        KeyCode::Down => app.focus = AppFocus::Menu,
        _ => {}
    }
    Ok(None)
}

fn handle_menu_input(key: KeyEvent, app: &mut App) -> Result<Option<AppTransition>, TUIError> {
    match key.code {
        KeyCode::Up => {
            if app.main_menu_state.selected() == Some(0) {
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
        KeyCode::Enter | KeyCode::Right => {
            if let Some(selected_index) = app.main_menu_state.selected() {
                match app.main_menu_items[selected_index] {
                    "Batch PCAP Processing" => return Ok(Some(AppTransition::ToBatchSetupScreen)),
                    "Feature Set" => {
                        // Initialize selection state based on current config
                        let current_idx = FlowType::value_variants().iter().position(|&v| v == app.config.config.features).unwrap_or(0);
                        app.flow_type_selection_state.select(Some(current_idx));
                        app.focus = AppFocus::FlowTypeSelection;
                    }
                    "Mode" => {
                        let current_idx = match app.config.command {
                            Commands::Realtime { .. } => 0,
                            Commands::Pcap { .. } => 1,
                            _ => 0, // Default or should not happen for this menu item
                        };
                        app.command_selection_state.select(Some(current_idx));
                        app.focus = AppFocus::CommandSelection;
                    }
                    "Output Method" => {
                        let current_idx = ExportMethodType::value_variants().iter().position(|&v| v == app.config.output.output).unwrap_or(0);
                        app.output_selection_state.select(Some(current_idx));
                        app.focus = AppFocus::OutputSelection;
                    }
                    "Active Timeout" => {
                        app.active_timeout_input_buffer = app.config.config.active_timeout.to_string();
                        app.focus = AppFocus::ActiveTimeoutInput;
                    }
                    "Idle Timeout" => {
                        app.idle_timeout_input_buffer = app.config.config.idle_timeout.to_string();
                        app.focus = AppFocus::IdleTimeoutInput;
                    }
                    "Expiration Check Interval" => {
                        app.expiration_check_interval_input_buffer = app.config.config.expiration_check_interval.to_string();
                        app.focus = AppFocus::ExpirationCheckIntervalInput;
                    }
                     "Threads" => {
                        app.threads_input_buffer = app.config.config.threads.map_or(String::new(), |t| t.to_string());
                        app.focus = AppFocus::ThreadsInput;
                    }
                    "Early Export" => {
                        app.early_export_input_buffer = app.config.config.early_export.map_or(String::new(), |e| e.to_string());
                        app.focus = AppFocus::EarlyExportInput;
                    }
                    "Header" => {
                        app.config.output.header = !app.config.output.header; // Toggle directly
                    }
                    "Drop Contaminant Features" => {
                        app.config.output.drop_contaminant_features = !app.config.output.drop_contaminant_features; // Toggle
                    }
                    // ... other general config items ...
                    _ => {}
                }
            }
        }
        KeyCode::Esc => return Err(TUIError::Other("User quit".to_string())),
        _ => {}
    }
    Ok(None)
}


// Specific handler for AppFocus::OutputSelection
fn handle_output_selection_input(key: KeyEvent, app: &mut App) {
    let variants = ExportMethodType::value_variants();
    let num_variants = variants.len();
    let current_idx = app.output_selection_state.selected().unwrap_or(0);

    match key.code {
        KeyCode::Up => {
            let new_idx = if current_idx == 0 { num_variants - 1 } else { current_idx - 1 };
            app.output_selection_state.select(Some(new_idx));
        }
        KeyCode::Down => {
            let new_idx = (current_idx + 1) % num_variants;
            app.output_selection_state.select(Some(new_idx));
        }
        KeyCode::Enter => {
            if let Some(selected_idx) = app.output_selection_state.selected() {
                app.config.output.output = variants[selected_idx].clone();
                // If a file-based output is selected, prepare for export_path input
                match app.config.output.output {
                    ExportMethodType::Csv | ExportMethodType::Pandas | ExportMethodType::Polars => {
                        app.output_argument_input_buffer = app.config.output.export_path.clone().unwrap_or_default();
                        app.focus = AppFocus::OutputArgumentInput;
                    }
                    _ => { // For Print, go back to menu
                        app.focus = AppFocus::Menu;
                    }
                }
            }
        }
        KeyCode::Esc => {
            app.focus = AppFocus::Menu;
        }
        _ => {}
    }
}


// Placeholder for other input handlers from original tui.rs, adapt as needed
fn handle_config_file_input(key: KeyEvent, app: &mut App) -> Result<(), TUIError> {
    match key.code {
        KeyCode::Char(c) => app.config_file_input.push(c),
        KeyCode::Backspace => { app.config_file_input.pop(); }
        KeyCode::Enter => {
            if fs::metadata(&app.config_file_input).is_ok() {
                app.config_file = Some(app.config_file_input.clone());
                match confy::load_path::<ConfigFile>(&app.config_file_input) {
                    Ok(cf) => app.config = Config {
                        config: cf.config,
                        output: cf.output,
                        command: app.config.command.clone(), // Preserve command if not in file
                    },
                    Err(e) => {
                        error!("Failed to load config file {}: {}", app.config_file_input, e);
                        app.config = Config::reset(); // Reset on error
                    }
                }
            } else if app.config_file_input.is_empty() {
                 info!("Starting with a new default configuration.");
                 app.config = Config::reset();
            } else {
                error!("Config file not found: {}", app.config_file_input);
                // Optionally clear input or keep it for user to correct
            }
            app.config_file_input.clear();
            app.focus = AppFocus::Menu;
        }
        KeyCode::Esc => { // Allow Esc to cancel config file input and go to menu
            app.config_file_input.clear();
            app.focus = AppFocus::Menu;
        }
        _ => {}
    }
    Ok(())
}


fn handle_output_argument_input(key: KeyEvent, app: &mut App) {
    match key.code {
        KeyCode::Char(c) => app.output_argument_input_buffer.push(c),
        KeyCode::Backspace => { app.output_argument_input_buffer.pop(); },
        KeyCode::Enter => {
            app.config.output.export_path = Some(app.output_argument_input_buffer.clone()).filter(|s| !s.is_empty());
            app.focus = AppFocus::Menu; // Return to menu after setting
        }
        KeyCode::Esc => {
            app.focus = AppFocus::Menu; // Cancel and return to menu
        }
        _ => {}
    }
}


fn handle_config_file_save_input(key: KeyEvent, app: &mut App) -> Result<(), TUIError> {
     match key.code {
        KeyCode::Char(c) => app.config_file_input.push(c),
        KeyCode::Backspace => { app.config_file_input.pop(); }
        KeyCode::Enter => {
            let path_to_save = app.config_file_input.clone();
            if path_to_save.is_empty() {
                error!("Save path cannot be empty.");
            } else {
                let config_to_save = ConfigFile {
                    config: app.config.config.clone(),
                    output: app.config.output.clone(),
                };
                if let Err(e) = confy::store_path(&path_to_save, config_to_save) {
                    error!("Error saving config to {}: {}", path_to_save, e);
                } else {
                    info!("Config saved to {}", path_to_save);
                    app.config_file = Some(path_to_save);
                }
            }
            app.config_file_input.clear();
            app.focus = AppFocus::Menu;
        }
        KeyCode::Esc => {
            app.config_file_input.clear();
            app.focus = AppFocus::Menu;
        }
        _ => {}
    }
    Ok(())
}

// Implement other handlers like handle_flow_type_input, handle_numeric_input etc.
// These would modify app.config fields and switch app.focus.

// A new generic text input handler for simple text fields
fn handle_generic_text_input(key: KeyEvent, app: &mut App) {
    let buffer: &mut String = match app.focus {
        AppFocus::ActiveTimeoutInput => &mut app.active_timeout_input_buffer,
        AppFocus::IdleTimeoutInput => &mut app.idle_timeout_input_buffer,
        AppFocus::ExpirationCheckIntervalInput => &mut app.expiration_check_interval_input_buffer,
        AppFocus::ThreadsInput => &mut app.threads_input_buffer,
        AppFocus::EarlyExportInput => &mut app.early_export_input_buffer,
        AppFocus::CommandArgumentInput => &mut app.command_argument_input_buffer,
        // AppFocus::OutputArgumentInput is handled by its own function due to specific logic.
        _ => return, // Should not happen if called correctly
    };

    match key.code {
        KeyCode::Char(c) => buffer.push(c),
        KeyCode::Backspace => { buffer.pop(); },
        KeyCode::Enter => {
            // Apply the input and return to menu
            match app.focus {
                AppFocus::ActiveTimeoutInput => {
                    if let Ok(val) = app.active_timeout_input_buffer.parse() { app.config.config.active_timeout = val; }
                    else if app.active_timeout_input_buffer.is_empty() { /* Allow empty to reset to default or handle error */ }
                }
                AppFocus::IdleTimeoutInput => {
                    if let Ok(val) = app.idle_timeout_input_buffer.parse() { app.config.config.idle_timeout = val; }
                }
                AppFocus::ExpirationCheckIntervalInput => {
                    if let Ok(val) = app.expiration_check_interval_input_buffer.parse() { app.config.config.expiration_check_interval = val; }
                }
                AppFocus::ThreadsInput => {
                     app.config.config.threads = app.threads_input_buffer.parse().ok();
                }
                AppFocus::EarlyExportInput => {
                    app.config.config.early_export = app.early_export_input_buffer.parse().ok();
                }
                AppFocus::CommandArgumentInput => {
                    match &mut app.config.command {
                        Commands::Realtime { interface, .. } => *interface = app.command_argument_input_buffer.clone(),
                        Commands::Pcap { path, .. } => *path = app.command_argument_input_buffer.clone(),
                        _ => {}
                    }
                }
                _ => {}
            }
            app.focus = AppFocus::Menu;
        }
        KeyCode::Esc => {
            app.focus = AppFocus::Menu; // Cancel
        }
        _ => {}
    }
}

```

**Notes on this generated `tui.rs`:**

1.  **Dependencies:** Make sure your `Cargo.toml` for the `rustiflow` crate includes `ratatui`, `crossterm`, `serde`, `log`, `strum`, `strum_macros`, `tokio`, `num_cpus`, and `confy`.
2.  **`batch_processor` Function:** The `launch_tui` function now takes a `batch_processor` function pointer. This function (which you'd implement in `main.rs` or a separate module) is responsible for the actual batch processing work. It receives the `BatchProcessingState` and a `mpsc::Sender<BatchProgress>` to send progress updates back to the TUI. It should return a `JoinHandle<()>`.
3.  **Async Progress Updates:** The main TUI loop in `launch_tui` uses `tokio::select!` to listen for user input and for progress messages from the spawned batch task.
4.  **Input Popups:** For directory and number input in the batch setup, I've used `AppTransition::ToTextInput`. A `render_text_input_popup` and basic handling in the main loop are added. A more robust solution would involve a dedicated input mode or widget.
5.  **Error Handling:** The `TUIError` enum is basic. You can expand it. Validation errors in batch setup are now stored in `BatchProcessingState` and displayed.
6.  **General Config UI:** The rendering and event handling for the general application configuration (non-batch parts) are kept abbreviated using placeholders like `render_content_general_config`. You would fill these in with your existing logic, adapted for the `App` struct and `AppFocus` enum.
7.  **`FlowType` (FeatureSet):** For cycling through `FlowType` in the batch setup, it needs to derive `strum::VariantNames` and `std::str::FromStr` (or `strum::EnumString`).
8.  **Stopping Batch Task:** Pressing `Esc` on the batch progress screen will now attempt to abort the task and return to the setup screen.
9.  **Path Initialization:** Batch input/output directories are initialized to current dir and a subfolder.
10. **Cloning `BatchProcessingState` for Task:** The `BatchProcessingState` now derives `Clone`. When spawning the batch task, a clone of the state is passed. The `Arc<Mutex<BatchProgress>>` within it is already designed for sharing.

This file is quite extensive. You'll need to carefully review and adapt it to your existing codebase, especially the parts marked as abbreviated or requiring further implementation for full input functionality.Okay, I've generated the `tui.rs` file for you in the canvas.

It includes the new batch processing TUI elements, integrates them with a main event loop, and sets up the structure for asynchronous batch processing with progress updates.

**Key things to note about this version:**

* **`ratatui`:** It uses `ratatui` for all TUI components.
* **`batch_processor` function:** The `launch_tui` function now expects a function pointer `batch_processor`. This function (which you'll define in `main.rs` or another module) will contain the actual logic for performing the batch processing. It will receive the batch configuration and a channel sender to send `BatchProgress` updates back to the TUI.
* **Asynchronous Updates:** The TUI loop uses `tokio::select!` to handle both user input and incoming progress messages from the batch task.
* **Input Handling:**
    * Basic text input popups are implemented for directory paths in the batch setup.
    * Cycling through feature sets and toggling recursive search are handled.
    * Adjusting worker count and timeouts with `+/-` keys is supported.
* **Error Display:** Validation errors for batch inputs are now displayed on the setup screen. The progress screen can also show a `last_error_message`.
* **Task Management:** Starting a batch process spawns a Tokio task. Pressing `Esc` on the progress screen attempts to abort this task.
* **General Config UI:** The parts of the TUI related to the *original* single-file processing or real-time mode configuration are present but simplified in the rendering functions (`render_content_general_config`, etc.) to keep the example focused. You'll need to integrate your existing logic there.

You'll need to ensure your `Cargo.toml` has all the necessary dependencies like `ratatui`, `crossterm`, `tokio`, `strum`, `num_cpus`, etc. The actual implementation of the `batch_processor` function in your `main.rs` will be crucial for the batch functionality to wo

use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use std::error::Error;
use std::io;
use std::time::Duration;
use tokio::sync::watch::Receiver;
use tokio::task;
use tui::backend::{Backend, CrosstermBackend};
use tui::layout::{Alignment, Constraint, Direction, Layout};
use tui::style::{Color, Style};
use tui::widgets::{Block, Borders, Paragraph, Sparkline};
use tui::{Frame, Terminal};

struct PacketData {
    count: u64,
}

struct App {
    packet_data: Vec<PacketData>,
    max_visible_intervals: usize,
}

impl App {
    fn new() -> Self {
        Self {
            packet_data: Vec::new(),
            max_visible_intervals: 100,
        }
    }

    fn update_packet_data(&mut self, counts: &[(u64, u64)]) {
        self.packet_data.clear();
        for &(_timestamp, count) in counts.iter().rev() {
            self.packet_data.push(PacketData { count });
        }
    }

    fn get_bar_data(&self) -> Vec<u64> {
        self.packet_data
            .iter()
            .map(|data| (data.count))
            .take(self.max_visible_intervals)
            .collect()
    }
}

pub async fn launch_packet_tui(packet_rx: Receiver<Vec<(u64, u64)>>) -> Result<(), Box<dyn Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();

    let res = run_app(&mut terminal, &mut app, packet_rx).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    res
}

async fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    mut packet_rx: Receiver<Vec<(u64, u64)>>,
) -> Result<(), Box<dyn Error>> {
    loop {
        terminal.draw(|f| ui_main_screen(f, app))?;

        tokio::select! {
            Ok(_) = packet_rx.changed() => {
                let counts = packet_rx.borrow();
                app.update_packet_data(&*counts);
            }

            poll_result = task::spawn_blocking(|| crossterm::event::poll(Duration::from_millis(100))) => {
                if poll_result?? {
                    if let Event::Key(key) = event::read()? {
                        match key.code {
                            KeyCode::Char('q') => return Ok(()),
                            _ => {}
                        }
                    }
                }
            }
        }
    }
}

fn ui_main_screen<B: Backend>(f: &mut Frame<B>, app: &App) {
    let size = f.size();

    let background = Block::default().style(Style::default().bg(Color::Black));

    f.render_widget(background, size);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(0)].as_ref())
        .split(size);

    let rustiflow_art = "
    █▀█ █ █ █▀ ▀█▀ █ █▀▀ █   █▀█ █ █ █
    █▀▄ █▄█ ▄█  █  █ █▀  █▄▄ █▄█ ▀▄▀▄▀            Press 'q' to quit the graph";

    let art_paragraph = Paragraph::new(rustiflow_art)
        .style(Style::default().fg(Color::Yellow))
        .alignment(Alignment::Left);

    f.render_widget(art_paragraph, layout[0]);

    let bar_data: Vec<u64> = app.get_bar_data();

    let bar_chart = Sparkline::default()
        .block(Block::default().borders(Borders::NONE))
        .style(Style::default().fg(Color::Yellow))
        .data(&bar_data)
        .max(
            app.packet_data
                .iter()
                .map(|data| data.count)
                .max()
                .unwrap_or((app.max_visible_intervals + 1) as u64),
        );

    f.render_widget(bar_chart, layout[1]);
}

use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ghost_core::{DetectionEngine, ThreatLevel};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, Cell, Clear, Gauge, List, ListItem, ListState, Paragraph, Row, Table,
        TableState, Tabs, Wrap,
    },
    Frame, Terminal,
};
use std::{
    collections::VecDeque,
    io,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::Mutex, time};

mod app;
mod events;
mod ui;

use app::{App, TabIndex};

#[tokio::main]
async fn main() -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let app = Arc::new(Mutex::new(App::new().await?));

    // Clone for background task
    let app_clone = Arc::clone(&app);

    // Start background scanning task
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(2));
        loop {
            interval.tick().await;
            if let Ok(mut app) = app_clone.try_lock() {
                if let Err(e) = app.update_scan_data().await {
                    app.add_log_message(format!("Scan error: {}", e));
                }
            }
        }
    });

    // Main event loop
    let res = run_app(&mut terminal, app).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err);
    }

    Ok(())
}

async fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: Arc<Mutex<App>>) -> Result<()> {
    loop {
        // Draw the UI
        terminal.draw(|f| {
            if let Ok(app) = app.try_lock() {
                ui::draw::<CrosstermBackend<std::io::Stdout>>(f, &app);
            }
        })?;

        // Handle events
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Tab => {
                            if let Ok(mut app) = app.try_lock() {
                                app.next_tab();
                            }
                        }
                        KeyCode::Up => {
                            if let Ok(mut app) = app.try_lock() {
                                app.scroll_up();
                            }
                        }
                        KeyCode::Down => {
                            if let Ok(mut app) = app.try_lock() {
                                app.scroll_down();
                            }
                        }
                        KeyCode::Enter => {
                            if let Ok(mut app) = app.try_lock() {
                                app.select_item();
                            }
                        }
                        KeyCode::Char('r') => {
                            if let Ok(mut app) = app.try_lock() {
                                if let Err(e) = app.force_refresh().await {
                                    app.add_log_message(format!("Refresh error: {}", e));
                                }
                            }
                        }
                        KeyCode::Char('c') => {
                            if let Ok(mut app) = app.try_lock() {
                                app.clear_detections();
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

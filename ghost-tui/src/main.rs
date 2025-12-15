use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    Terminal,
};
use std::{io, panic, sync::Arc, time::Duration};
use tokio::{sync::Mutex, time};

mod app;
mod events;
mod ui;

use app::App;

/// Cleanup terminal state - called on exit or panic
fn cleanup_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
}

/// Initialize terminal with proper error handling for Windows
fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    // Set up panic hook to restore terminal on crash
    let original_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        cleanup_terminal();
        original_hook(panic_info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging for debugging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .format_timestamp(None)
        .init();

    // Setup terminal with proper Windows support
    let mut terminal = match setup_terminal() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to initialize terminal: {}", e);
            eprintln!("Make sure you're running in a terminal that supports ANSI escape codes.");
            #[cfg(windows)]
            eprintln!("On Windows, use Windows Terminal, PowerShell, or cmd.exe.");
            return Err(e);
        }
    };

    // Create app state
    let app = match App::new().await {
        Ok(a) => Arc::new(Mutex::new(a)),
        Err(e) => {
            cleanup_terminal();
            eprintln!("Failed to initialize application: {}", e);
            return Err(e);
        }
    };

    // Draw the initial frame immediately so users see the TUI
    {
        let app_guard = app.lock().await;
        terminal.draw(|f| ui::draw(f, &app_guard))?;
    }

    // Clone for background task
    let app_clone = Arc::clone(&app);

    // Start background scanning task with initial delay to let UI render
    tokio::spawn(async move {
        // Small delay to let the first frame render
        time::sleep(Duration::from_millis(100)).await;

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
    cleanup_terminal();
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("Application error: {:?}", err);
    }

    Ok(())
}

async fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: Arc<Mutex<App>>) -> Result<()> {
    loop {
        // Draw the UI
        terminal.draw(|f| {
            if let Ok(app) = app.try_lock() {
                ui::draw(f, &app);
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

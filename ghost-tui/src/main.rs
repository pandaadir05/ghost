use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ghost_core::{process, DetectionEngine};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    Terminal,
};
use std::{
    io, panic,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{Mutex, Notify},
    time,
};

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

    // Initialize the detection engine before touching the terminal so
    // failures print normally
    let detection_engine = match DetectionEngine::new() {
        Ok(engine) => engine,
        Err(e) => {
            eprintln!("Failed to initialize detection engine: {}", e);
            return Err(anyhow::anyhow!(
                "Failed to initialize detection engine: {}",
                e
            ));
        }
    };

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

    // Wakes the scanner early when the user requests a refresh
    let refresh = Arc::new(Notify::new());

    // Clone for background task
    let app_clone = Arc::clone(&app);
    let refresh_signal = Arc::clone(&refresh);

    // Start background scanning task with initial delay to let UI render.
    // The task owns the detection engine and analyzes processes WITHOUT the
    // app lock, streaming each result into the shared state under a brief
    // lock so the UI fills in live instead of all at once - a full sweep
    // can take minutes on busy systems.
    tokio::spawn(async move {
        let mut engine = detection_engine;

        // Small delay to let the first frame render
        time::sleep(Duration::from_millis(100)).await;

        let mut interval = time::interval(Duration::from_secs(2));
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = refresh_signal.notified() => {}
            }

            let processes = match process::enumerate_processes() {
                Ok(procs) => procs,
                Err(e) => {
                    let mut app = app_clone.lock().await;
                    app.add_log_message(format!("Scan error: process enumeration failed: {}", e));
                    continue;
                }
            };

            let scan_start = Instant::now();
            app_clone.lock().await.begin_scan(processes.clone());

            for (i, proc) in processes.iter().enumerate() {
                let data = App::scan_process(&mut engine, proc);
                app_clone.lock().await.record_scan_result(i + 1, data);
            }

            app_clone
                .lock()
                .await
                .finish_scan(scan_start.elapsed().as_millis() as u64);
        }
    });

    // Main event loop
    let res = run_app(&mut terminal, app, refresh).await;

    // Restore terminal
    cleanup_terminal();
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("Application error: {:?}", err);
    }

    Ok(())
}

async fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    app: Arc<Mutex<App>>,
    refresh: Arc<Notify>,
) -> Result<()> {
    loop {
        // Draw the UI. If the state is momentarily locked, keep the last
        // frame - drawing without widgets would blank the screen.
        if let Ok(app) = app.try_lock() {
            terminal.draw(|f| ui::draw(f, &app))?;
        }

        // Handle events. The short poll doubles as the redraw tick, which
        // keeps the elapsed-scan timer moving.
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') => return Ok(()),
                        KeyCode::Tab | KeyCode::Right => {
                            if let Ok(mut app) = app.try_lock() {
                                app.next_tab();
                            }
                        }
                        KeyCode::BackTab | KeyCode::Left => {
                            if let Ok(mut app) = app.try_lock() {
                                app.prev_tab();
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
                        KeyCode::Char('r') | KeyCode::Char('R') => {
                            if let Ok(mut app) = app.try_lock() {
                                app.add_log_message("Forcing refresh...".to_string());
                            }
                            refresh.notify_one();
                        }
                        KeyCode::Char('c') | KeyCode::Char('C') => {
                            if let Ok(mut app) = app.try_lock() {
                                app.clear_current();
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

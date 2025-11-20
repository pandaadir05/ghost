//! Terminal User Interface rendering for Ghost detection system.
//!
//! This module provides all the drawing functions for the TUI components,
//! including the main dashboard, process list, detection history, and system logs.

#![allow(dead_code, unused_imports)]

use crate::app::{App, TabIndex};
use ghost_core::ThreatLevel;
use ratatui::{
    backend::Backend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Cell, Gauge, List, ListItem, Paragraph, Row, Table, Tabs, Wrap},
    Frame,
};

/// Color scheme for consistent theming across the application.
mod colors {
    use ratatui::style::Color;

    pub const PRIMARY: Color = Color::Cyan;
    pub const SECONDARY: Color = Color::Magenta;
    pub const SUCCESS: Color = Color::Green;
    pub const WARNING: Color = Color::Yellow;
    pub const DANGER: Color = Color::Red;
    pub const BACKGROUND: Color = Color::Black;
    pub const TEXT: Color = Color::White;
    pub const MUTED: Color = Color::Gray;
}

use colors::*;

pub fn draw(f: &mut Frame, app: &App) {
    let size = f.size();

    // Create main layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Content
            Constraint::Length(3), // Footer
        ])
        .split(size);

    // Draw header
    draw_header(f, chunks[0], app);

    // Draw main content based on selected tab
    match app.current_tab {
        TabIndex::Overview => draw_overview(f, chunks[1], app),
        TabIndex::Processes => draw_processes(f, chunks[1], app),
        TabIndex::Detections => draw_detections(f, chunks[1], app),
        TabIndex::Memory => draw_memory(f, chunks[1], app),
        TabIndex::Logs => draw_logs(f, chunks[1], app),
        TabIndex::ThreatIntel => {} // TODO: Implement threat intel view
    }

    // Draw footer
    draw_footer(f, chunks[2], app);
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let titles = app.get_tab_titles();
    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Ghost - Process Injection Detection")
                .title_style(Style::default().fg(PRIMARY).add_modifier(Modifier::BOLD))
                .border_style(Style::default().fg(PRIMARY)),
        )
        .select(app.current_tab as usize)
        .style(Style::default().fg(TEXT))
        .highlight_style(
            Style::default()
                .fg(BACKGROUND)
                .bg(PRIMARY)
                .add_modifier(Modifier::BOLD),
        );

    f.render_widget(tabs, area);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let help_text = match app.current_tab {
        TabIndex::Overview => {
            "Up/Down: Navigate | Tab: Switch tabs | R: Refresh | C: Clear | Q: Quit"
        }
        TabIndex::Processes => {
            "Up/Down: Select process | Enter: View details | Tab: Switch tabs | Q: Quit"
        }
        TabIndex::Detections => {
            "Up/Down: Navigate detections | C: Clear history | Tab: Switch tabs | Q: Quit"
        }
        TabIndex::Memory => "Up/Down: Navigate | Tab: Switch tabs | R: Refresh | Q: Quit",
        TabIndex::Logs => "Up/Down: Navigate logs | C: Clear logs | Tab: Switch tabs | Q: Quit",
        TabIndex::ThreatIntel => "Up/Down: Navigate threats | Tab: Switch tabs | Q: Quit",
    };

    let footer = Paragraph::new(help_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(SECONDARY)),
        )
        .style(Style::default().fg(TEXT))
        .alignment(Alignment::Center);

    f.render_widget(footer, area);
}

fn draw_overview(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8), // Stats
            Constraint::Length(8), // Threat level gauge
            Constraint::Min(0),    // Recent detections
        ])
        .split(area);

    // Statistics panel
    draw_stats_panel(f, chunks[0], app);

    // Threat level gauge
    draw_threat_gauge(f, chunks[1], app);

    // Recent detections
    draw_recent_detections(f, chunks[2], app);
}

fn draw_stats_panel(f: &mut Frame, area: Rect, app: &App) {
    let stats_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);

    let total_processes = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Total Processes")
                .border_style(Style::default().fg(PRIMARY)),
        )
        .gauge_style(Style::default().fg(PRIMARY))
        .percent(std::cmp::min(app.stats.total_processes.saturating_mul(100) / 500, 100) as u16)
        .label(format!("{}", app.stats.total_processes));

    f.render_widget(total_processes, stats_chunks[0]);

    let suspicious_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Suspicious")
                .border_style(Style::default().fg(WARNING)),
        )
        .gauge_style(Style::default().fg(WARNING))
        .percent(if app.stats.total_processes > 0 {
            (app.stats.suspicious_processes.saturating_mul(100) / app.stats.total_processes) as u16
        } else {
            0
        })
        .label(format!("{}", app.stats.suspicious_processes));

    f.render_widget(suspicious_gauge, stats_chunks[1]);

    let malicious_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Malicious")
                .border_style(Style::default().fg(DANGER)),
        )
        .gauge_style(Style::default().fg(DANGER))
        .percent(if app.stats.total_processes > 0 {
            (app.stats.malicious_processes.saturating_mul(100) / app.stats.total_processes) as u16
        } else {
            0
        })
        .label(format!("{}", app.stats.malicious_processes));

    f.render_widget(malicious_gauge, stats_chunks[2]);

    let perf_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Scan Time (ms)")
                .border_style(Style::default().fg(SUCCESS)),
        )
        .gauge_style(Style::default().fg(SUCCESS))
        .percent(std::cmp::min(app.stats.scan_time_ms as u16 / 10, 100))
        .label(format!("{}ms", app.stats.scan_time_ms));

    f.render_widget(perf_gauge, stats_chunks[3]);
}

fn draw_threat_gauge(f: &mut Frame, area: Rect, app: &App) {
    let threat_level = if app.stats.malicious_processes > 0 {
        100
    } else if app.stats.suspicious_processes > 0 {
        60
    } else {
        20
    };

    let color = if threat_level > 80 {
        DANGER
    } else if threat_level > 40 {
        WARNING
    } else {
        SUCCESS
    };

    let threat_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("System Threat Level")
                .title_style(Style::default().fg(color).add_modifier(Modifier::BOLD))
                .border_style(Style::default().fg(color)),
        )
        .gauge_style(Style::default().fg(color))
        .percent(threat_level)
        .label(format!(
            "{}% - {} Detection(s)",
            threat_level, app.stats.total_detections
        ));

    f.render_widget(threat_gauge, area);
}

fn draw_recent_detections(f: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
        .detections
        .iter()
        .take(10)
        .map(|detection| {
            let (level_marker, style) = match detection.threat_level {
                ThreatLevel::Malicious => ("[!]", Style::default().fg(DANGER)),
                ThreatLevel::Suspicious => ("[?]", Style::default().fg(WARNING)),
                ThreatLevel::Clean => ("[+]", Style::default().fg(SUCCESS)),
            };

            let time = detection.timestamp.format("%H:%M:%S");
            let content = format!(
                "{} [{}] {} (PID: {}) - {:.1}%",
                level_marker,
                time,
                detection.process.name,
                detection.process.pid,
                detection.confidence * 100.0
            );

            ListItem::new(content).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Recent Detections")
                .border_style(Style::default().fg(SECONDARY)),
        )
        .style(Style::default().fg(TEXT));

    f.render_widget(list, area);
}

fn draw_processes(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area);

    // Process table
    let header_cells = ["PID", "PPID", "Name", "Threads", "Status"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(PRIMARY).add_modifier(Modifier::BOLD)));

    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let rows: Vec<Row> = app
        .processes
        .iter()
        .map(|proc| {
            let status = match app.detections.iter().find(|d| d.process.pid == proc.pid) {
                Some(detection) => match detection.threat_level {
                    ThreatLevel::Malicious => "MALICIOUS",
                    ThreatLevel::Suspicious => "SUSPICIOUS",
                    ThreatLevel::Clean => "CLEAN",
                },
                None => "CLEAN",
            };

            Row::new(vec![
                Cell::from(proc.pid.to_string()),
                Cell::from(proc.ppid.to_string()),
                Cell::from(proc.name.as_str()),
                Cell::from(proc.thread_count.to_string()),
                Cell::from(status),
            ])
        })
        .collect();

    let table = Table::new(rows)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("System Processes")
                .border_style(Style::default().fg(PRIMARY)),
        )
        .highlight_style(Style::default().bg(PRIMARY).fg(BACKGROUND))
        .widths(&[
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Min(20),
            Constraint::Length(8),
            Constraint::Length(15),
        ]);

    let mut state = app.processes_state.clone();
    f.render_stateful_widget(table, chunks[0], &mut state);

    // Process details panel
    draw_process_details(f, chunks[1], app);
}

fn draw_process_details(f: &mut Frame, area: Rect, app: &App) {
    let details = if let Some(ref process) = app.selected_process {
        format!(
            "PID: {}\nPPID: {}\nName: {}\nPath: {}\nThreads: {}",
            process.pid,
            process.ppid,
            process.name,
            process.path.as_deref().unwrap_or("Unknown"),
            process.thread_count
        )
    } else {
        "Select a process to view details".to_string()
    };

    let paragraph = Paragraph::new(details)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Process Details")
                .border_style(Style::default().fg(SECONDARY)),
        )
        .style(Style::default().fg(TEXT))
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

fn draw_detections(f: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
        .detections
        .iter()
        .map(|detection| {
            let level_style = match detection.threat_level {
                ThreatLevel::Malicious => Style::default().fg(DANGER),
                ThreatLevel::Suspicious => Style::default().fg(WARNING),
                ThreatLevel::Clean => Style::default().fg(SUCCESS),
            };

            let content = vec![
                Line::from(vec![
                    Span::styled(
                        format!("[{}] ", detection.timestamp.format("%Y-%m-%d %H:%M:%S")),
                        Style::default().fg(MUTED),
                    ),
                    Span::styled(
                        format!("{:?}", detection.threat_level),
                        level_style.add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(format!(
                    "Process: {} (PID: {})",
                    detection.process.name, detection.process.pid
                )),
                Line::from(format!("Confidence: {:.1}%", detection.confidence * 100.0)),
                Line::from("Indicators:"),
            ];

            let mut all_lines = content;
            for indicator in &detection.indicators {
                all_lines.push(Line::from(format!("  - {}", indicator)));
            }
            all_lines.push(Line::from(""));

            ListItem::new(Text::from(all_lines))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(
                    "Detection History ({} total)",
                    app.detections.len()
                ))
                .border_style(Style::default().fg(DANGER)),
        )
        .style(Style::default().fg(TEXT));

    let mut state = app.detections_state.clone();
    f.render_stateful_widget(list, area, &mut state);
}

fn draw_memory(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(area);

    let memory_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Memory Usage")
                .border_style(Style::default().fg(PRIMARY)),
        )
        .gauge_style(Style::default().fg(PRIMARY))
        .percent((app.stats.memory_usage_mb * 10.0) as u16)
        .label(format!("{:.2} MB", app.stats.memory_usage_mb));

    f.render_widget(memory_gauge, chunks[0]);

    let memory_info = Paragraph::new(
        "Memory Analysis:\n\n\
        - Process memory regions scanned\n\
        - RWX regions monitored\n\
        - Suspicious allocations detected\n\
        - Memory layout anomalies tracked\n\n\
        Advanced memory analysis features coming soon...",
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Memory Analysis")
            .border_style(Style::default().fg(SECONDARY)),
    )
    .style(Style::default().fg(TEXT))
    .wrap(Wrap { trim: true });

    f.render_widget(memory_info, chunks[1]);
}

fn draw_logs(f: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
        .logs
        .iter()
        .map(|log| ListItem::new(log.as_str()).style(Style::default().fg(TEXT)))
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("System Logs ({} entries)", app.logs.len()))
                .border_style(Style::default().fg(SUCCESS)),
        )
        .style(Style::default().fg(TEXT));

    let mut state = app.logs_state.clone();
    f.render_stateful_widget(list, area, &mut state);
}

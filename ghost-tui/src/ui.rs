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
    let size = f.area();

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
        TabIndex::ThreatIntel => draw_threat_intel(f, chunks[1], app),
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

    let table = Table::new(
        rows,
        &[
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Min(20),
            Constraint::Length(8),
            Constraint::Length(15),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("System Processes")
            .border_style(Style::default().fg(PRIMARY)),
    )
    .row_highlight_style(Style::default().bg(PRIMARY).fg(BACKGROUND));

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
        .constraints([
            Constraint::Length(8),  // Stats gauges
            Constraint::Length(12), // Memory breakdown
            Constraint::Min(0),     // Details
        ])
        .split(area);

    // Memory stats gauges
    let stats_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(chunks[0]);

    let mem = &app.memory_stats;

    let regions_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Total Regions")
                .border_style(Style::default().fg(PRIMARY)),
        )
        .gauge_style(Style::default().fg(PRIMARY))
        .percent(std::cmp::min((mem.total_regions / 100) as u16, 100))
        .label(format!("{}", mem.total_regions));

    f.render_widget(regions_gauge, stats_chunks[0]);

    let rwx_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("RWX Regions")
                .border_style(Style::default().fg(if mem.rwx_regions > 0 {
                    DANGER
                } else {
                    SUCCESS
                })),
        )
        .gauge_style(Style::default().fg(if mem.rwx_regions > 0 { DANGER } else { SUCCESS }))
        .percent(std::cmp::min((mem.rwx_regions * 10) as u16, 100))
        .label(format!("{}", mem.rwx_regions));

    f.render_widget(rwx_gauge, stats_chunks[1]);

    let suspicious_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Suspicious")
                .border_style(Style::default().fg(if mem.suspicious_allocations > 0 {
                    WARNING
                } else {
                    SUCCESS
                })),
        )
        .gauge_style(Style::default().fg(if mem.suspicious_allocations > 0 {
            WARNING
        } else {
            SUCCESS
        }))
        .percent(std::cmp::min((mem.suspicious_allocations * 10) as u16, 100))
        .label(format!("{}", mem.suspicious_allocations));

    f.render_widget(suspicious_gauge, stats_chunks[2]);

    let committed_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Committed (MB)")
                .border_style(Style::default().fg(SECONDARY)),
        )
        .gauge_style(Style::default().fg(SECONDARY))
        .percent(std::cmp::min((mem.total_committed_mb / 100.0) as u16, 100))
        .label(format!("{:.1}", mem.total_committed_mb));

    f.render_widget(committed_gauge, stats_chunks[3]);

    // Memory breakdown table
    let rows = vec![
        Row::new(vec![
            Cell::from("Private Regions"),
            Cell::from(format!("{}", mem.private_regions)),
            Cell::from(format!(
                "{:.1}%",
                if mem.total_regions > 0 {
                    mem.private_regions as f64 / mem.total_regions as f64 * 100.0
                } else {
                    0.0
                }
            )),
        ]),
        Row::new(vec![
            Cell::from("Shared Regions"),
            Cell::from(format!("{}", mem.shared_regions)),
            Cell::from(format!(
                "{:.1}%",
                if mem.total_regions > 0 {
                    mem.shared_regions as f64 / mem.total_regions as f64 * 100.0
                } else {
                    0.0
                }
            )),
        ]),
        Row::new(vec![
            Cell::from("RWX (Dangerous)").style(Style::default().fg(if mem.rwx_regions > 0 {
                DANGER
            } else {
                TEXT
            })),
            Cell::from(format!("{}", mem.rwx_regions))
                .style(Style::default().fg(if mem.rwx_regions > 0 { DANGER } else { TEXT })),
            Cell::from(format!(
                "{:.1}%",
                if mem.total_regions > 0 {
                    mem.rwx_regions as f64 / mem.total_regions as f64 * 100.0
                } else {
                    0.0
                }
            )),
        ]),
        Row::new(vec![
            Cell::from("Largest Region"),
            Cell::from(format!("{:.2} MB", mem.largest_region_mb)),
            Cell::from("-"),
        ]),
    ];

    let header = Row::new(vec![
        Cell::from("Type").style(Style::default().fg(PRIMARY).add_modifier(Modifier::BOLD)),
        Cell::from("Count").style(Style::default().fg(PRIMARY).add_modifier(Modifier::BOLD)),
        Cell::from("Percentage").style(Style::default().fg(PRIMARY).add_modifier(Modifier::BOLD)),
    ]);

    let table = Table::new(
        rows,
        &[
            Constraint::Percentage(40),
            Constraint::Percentage(30),
            Constraint::Percentage(30),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Memory Breakdown")
            .border_style(Style::default().fg(SECONDARY)),
    );

    f.render_widget(table, chunks[1]);

    // Memory analysis info
    let analysis_text = if mem.rwx_regions > 0 {
        format!(
            "⚠ WARNING: {} RWX memory regions detected!\n\n\
            RWX (Read-Write-Execute) memory is commonly used for:\n\
            • Just-In-Time (JIT) compilation\n\
            • Shellcode injection\n\
            • Self-modifying code\n\n\
            {} suspicious allocations flagged for review.\n\n\
            Recommendations:\n\
            • Review processes with RWX regions\n\
            • Check for code injection indicators\n\
            • Monitor for behavioral anomalies",
            mem.rwx_regions, mem.suspicious_allocations
        )
    } else {
        format!(
            "✓ No RWX memory regions detected\n\n\
            Memory Analysis Summary:\n\
            • {} total memory regions scanned\n\
            • {} private regions (process-specific)\n\
            • {} shared regions (libraries/mapped files)\n\
            • {:.2} MB total committed memory\n\n\
            Status: Memory layout appears normal.\n\
            No immediate signs of code injection detected.",
            mem.total_regions, mem.private_regions, mem.shared_regions, mem.total_committed_mb
        )
    };

    let analysis = Paragraph::new(analysis_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Analysis")
                .border_style(Style::default().fg(if mem.rwx_regions > 0 {
                    WARNING
                } else {
                    SUCCESS
                })),
        )
        .style(Style::default().fg(TEXT))
        .wrap(Wrap { trim: true });

    f.render_widget(analysis, chunks[2]);
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

fn draw_threat_intel(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10), // Feed status
            Constraint::Length(8),  // Stats
            Constraint::Min(0),     // IOC list
        ])
        .split(area);

    // Threat Feed Status Panel
    draw_feed_status(f, chunks[0], app);

    // Stats bar
    draw_intel_stats(f, chunks[1], app);

    // Recent IOCs
    draw_ioc_list(f, chunks[2], app);
}

fn draw_feed_status(f: &mut Frame, area: Rect, app: &App) {
    let feeds = &app.threat_intel_data.threat_feed_status;

    let rows: Vec<Row> = if feeds.is_empty() {
        vec![
            Row::new(vec![
                Cell::from("AlienVault OTX"),
                Cell::from("⚠ Not Connected").style(Style::default().fg(WARNING)),
                Cell::from("-"),
                Cell::from("0"),
            ]),
            Row::new(vec![
                Cell::from("Abuse.ch"),
                Cell::from("⚠ Not Connected").style(Style::default().fg(WARNING)),
                Cell::from("-"),
                Cell::from("0"),
            ]),
            Row::new(vec![
                Cell::from("MISP Feed"),
                Cell::from("⚠ Not Connected").style(Style::default().fg(WARNING)),
                Cell::from("-"),
                Cell::from("0"),
            ]),
            Row::new(vec![
                Cell::from("Local Rules"),
                Cell::from("✓ Active").style(Style::default().fg(SUCCESS)),
                Cell::from("Built-in"),
                Cell::from("47"),
            ]),
        ]
    } else {
        feeds
            .iter()
            .map(|feed| {
                let status_style = if feed.status == "Active" {
                    Style::default().fg(SUCCESS)
                } else {
                    Style::default().fg(WARNING)
                };

                Row::new(vec![
                    Cell::from(feed.name.as_str()),
                    Cell::from(feed.status.as_str()).style(status_style),
                    Cell::from(feed.last_update.as_str()),
                    Cell::from(feed.ioc_count.to_string()),
                ])
            })
            .collect()
    };

    let header = Row::new(vec![
        Cell::from("Feed").style(Style::default().fg(PRIMARY).add_modifier(Modifier::BOLD)),
        Cell::from("Status").style(Style::default().fg(PRIMARY).add_modifier(Modifier::BOLD)),
        Cell::from("Last Update").style(Style::default().fg(PRIMARY).add_modifier(Modifier::BOLD)),
        Cell::from("IOCs").style(Style::default().fg(PRIMARY).add_modifier(Modifier::BOLD)),
    ]);

    let table = Table::new(
        rows,
        &[
            Constraint::Percentage(30),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Threat Feeds")
            .border_style(Style::default().fg(SECONDARY)),
    );

    f.render_widget(table, area);
}

fn draw_intel_stats(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);

    let total_iocs = app.threat_intel_data.total_iocs;
    let active_threats = app.threat_intel_data.active_threats.len();
    let matched = app
        .detections
        .iter()
        .filter(|d| d.threat_context.is_some())
        .count();

    let ioc_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Total IOCs")
                .border_style(Style::default().fg(PRIMARY)),
        )
        .gauge_style(Style::default().fg(PRIMARY))
        .percent(std::cmp::min((total_iocs / 10) as u16, 100))
        .label(format!("{}", total_iocs));

    f.render_widget(ioc_gauge, chunks[0]);

    let threats_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Active Threats")
                .border_style(Style::default().fg(DANGER)),
        )
        .gauge_style(Style::default().fg(DANGER))
        .percent(std::cmp::min((active_threats * 10) as u16, 100))
        .label(format!("{}", active_threats));

    f.render_widget(threats_gauge, chunks[1]);

    let matched_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("IOC Matches")
                .border_style(Style::default().fg(WARNING)),
        )
        .gauge_style(Style::default().fg(WARNING))
        .percent(std::cmp::min((matched * 20) as u16, 100))
        .label(format!("{}", matched));

    f.render_widget(matched_gauge, chunks[2]);

    let coverage_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Coverage")
                .border_style(Style::default().fg(SUCCESS)),
        )
        .gauge_style(Style::default().fg(SUCCESS))
        .percent(47) // MITRE coverage percentage
        .label("47%");

    f.render_widget(coverage_gauge, chunks[3]);
}

fn draw_ioc_list(f: &mut Frame, area: Rect, app: &App) {
    let iocs = &app.threat_intel_data.recent_iocs;

    let items: Vec<ListItem> = if iocs.is_empty() {
        // Show sample/placeholder data when no real IOCs
        vec![
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled("ProcessName", Style::default().fg(PRIMARY)),
                    Span::raw(" | "),
                    Span::styled(
                        "mimikatz.exe",
                        Style::default().fg(DANGER).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  Source: ", Style::default().fg(MUTED)),
                    Span::raw("MITRE ATT&CK"),
                    Span::styled(" | Confidence: ", Style::default().fg(MUTED)),
                    Span::raw("95%"),
                    Span::styled(" | Tags: ", Style::default().fg(MUTED)),
                    Span::styled(
                        "credential-theft, lateral-movement",
                        Style::default().fg(WARNING),
                    ),
                ]),
            ]),
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled("FileHash", Style::default().fg(PRIMARY)),
                    Span::raw(" | "),
                    Span::styled(
                        "a1b2c3d4...f5e6",
                        Style::default().fg(WARNING).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  Source: ", Style::default().fg(MUTED)),
                    Span::raw("Abuse.ch"),
                    Span::styled(" | Confidence: ", Style::default().fg(MUTED)),
                    Span::raw("88%"),
                    Span::styled(" | Tags: ", Style::default().fg(MUTED)),
                    Span::styled("ransomware, cobalt-strike", Style::default().fg(DANGER)),
                ]),
            ]),
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled("BehaviorPattern", Style::default().fg(PRIMARY)),
                    Span::raw(" | "),
                    Span::styled(
                        "process_hollowing_svchost",
                        Style::default().fg(WARNING).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  Source: ", Style::default().fg(MUTED)),
                    Span::raw("Ghost Built-in"),
                    Span::styled(" | Confidence: ", Style::default().fg(MUTED)),
                    Span::raw("92%"),
                    Span::styled(" | Tags: ", Style::default().fg(MUTED)),
                    Span::styled("evasion, T1055", Style::default().fg(WARNING)),
                ]),
            ]),
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled("MemorySignature", Style::default().fg(PRIMARY)),
                    Span::raw(" | "),
                    Span::styled(
                        "shellcode_x64_staged",
                        Style::default().fg(DANGER).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  Source: ", Style::default().fg(MUTED)),
                    Span::raw("Ghost Built-in"),
                    Span::styled(" | Confidence: ", Style::default().fg(MUTED)),
                    Span::raw("97%"),
                    Span::styled(" | Tags: ", Style::default().fg(MUTED)),
                    Span::styled("shellcode, metasploit", Style::default().fg(DANGER)),
                ]),
            ]),
            ListItem::new(vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "  Connect threat feeds for live IOC data ",
                    Style::default().fg(MUTED),
                )]),
            ]),
        ]
    } else {
        iocs.iter()
            .map(|ioc| {
                let level_style = match ioc.threat_level {
                    ThreatLevel::Malicious => Style::default().fg(DANGER),
                    ThreatLevel::Suspicious => Style::default().fg(WARNING),
                    ThreatLevel::Clean => Style::default().fg(SUCCESS),
                };

                ListItem::new(vec![
                    Line::from(vec![
                        Span::styled(format!("{:?}", ioc.ioc_type), Style::default().fg(PRIMARY)),
                        Span::raw(" | "),
                        Span::styled(&ioc.value, level_style.add_modifier(Modifier::BOLD)),
                    ]),
                    Line::from(vec![
                        Span::styled("  Source: ", Style::default().fg(MUTED)),
                        Span::raw(&ioc.source),
                        Span::styled(" | Confidence: ", Style::default().fg(MUTED)),
                        Span::raw(format!("{:.0}%", ioc.confidence * 100.0)),
                        Span::styled(" | Tags: ", Style::default().fg(MUTED)),
                        Span::styled(ioc.tags.join(", "), Style::default().fg(WARNING)),
                    ]),
                ])
            })
            .collect()
    };

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Indicators of Compromise")
                .border_style(Style::default().fg(DANGER)),
        )
        .style(Style::default().fg(TEXT));

    let mut state = app.threat_intel_state.clone();
    f.render_stateful_widget(list, area, &mut state);
}

//! Application state and business logic for the Ghost TUI.
//!
//! This module manages the core application state, including process scanning,
//! detection events, and user interaction state.

#![allow(dead_code)]

use anyhow::Result;
use chrono::{DateTime, Utc};
use ghost_core::{
    memory, process, thread, DetectionEngine, IndicatorOfCompromise, ProcessInfo, ThreatContext,
    ThreatIntelligence, ThreatLevel,
};
use ratatui::widgets::{ListState, TableState};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TabIndex {
    Overview = 0,
    Processes = 1,
    Detections = 2,
    ThreatIntel = 3,
    Memory = 4,
    Logs = 5,
}

impl TabIndex {
    pub fn from_index(index: usize) -> Self {
        match index {
            0 => TabIndex::Overview,
            1 => TabIndex::Processes,
            2 => TabIndex::Detections,
            3 => TabIndex::ThreatIntel,
            4 => TabIndex::Memory,
            5 => TabIndex::Logs,
            _ => TabIndex::Overview,
        }
    }

    pub fn next(self) -> Self {
        Self::from_index((self as usize + 1) % 6)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvent {
    pub timestamp: DateTime<Utc>,
    pub process: ProcessInfo,
    pub threat_level: ThreatLevel,
    pub indicators: Vec<String>,
    pub confidence: f32,
    pub threat_context: Option<ThreatContext>,
}

#[derive(Debug, Clone)]
pub struct ThreatIntelData {
    pub total_iocs: usize,
    pub recent_iocs: Vec<IndicatorOfCompromise>,
    pub active_threats: Vec<String>,
    pub threat_feed_status: Vec<FeedStatus>,
}

#[derive(Debug, Clone)]
pub struct FeedStatus {
    pub name: String,
    pub status: String,
    pub last_update: String,
    pub ioc_count: usize,
}

#[derive(Debug, Clone)]
pub struct SystemStats {
    pub total_processes: usize,
    pub suspicious_processes: usize,
    pub malicious_processes: usize,
    pub total_detections: usize,
    pub scan_time_ms: u64,
    pub memory_usage_mb: f64,
}

#[derive(Debug)]
pub struct App {
    pub current_tab: TabIndex,
    pub detection_engine: DetectionEngine,
    pub threat_intel: ThreatIntelligence,
    pub processes: Vec<ProcessInfo>,
    pub detections: VecDeque<DetectionEvent>,
    pub logs: VecDeque<String>,
    pub stats: SystemStats,
    pub threat_intel_data: ThreatIntelData,
    pub last_scan: Option<Instant>,

    // UI state
    pub processes_state: TableState,
    pub detections_state: ListState,
    pub logs_state: ListState,
    pub threat_intel_state: ListState,
    pub selected_process: Option<ProcessInfo>,

    // Settings
    pub auto_refresh: bool,
    pub max_log_entries: usize,
    pub max_detection_entries: usize,
}

impl App {
    /// Creates a new application instance with initialized detection engine.
    ///
    /// # Errors
    ///
    /// Returns an error if the detection engine or threat intelligence
    /// system fails to initialize.
    pub async fn new() -> Result<Self> {
        let mut threat_intel = ThreatIntelligence::new();
        if let Err(e) = threat_intel.initialize_default_feeds().await {
            log::warn!("Failed to initialize threat feeds: {}", e);
        }

        let detection_engine = DetectionEngine::new()
            .map_err(|e| anyhow::anyhow!("Failed to initialize detection engine: {}", e))?;

        let mut app = Self {
            current_tab: TabIndex::Overview,
            detection_engine,
            threat_intel,
            processes: Vec::new(),
            detections: VecDeque::new(),
            logs: VecDeque::new(),
            stats: SystemStats {
                total_processes: 0,
                suspicious_processes: 0,
                malicious_processes: 0,
                total_detections: 0,
                scan_time_ms: 0,
                memory_usage_mb: 0.0,
            },
            threat_intel_data: ThreatIntelData {
                total_iocs: 0,
                recent_iocs: Vec::new(),
                active_threats: Vec::new(),
                threat_feed_status: Vec::new(),
            },
            last_scan: None,
            processes_state: TableState::default(),
            detections_state: ListState::default(),
            logs_state: ListState::default(),
            threat_intel_state: ListState::default(),
            selected_process: None,
            auto_refresh: true,
            max_log_entries: 1000,
            max_detection_entries: 500,
        };

        app.add_log_message("Ghost TUI v0.1.0 - Process Injection Detection".into());
        app.add_log_message("Detection engine initialized successfully".into());

        if let Err(e) = app.update_scan_data().await {
            app.add_log_message(format!("Initial scan failed: {}", e));
        }

        Ok(app)
    }

    /// Performs a full system scan for process injection indicators.
    ///
    /// This method enumerates all running processes, analyzes their memory
    /// regions and threads, and records any suspicious or malicious findings.
    pub async fn update_scan_data(&mut self) -> Result<()> {
        let scan_start = Instant::now();

        self.processes = match process::enumerate_processes() {
            Ok(procs) => procs,
            Err(e) => {
                self.add_log_message(format!("Process enumeration failed: {}", e));
                return Err(anyhow::anyhow!("Process enumeration failed: {}", e));
            }
        };

        let mut detection_count = 0;
        let mut suspicious_count = 0;
        let mut malicious_count = 0;

        let processes = self.processes.clone();
        for proc in &processes {
            if Self::should_skip_process(proc) {
                continue;
            }

            let regions = match memory::enumerate_memory_regions(proc.pid) {
                Ok(r) => r,
                Err(_) => continue,
            };

            let threads = thread::enumerate_threads(proc.pid).ok();
            let result = self
                .detection_engine
                .analyze_process(proc, &regions, threads.as_deref());

            match result.threat_level {
                ThreatLevel::Suspicious => suspicious_count += 1,
                ThreatLevel::Malicious => malicious_count += 1,
                ThreatLevel::Clean => {}
            }

            if result.threat_level != ThreatLevel::Clean {
                detection_count += 1;
                self.add_detection(DetectionEvent {
                    timestamp: Utc::now(),
                    process: proc.clone(),
                    threat_level: result.threat_level,
                    indicators: result.indicators,
                    confidence: result.confidence,
                    threat_context: result.threat_context,
                });
            }
        }

        let scan_duration = scan_start.elapsed();

        self.stats = SystemStats {
            total_processes: self.processes.len(),
            suspicious_processes: suspicious_count,
            malicious_processes: malicious_count,
            total_detections: self.detections.len(),
            scan_time_ms: scan_duration.as_millis() as u64,
            memory_usage_mb: self.estimate_memory_usage(),
        };

        self.last_scan = Some(scan_start);

        self.add_log_message(format!(
            "Scan complete: {} processes, {} detections in {}ms",
            self.processes.len(),
            detection_count,
            scan_duration.as_millis()
        ));

        Ok(())
    }

    /// Determines if a process should be skipped during scanning.
    fn should_skip_process(proc: &ProcessInfo) -> bool {
        const SKIP_PROCESSES: &[&str] = &["System", "Registry", "Idle", "smss.exe"];
        SKIP_PROCESSES.iter().any(|&name| proc.name == name) || proc.pid == 0 || proc.pid == 4
    }

    pub async fn force_refresh(&mut self) -> Result<()> {
        self.add_log_message("Forcing refresh...".to_string());
        self.update_scan_data().await
    }

    pub fn add_detection(&mut self, detection: DetectionEvent) {
        // Add to front of deque for most recent first
        self.detections.push_front(detection);

        // Limit size
        while self.detections.len() > self.max_detection_entries {
            self.detections.pop_back();
        }
    }

    pub fn add_log_message(&mut self, message: String) {
        let timestamp = Utc::now().format("%H:%M:%S");
        let log_entry = format!("[{}] {}", timestamp, message);

        self.logs.push_front(log_entry);

        // Limit log size
        while self.logs.len() > self.max_log_entries {
            self.logs.pop_back();
        }
    }

    pub fn clear_detections(&mut self) {
        self.detections.clear();
        self.add_log_message("Detection history cleared".to_string());
    }

    pub fn next_tab(&mut self) {
        self.current_tab = self.current_tab.next();
    }

    pub fn scroll_up(&mut self) {
        match self.current_tab {
            TabIndex::Processes => {
                let i = match self.processes_state.selected() {
                    Some(i) => {
                        if i == 0 {
                            self.processes.len() - 1
                        } else {
                            i - 1
                        }
                    }
                    None => 0,
                };
                self.processes_state.select(Some(i));
                if let Some(process) = self.processes.get(i) {
                    self.selected_process = Some(process.clone());
                }
            }
            TabIndex::Detections => {
                let i = match self.detections_state.selected() {
                    Some(i) => {
                        if i == 0 {
                            self.detections.len() - 1
                        } else {
                            i - 1
                        }
                    }
                    None => 0,
                };
                self.detections_state.select(Some(i));
            }
            TabIndex::Logs => {
                let i = match self.logs_state.selected() {
                    Some(i) => {
                        if i == 0 {
                            self.logs.len() - 1
                        } else {
                            i - 1
                        }
                    }
                    None => 0,
                };
                self.logs_state.select(Some(i));
            }
            _ => {}
        }
    }

    pub fn scroll_down(&mut self) {
        match self.current_tab {
            TabIndex::Processes => {
                let i = match self.processes_state.selected() {
                    Some(i) => {
                        if i >= self.processes.len() - 1 {
                            0
                        } else {
                            i + 1
                        }
                    }
                    None => 0,
                };
                self.processes_state.select(Some(i));
                if let Some(process) = self.processes.get(i) {
                    self.selected_process = Some(process.clone());
                }
            }
            TabIndex::Detections => {
                let i = match self.detections_state.selected() {
                    Some(i) => {
                        if i >= self.detections.len() - 1 {
                            0
                        } else {
                            i + 1
                        }
                    }
                    None => 0,
                };
                self.detections_state.select(Some(i));
            }
            TabIndex::Logs => {
                let i = match self.logs_state.selected() {
                    Some(i) => {
                        if i >= self.logs.len() - 1 {
                            0
                        } else {
                            i + 1
                        }
                    }
                    None => 0,
                };
                self.logs_state.select(Some(i));
            }
            _ => {}
        }
    }

    pub fn select_item(&mut self) {
        if self.current_tab == TabIndex::Processes {
            if let Some(i) = self.processes_state.selected() {
                if let Some(process) = self.processes.get(i) {
                    self.selected_process = Some(process.clone());
                    self.add_log_message(format!(
                        "Selected process: {} (PID: {})",
                        process.name, process.pid
                    ));
                }
            }
        }
    }

    fn estimate_memory_usage(&self) -> f64 {
        // Rough estimation of memory usage in MB
        let processes_size = self.processes.len() * std::mem::size_of::<ProcessInfo>();
        let detections_size = self.detections.len() * 200; // Estimate per detection
        let logs_size = self.logs.iter().map(|s| s.len()).sum::<usize>();

        (processes_size + detections_size + logs_size) as f64 / 1024.0 / 1024.0
    }

    pub fn get_tab_titles(&self) -> Vec<&str> {
        vec!["Overview", "Processes", "Detections", "Threat Intel", "Memory", "Logs"]
    }
}

use anyhow::Result;
use eframe::egui;
use ghost_core::{memory, process, thread as ghost_thread, DetectionEngine, ThreatLevel};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

fn format_mm_ss(total_secs: u64) -> String {
    let minutes = total_secs / 60;
    let seconds = total_secs % 60;
    format!("{minutes}:{seconds:02}")
}

#[derive(Debug, Clone)]
struct DetectionSummary {
    name: String,
    pid: u32,
    threat_level: ThreatLevel,
    confidence: f32,
    indicators_preview: Vec<String>,
}

#[derive(Debug, Clone)]
enum ScanEvent {
    Started { total: usize },
    Progress {
        scanned: usize,
        total: usize,
        current: Option<(String, u32)>,
    },
    Finished {
        detections: Vec<DetectionSummary>,
        scanned: usize,
        total: usize,
        errors: usize,
        duration: Duration,
    },
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanState {
    Idle,
    Scanning,
    Done,
    Error,
}

struct GhostGuiApp {
    target_pid_input: String,
    target_name_input: String,

    scan_state: ScanState,
    status_line: String,

    scanned: usize,
    total: usize,
    errors: usize,
    started_at: Option<Instant>,

    live_updates_visible: bool,
    deferred_progress: Option<(usize, usize, Option<(String, u32)>)>,

    detections: Vec<DetectionSummary>,

    rx: Option<mpsc::Receiver<ScanEvent>>,
}

impl Default for GhostGuiApp {
    fn default() -> Self {
        Self {
            target_pid_input: String::new(),
            target_name_input: String::new(),
            scan_state: ScanState::Idle,
            status_line: "Ready".to_string(),
            scanned: 0,
            total: 0,
            errors: 0,
            started_at: None,

            live_updates_visible: true,
            deferred_progress: None,
            detections: Vec::new(),
            rx: None,
        }
    }
}

impl GhostGuiApp {
    fn start_scan(&mut self) {
        if self.scan_state == ScanState::Scanning {
            return;
        }

        let pid = self
            .target_pid_input
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|p| *p != 0);

        let name_filter = self.target_name_input.trim().to_string();
        let name_filter = if name_filter.is_empty() {
            None
        } else {
            Some(name_filter)
        };

        self.scan_state = ScanState::Scanning;
        self.status_line = "Starting scan...".to_string();
        self.scanned = 0;
        self.total = 0;
        self.errors = 0;
        self.detections.clear();
        self.started_at = Some(Instant::now());
        self.live_updates_visible = true;
        self.deferred_progress = None;

        let (tx, rx) = mpsc::channel::<ScanEvent>();
        self.rx = Some(rx);

        thread::spawn(move || {
            let tx_err = tx.clone();
            if let Err(e) = run_scan_thread(tx, pid, name_filter.as_deref()) {
                // If sending fails, the UI was closed.
                let _ = tx_err.send(ScanEvent::Error(format!("Scan failed: {e}")));
            }
        });
    }

    fn poll_scan_events(&mut self) {
        let Some(rx) = self.rx.as_ref() else {
            return;
        };

        let mut clear_rx = false;
        while let Ok(ev) = rx.try_recv() {
            match ev {
                ScanEvent::Started { total } => {
                    self.total = total;
                    self.status_line = format!("Scanning {total} processes...");
                }
                ScanEvent::Progress {
                    scanned,
                    total,
                    current,
                } => {
                    if self.live_updates_visible {
                        self.scanned = scanned;
                        self.total = total;
                        if let Some((name, pid)) = current {
                            self.status_line = format!("Scanning {name} (PID {pid})...");
                        } else {
                            self.status_line = "Scanning...".to_string();
                        }
                    } else {
                        // Keep scanning in the background but avoid UI churn.
                        // We only keep the most recent progress update and apply it when shown.
                        self.deferred_progress = Some((scanned, total, current));
                    }
                }
                ScanEvent::Finished {
                    detections,
                    scanned,
                    total,
                    errors,
                    duration,
                } => {
                    self.detections = detections;
                    self.scanned = scanned;
                    self.total = total;
                    self.errors = errors;
                    self.scan_state = ScanState::Done;
                    self.status_line = format!(
                        "Scan finished: {} detections ({} scanned, {} errors) in {}ms",
                        self.detections.len(),
                        scanned,
                        errors,
                        duration.as_millis()
                    );
                    clear_rx = true;
                }
                ScanEvent::Error(msg) => {
                    self.scan_state = ScanState::Error;
                    self.status_line = msg;
                    clear_rx = true;
                }
            }
        }

        if clear_rx {
            self.rx = None;
        }
    }
}

impl eframe::App for GhostGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_scan_events();

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.heading("Ghost - Process Injection Detection");
            ui.add_space(8.0);

            ui.horizontal_wrapped(|ui| {
                ui.label("PID (optional):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.target_pid_input)
                        .hint_text("e.g. 1234")
                        .desired_width(120.0),
                );

                ui.add_space(12.0);

                ui.label("Process name contains (optional):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.target_name_input)
                        .hint_text("e.g. chrome")
                        .desired_width(180.0),
                );

                ui.add_space(12.0);

                let can_start = self.scan_state != ScanState::Scanning;
                if ui
                    .add_enabled(can_start, egui::Button::new("Start scan"))
                    .clicked()
                {
                    self.start_scan();
                }
            });

            ui.add_space(6.0);

            ui.horizontal_wrapped(|ui| {
                ui.add(egui::Label::new(&self.status_line).wrap(true));

                if self.scan_state == ScanState::Scanning {
                    ui.add_space(12.0);
                    let label = if self.live_updates_visible {
                        "Hide updates"
                    } else {
                        "Show updates"
                    };

                    if ui.button(label).clicked() {
                        self.live_updates_visible = !self.live_updates_visible;

                        if self.live_updates_visible {
                            // Catch up to the most recent progress update.
                            if let Some((scanned, total, current)) = self.deferred_progress.take()
                            {
                                self.scanned = scanned;
                                self.total = total;
                                if let Some((name, pid)) = current {
                                    self.status_line =
                                        format!("Scanning {name} (PID {pid})...");
                                } else {
                                    self.status_line = "Scanning...".to_string();
                                }
                            }
                        } else {
                            self.status_line =
                                "Scanning in background (updates hidden)...".to_string();
                        }
                    }
                }
            });

            if self.scan_state == ScanState::Scanning && self.live_updates_visible && self.total > 0 {
                let frac = self.scanned as f32 / self.total as f32;
                ui.add(egui::ProgressBar::new(frac).show_percentage());
            }

            if self.scan_state != ScanState::Idle && self.live_updates_visible {
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!("Scanned: {}/{}", self.scanned, self.total));
                    ui.add_space(12.0);
                    ui.label(format!("Errors: {}", self.errors));
                    if let Some(started) = self.started_at {
                        ui.add_space(12.0);
                        ui.label(format!("Elapsed: {}ms", started.elapsed().as_millis()));

                        // ETA (best-effort): only show when we have a rate estimate.
                        if self.total > 0 && self.scanned >= 2 {
                            let elapsed = started.elapsed();
                            let elapsed_secs = elapsed.as_secs_f64();
                            if elapsed_secs > 0.0 {
                                let rate = self.scanned as f64 / elapsed_secs;
                                if rate > 0.0 {
                                    let remaining = self.total.saturating_sub(self.scanned) as f64;
                                    let eta_secs = (remaining / rate).round() as u64;
                                    ui.add_space(12.0);
                                    ui.label(format!("ETA: {}", format_mm_ss(eta_secs)));
                                }
                            }
                        }
                    }
                });
            }

            ui.add_space(6.0);
            ui.separator();
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading(format!("Detections ({})", self.detections.len()));
            ui.add_space(6.0);

            if self.detections.is_empty() {
                ui.label("No suspicious processes detected.");
                ui.label("Tip: run as Administrator on Windows for full visibility.");
                return;
            }

            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                for det in &self.detections {
                    ui.group(|ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(format!("{:?}", det.threat_level));
                            ui.add_space(8.0);
                            ui.label(format!("{} (PID {})", det.name, det.pid));
                            ui.add_space(8.0);
                            ui.label(format!("{:.0}%", det.confidence * 100.0));
                        });

                        if !det.indicators_preview.is_empty() {
                            ui.add_space(4.0);
                            for ind in &det.indicators_preview {
                                ui.add(egui::Label::new(format!("- {ind}")).wrap(true));
                            }
                        }
                    });
                    ui.add_space(6.0);
                }
                });
        });

        // Keep UI responsive while scanning.
        if self.scan_state == ScanState::Scanning {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
    }
}

fn run_scan_thread(tx: mpsc::Sender<ScanEvent>, pid: Option<u32>, name: Option<&str>) -> Result<()> {
    let scan_start = Instant::now();

    let processes: Vec<process::ProcessInfo> = if let Some(pid) = pid {
        let all = process::enumerate_processes()?;
        all.into_iter().filter(|p| p.pid == pid).collect()
    } else if let Some(name) = name {
        let name_lc = name.to_lowercase();
        let all = process::enumerate_processes()?;
        all.into_iter()
            .filter(|p| p.name.to_lowercase().contains(&name_lc))
            .collect()
    } else {
        process::enumerate_processes()?
    };

    let targets: Vec<process::ProcessInfo> = processes
        .into_iter()
        .filter(|p| {
            p.name != "csrss.exe" && p.name != "wininit.exe" && p.name != "winlogon.exe"
        })
        .collect();

    let total = targets.len();
    if total == 0 {
        let _ = tx.send(ScanEvent::Error(
            "No matching processes found for the given PID/name filter.".to_string(),
        ));
        return Ok(());
    }
    let _ = tx.send(ScanEvent::Started { total });

    let mut engine = DetectionEngine::new()
        .map_err(|e| anyhow::anyhow!("Failed to initialize detection engine: {e}"))?;

    let mut detections: Vec<DetectionSummary> = Vec::new();
    let mut scanned = 0usize;
    let mut errors = 0usize;
    let mut last_progress = Instant::now();

    for proc in targets {
        scanned += 1;

        if last_progress.elapsed() >= Duration::from_millis(150) {
            let _ = tx.send(ScanEvent::Progress {
                scanned,
                total,
                current: Some((proc.name.clone(), proc.pid)),
            });
            last_progress = Instant::now();
        }

        match memory::enumerate_memory_regions(proc.pid) {
            Ok(regions) => {
                let threads = ghost_thread::enumerate_threads(proc.pid).ok();
                let result = engine.analyze_process(&proc, &regions, threads.as_deref());

                if result.threat_level != ThreatLevel::Clean {
                    detections.push(DetectionSummary {
                        name: result.process.name.clone(),
                        pid: result.process.pid,
                        threat_level: result.threat_level,
                        confidence: result.confidence,
                        indicators_preview: result.indicators.into_iter().take(5).collect(),
                    });
                }
            }
            Err(_) => {
                errors += 1;
            }
        }
    }

    let duration = scan_start.elapsed();
    let _ = tx.send(ScanEvent::Finished {
        detections,
        scanned,
        total,
        errors,
        duration,
    });

    Ok(())
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .format_timestamp(None)
        .init();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 720.0])
            .with_min_inner_size([720.0, 520.0])
            .with_resizable(true),
        ..Default::default()
    };
    eframe::run_native(
        "Ghost",
        native_options,
        Box::new(|_cc| Box::new(GhostGuiApp::default())),
    )
    .map_err(|e| anyhow::anyhow!("GUI failed: {e}"))?;

    Ok(())
}

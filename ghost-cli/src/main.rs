//! Ghost CLI - Process Injection Detection Framework
//!
//! A cross-platform command-line tool for detecting process injection,
//! process hollowing, and other malicious code injection techniques.

use anyhow::Result;
use clap::{Arg, Command, ValueHint};
use clap_complete::{generate, Shell};
use ghost_core::{
    memory, process, thread, Baseline, DetectionConfig, DetectionEngine, DetectionResult,
    OutputConfig, OutputFormatter, OutputVerbosity, ThreatLevel, WebhookConfig, WebhookNotifier,
    WebhookType,
};
use log::{debug, error, info};
use std::collections::HashSet;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;

/// Scan result containing detections and metadata
struct ScanResult {
    detections: Vec<DetectionResult>,
    processes: Vec<process::ProcessInfo>,
    scanned_count: usize,
    error_count: usize,
    duration: Duration,
}

/// Runs a single scan and returns results
fn run_scan(
    engine: &mut DetectionEngine,
    target_pid: Option<u32>,
    target_process: Option<&str>,
    quiet: bool,
    verbose: bool,
) -> Result<ScanResult> {
    let scan_start = Instant::now();

    let processes: Vec<process::ProcessInfo> = if let Some(pid) = target_pid {
        info!("Targeting specific process ID: {}", pid);
        let all_processes = process::enumerate_processes()?;
        all_processes.into_iter().filter(|p| p.pid == pid).collect()
    } else if let Some(name) = target_process {
        info!("Targeting processes with name: {}", name);
        let all_processes = process::enumerate_processes()?;
        all_processes
            .into_iter()
            .filter(|p| p.name.to_lowercase().contains(&name.to_lowercase()))
            .collect()
    } else {
        process::enumerate_processes()?
    };

    if !quiet {
        println!("Scanning {} processes...", processes.len());
    }

    let mut detections = Vec::new();
    let mut scanned_count = 0;
    let mut error_count = 0;

    for proc in &processes {
        // Skip known safe system processes
        if proc.name == "csrss.exe" || proc.name == "wininit.exe" || proc.name == "winlogon.exe" {
            continue;
        }

        scanned_count += 1;

        match memory::enumerate_memory_regions(proc.pid) {
            Ok(regions) => {
                let threads = thread::enumerate_threads(proc.pid).ok();
                let result = engine.analyze_process(proc, &regions, threads.as_deref());

                if result.threat_level != ThreatLevel::Clean {
                    detections.push(result);
                }
            }
            Err(e) => {
                error_count += 1;
                if verbose {
                    debug!("Failed to scan {} (PID: {}): {}", proc.name, proc.pid, e);
                }
            }
        }
    }

    let duration = scan_start.elapsed();
    Ok(ScanResult {
        detections,
        processes,
        scanned_count,
        error_count,
        duration,
    })
}

/// Formats and outputs scan results
fn output_results(
    detections: &[DetectionResult],
    scanned_count: usize,
    duration: Duration,
    formatter: &OutputFormatter,
    format: &str,
    output_file: Option<&str>,
    quiet: bool,
) -> Result<()> {
    let formatted =
        formatter.format_results(detections, scanned_count, duration.as_millis() as u64);

    let output_content = match format {
        "json" => {
            if formatted.summary.is_some() || !detections.is_empty() {
                formatter.to_json(&formatted)
            } else {
                serde_json::json!({
                    "status": "clean",
                    "message": "No suspicious activity detected",
                    "processes_scanned": scanned_count,
                    "scan_duration_ms": duration.as_millis()
                })
                .to_string()
            }
        }
        _ => formatter.to_table(&formatted),
    };

    if let Some(path) = output_file {
        use std::fs::File;
        let mut file = File::create(path)?;
        file.write_all(output_content.as_bytes())?;
        if !quiet {
            println!("Results written to {}", path);
        }
    } else if !quiet || !detections.is_empty() {
        print!("{}", output_content);
        io::stdout().flush()?;
    }

    Ok(())
}

/// Runs continuous monitoring mode
fn run_watch_mode(
    engine: &mut DetectionEngine,
    target_pid: Option<u32>,
    target_process: Option<&str>,
    interval_secs: u64,
    quiet: bool,
    verbose: bool,
    running: Arc<AtomicBool>,
    webhook: Option<&WebhookNotifier>,
    rt: &Runtime,
) -> Result<()> {
    let mut seen_detections: HashSet<(u32, String)> = HashSet::new();
    let mut scan_count = 0u64;

    if !quiet {
        println!("Starting watch mode (interval: {}s)", interval_secs);
        println!("Press Ctrl+C to stop\n");
    }

    while running.load(Ordering::SeqCst) {
        scan_count += 1;
        let timestamp = chrono::Local::now().format("%H:%M:%S");

        if !quiet {
            print!("[{}] Scan #{}: ", timestamp, scan_count);
            io::stdout().flush()?;
        }

        match run_scan(engine, target_pid, target_process, true, verbose) {
            Ok(result) => {
                // Filter to only new detections we haven't seen
                let new_detections: Vec<_> = result
                    .detections
                    .iter()
                    .filter(|d| {
                        let key = (d.process.pid, d.process.name.clone());
                        seen_detections.insert(key)
                    })
                    .collect();

                if !quiet {
                    if new_detections.is_empty() && result.detections.is_empty() {
                        println!(
                            "clean ({} processes, {}ms)",
                            result.scanned_count,
                            result.duration.as_millis()
                        );
                    } else if new_detections.is_empty() {
                        println!(
                            "{} known threats ({} processes, {}ms)",
                            result.detections.len(),
                            result.scanned_count,
                            result.duration.as_millis()
                        );
                    } else {
                        println!(
                            "{} NEW detections! ({} total, {} processes, {}ms)",
                            new_detections.len(),
                            result.detections.len(),
                            result.scanned_count,
                            result.duration.as_millis()
                        );
                    }
                }

                // Print details for new detections and send webhooks
                for detection in &new_detections {
                    let level = match detection.threat_level {
                        ThreatLevel::Malicious => "\x1b[31mMALICIOUS\x1b[0m",
                        ThreatLevel::Suspicious => "\x1b[33mSUSPICIOUS\x1b[0m",
                        ThreatLevel::Clean => "CLEAN",
                    };

                    println!(
                        "  [{}] {} (PID: {}) - {:.0}% confidence",
                        level,
                        detection.process.name,
                        detection.process.pid,
                        detection.confidence * 100.0
                    );

                    if verbose {
                        for indicator in detection.indicators.iter().take(3) {
                            println!("    - {}", indicator);
                        }
                        if detection.indicators.len() > 3 {
                            println!("    ... and {} more", detection.indicators.len() - 3);
                        }
                    }

                    // Send webhook notification for new detections
                    if let Some(notifier) = webhook {
                        let hostname = hostname::get()
                            .map(|h| h.to_string_lossy().to_string())
                            .unwrap_or_else(|_| "unknown".to_string());

                        if let Err(e) = rt.block_on(notifier.send_detection(detection, &hostname)) {
                            debug!("Failed to send webhook: {}", e);
                        }
                    }
                }

                if result.error_count > 0 && verbose {
                    debug!("{} processes couldn't be scanned", result.error_count);
                }
            }
            Err(e) => {
                if !quiet {
                    println!("error: {}", e);
                }
            }
        }

        // Wait for next interval, checking for shutdown every 100ms
        let wait_until = Instant::now() + Duration::from_secs(interval_secs);
        while Instant::now() < wait_until && running.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    if !quiet {
        println!("\nWatch mode stopped. {} scans completed.", scan_count);
    }

    Ok(())
}

/// Builds the CLI command structure
fn build_cli() -> Command {
    Command::new("ghost")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Cross-Platform Process Injection Detection Framework")
        .long_about(
            "Ghost scans running processes for signs of code injection, \
             process hollowing, and other malicious techniques.\n\n\
             Exit Codes:\n\
             0 - No suspicious activity detected\n\
             1 - Suspicious processes found\n\
             2 - Error occurred during scanning",
        )
        .subcommand(
            Command::new("completions")
                .about("Generate shell completions")
                .arg(
                    Arg::new("shell")
                        .required(true)
                        .value_parser(["bash", "zsh", "fish", "powershell", "elvish"])
                        .help("Shell to generate completions for"),
                ),
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_name("FORMAT")
                .help("Output format")
                .default_value("table")
                .value_parser(["table", "json", "csv"]),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Show more details")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("pid")
                .short('p')
                .long("pid")
                .value_name("PID")
                .help("Scan specific process ID"),
        )
        .arg(
            Arg::new("process")
                .long("process")
                .value_name("NAME")
                .help("Scan processes matching name"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .value_hint(ValueHint::FilePath)
                .help("Write results to file"),
        )
        .arg(
            Arg::new("debug")
                .short('d')
                .long("debug")
                .action(clap::ArgAction::SetTrue)
                .help("Enable debug logging"),
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .action(clap::ArgAction::SetTrue)
                .help("Minimal output"),
        )
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .value_hint(ValueHint::FilePath)
                .help("Load config from file"),
        )
        .arg(
            Arg::new("watch")
                .short('w')
                .long("watch")
                .action(clap::ArgAction::SetTrue)
                .help("Continuous monitoring mode"),
        )
        .arg(
            Arg::new("interval")
                .short('i')
                .long("interval")
                .value_name("SECONDS")
                .help("Scan interval for watch mode (default: 5)")
                .default_value("5")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("mitre-stats")
                .long("mitre-stats")
                .action(clap::ArgAction::SetTrue)
                .help("Show MITRE ATT&CK coverage"),
        )
        .arg(
            Arg::new("summary")
                .long("summary")
                .action(clap::ArgAction::SetTrue)
                .help("Summary output only"),
        )
        .arg(
            Arg::new("max-indicators")
                .long("max-indicators")
                .value_name("COUNT")
                .help("Max indicators per detection (default: 10)")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new("min-threat-level")
                .long("min-threat-level")
                .value_name("LEVEL")
                .help("Minimum threat level to report")
                .value_parser(["clean", "suspicious", "malicious"]),
        )
        .arg(
            Arg::new("save-baseline")
                .long("save-baseline")
                .value_name("FILE")
                .value_hint(ValueHint::FilePath)
                .help("Save current state as baseline"),
        )
        .arg(
            Arg::new("baseline")
                .short('b')
                .long("baseline")
                .value_name("FILE")
                .value_hint(ValueHint::FilePath)
                .help("Compare against baseline file"),
        )
        .arg(
            Arg::new("webhook")
                .long("webhook")
                .value_name("URL")
                .help("Send alerts to webhook URL (Slack/Discord/HTTP)"),
        )
        .arg(
            Arg::new("webhook-type")
                .long("webhook-type")
                .value_name("TYPE")
                .help("Webhook type (auto-detected if not specified)")
                .value_parser(["slack", "discord", "generic"]),
        )
}

fn main() -> Result<()> {
    let matches = build_cli().get_matches();

    // Handle completions subcommand
    if let Some(sub) = matches.subcommand_matches("completions") {
        let shell = sub.get_one::<String>("shell").unwrap();
        let shell = match shell.as_str() {
            "bash" => Shell::Bash,
            "zsh" => Shell::Zsh,
            "fish" => Shell::Fish,
            "powershell" => Shell::PowerShell,
            "elvish" => Shell::Elvish,
            _ => unreachable!(),
        };
        let mut cmd = build_cli();
        generate(shell, &mut cmd, "ghost", &mut io::stdout());
        return Ok(());
    }

    // Parse flags
    let debug_mode = matches.get_flag("debug");
    let quiet = matches.get_flag("quiet");
    let verbose = matches.get_flag("verbose");
    let watch_mode = matches.get_flag("watch");
    let summary_mode = matches.get_flag("summary");
    let mitre_stats = matches.get_flag("mitre-stats");

    let format = matches.get_one::<String>("format").unwrap();
    let interval = *matches.get_one::<u64>("interval").unwrap();
    let target_pid = matches
        .get_one::<String>("pid")
        .map(|s| s.parse::<u32>())
        .transpose()?;
    let target_process = matches.get_one::<String>("process").cloned();
    let output_file = matches.get_one::<String>("output").map(|s| s.as_str());
    let config_file = matches.get_one::<String>("config");
    let max_indicators = matches.get_one::<usize>("max-indicators").copied();
    let min_threat_level = matches.get_one::<String>("min-threat-level").cloned();
    let save_baseline = matches.get_one::<String>("save-baseline").cloned();
    let baseline_file = matches.get_one::<String>("baseline").cloned();
    let webhook_url = matches.get_one::<String>("webhook").cloned();
    let webhook_type_str = matches.get_one::<String>("webhook-type").cloned();

    // Set up logging
    let log_level = if debug_mode {
        log::LevelFilter::Debug
    } else if quiet {
        log::LevelFilter::Error
    } else {
        log::LevelFilter::Info
    };

    env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .format_timestamp(None)
        .init();

    // Build output config
    let output_config = OutputConfig {
        verbosity: if verbose {
            OutputVerbosity::Verbose
        } else if quiet || summary_mode {
            OutputVerbosity::Minimal
        } else {
            OutputVerbosity::Normal
        },
        max_indicators_per_detection: max_indicators.unwrap_or(10),
        min_threat_level,
        deduplicate_indicators: true,
        summary_mode,
        max_output_size: 0,
    };

    // Load or create config
    let config = if let Some(path) = config_file {
        match DetectionConfig::load(path) {
            Ok(mut cfg) => {
                cfg.output = output_config.clone();
                cfg
            }
            Err(e) => {
                eprintln!("Failed to load config: {}", e);
                return Err(e.into());
            }
        }
    } else {
        DetectionConfig {
            output: output_config.clone(),
            ..DetectionConfig::default()
        }
    };

    // Print banner
    if !quiet {
        println!(
            "Ghost v{} - Process Injection Detection\n",
            env!("CARGO_PKG_VERSION")
        );
    }

    // Initialize engine
    let mut engine = DetectionEngine::with_config(Some(config)).map_err(|e| {
        error!("Failed to initialize: {}", e);
        anyhow::anyhow!("{}", e)
    })?;

    // Show MITRE stats if requested
    if mitre_stats {
        let (techniques, tactics, actors) = engine.get_mitre_stats();
        println!("MITRE ATT&CK Coverage:");
        println!("  Techniques: {}", techniques);
        println!("  Tactics: {}", tactics);
        println!("  Threat Actors: {}", actors);
        println!();

        if !watch_mode && target_pid.is_none() && target_process.is_none() {
            return Ok(());
        }
    }

    let formatter = OutputFormatter::new(output_config);

    // Set up webhook notifier if configured
    let webhook_notifier = webhook_url.map(|url| {
        let webhook_type = match webhook_type_str.as_deref() {
            Some("slack") => WebhookType::Slack,
            Some("discord") => WebhookType::Discord,
            Some("generic") => WebhookType::Generic,
            _ => {
                // Auto-detect from URL
                if url.contains("hooks.slack.com") {
                    WebhookType::Slack
                } else if url.contains("discord.com/api/webhooks") {
                    WebhookType::Discord
                } else {
                    WebhookType::Generic
                }
            }
        };

        if !quiet {
            println!(
                "Webhook notifications enabled ({:?} -> {}...)\n",
                webhook_type,
                &url[..url.len().min(50)]
            );
        }

        let config = WebhookConfig::new(url, webhook_type);
        WebhookNotifier::new(config)
    });

    // Create tokio runtime for async webhook calls
    let rt = Runtime::new().expect("Failed to create tokio runtime");

    // Watch mode or single scan
    if watch_mode {
        // Set up Ctrl+C handler
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })?;

        run_watch_mode(
            &mut engine,
            target_pid,
            target_process.as_deref(),
            interval,
            quiet,
            verbose,
            running,
            webhook_notifier.as_ref(),
            &rt,
        )?;

        Ok(())
    } else {
        // Single scan
        let result = run_scan(
            &mut engine,
            target_pid,
            target_process.as_deref(),
            quiet,
            verbose,
        )?;

        info!(
            "Scan complete: {} processes, {} detections, {}ms",
            result.scanned_count,
            result.detections.len(),
            result.duration.as_millis()
        );

        // Send webhook notifications for detections
        if let Some(ref notifier) = webhook_notifier {
            let hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string());

            for detection in &result.detections {
                if let Err(e) = rt.block_on(notifier.send_detection(detection, &hostname)) {
                    debug!("Failed to send webhook: {}", e);
                }
            }
        }

        // Save baseline if requested
        if let Some(ref path) = save_baseline {
            let baseline = Baseline::from_detections(&result.detections, &result.processes);
            baseline.save(path)?;
            if !quiet {
                println!("Baseline saved to {}", path);
                println!(
                    "  {} processes, {} detections recorded",
                    result.processes.len(),
                    result.detections.len()
                );
            }
        }

        // Compare against baseline if provided
        if let Some(ref path) = baseline_file {
            let baseline = Baseline::load(path)?;
            let diff = baseline.compare(&result.detections, &result.processes);

            if diff.has_changes() {
                println!(
                    "\n\x1b[31m{} changes from baseline:\x1b[0m",
                    diff.total_changes()
                );

                if !diff.new_processes.is_empty() {
                    println!("\n  New threats ({}):", diff.new_processes.len());
                    for det in &diff.new_processes {
                        println!(
                            "    {} (PID: {}) - {:?}",
                            det.process.name, det.process.pid, det.threat_level
                        );
                    }
                }

                if !diff.escalated.is_empty() {
                    println!("\n  Escalated threats ({}):", diff.escalated.len());
                    for esc in &diff.escalated {
                        println!(
                            "    {} (PID: {}): {:?} -> {:?}",
                            esc.process.name,
                            esc.process.pid,
                            esc.baseline_level,
                            esc.current_level
                        );
                    }
                }

                if !diff.new_indicators.is_empty() {
                    println!("\n  New indicators ({}):", diff.new_indicators.len());
                    for ni in &diff.new_indicators {
                        println!("    {} (PID: {}):", ni.process.name, ni.process.pid);
                        for ind in ni.new_indicators.iter().take(3) {
                            println!("      - {}", ind);
                        }
                    }
                }
            } else if !quiet {
                println!("\x1b[32mNo changes from baseline\x1b[0m");
            }
        }

        // Normal output (skip if baseline comparison was the main purpose)
        if baseline_file.is_none() || save_baseline.is_some() {
            output_results(
                &result.detections,
                result.scanned_count,
                result.duration,
                &formatter,
                format,
                output_file,
                quiet,
            )?;
        }

        // Exit code
        let code = if result.error_count > 0 {
            2
        } else if baseline_file.is_some() {
            // When comparing baseline, exit 1 if changes detected
            let baseline = Baseline::load(baseline_file.as_ref().unwrap())?;
            let diff = baseline.compare(&result.detections, &result.processes);
            if diff.has_changes() {
                1
            } else {
                0
            }
        } else if !result.detections.is_empty() {
            1
        } else {
            0
        };

        std::process::exit(code);
    }
}

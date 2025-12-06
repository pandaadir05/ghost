//! Ghost CLI - Process Injection Detection Framework
//!
//! A cross-platform command-line tool for detecting process injection,
//! process hollowing, and other malicious code injection techniques.

use anyhow::Result;
use clap::{Arg, Command};
use ghost_core::{
    memory, process, thread, DetectionConfig, DetectionEngine, OutputConfig, OutputFormatter,
    OutputVerbosity, ThreatLevel,
};
use log::{debug, error, info, warn};
use std::time::Instant;

fn main() -> Result<()> {
    let matches = Command::new("ghost")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Cross-Platform Process Injection Detection Framework")
        .long_about(
            "Ghost scans running processes for signs of code injection, \
                     process hollowing, and other malicious techniques. \
                     Supports Windows and Linux platforms with kernel-level monitoring.\n\n\
                     Exit Codes:\n\
                     0 - No suspicious activity detected\n\
                     1 - Suspicious processes found\n\
                     2 - Error occurred during scanning",
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_name("FORMAT")
                .help("Output format: table, json")
                .default_value("table")
                .value_parser(["table", "json", "csv"]),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("pid")
                .short('p')
                .long("pid")
                .value_name("PID")
                .help("Target specific process ID"),
        )
        .arg(
            Arg::new("process")
                .long("process")
                .value_name("NAME")
                .help("Target specific process name"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Write output to file instead of stdout"),
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
                .help("Suppress all output except errors"),
        )
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Load configuration from file"),
        )
        .arg(
            Arg::new("mitre-analysis")
                .long("mitre-analysis")
                .action(clap::ArgAction::SetTrue)
                .help("Enable MITRE ATT&CK framework analysis"),
        )
        .arg(
            Arg::new("mitre-stats")
                .long("mitre-stats")
                .action(clap::ArgAction::SetTrue)
                .help("Show MITRE ATT&CK framework statistics"),
        )
        .arg(
            Arg::new("summary")
                .long("summary")
                .action(clap::ArgAction::SetTrue)
                .help("Output summary statistics only (reduces output size significantly)"),
        )
        .arg(
            Arg::new("max-indicators")
                .long("max-indicators")
                .value_name("COUNT")
                .help("Maximum indicators per detection (default: 10, 0 = unlimited)")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new("min-threat-level")
                .long("min-threat-level")
                .value_name("LEVEL")
                .help("Minimum threat level to report: clean, suspicious, malicious")
                .value_parser(["clean", "suspicious", "malicious"]),
        )
        .get_matches();

    let debug_mode = matches.get_flag("debug");
    let quiet = matches.get_flag("quiet");

    // Initialize logging based on flags
    let log_level = if debug_mode {
        log::LevelFilter::Debug
    } else if quiet {
        log::LevelFilter::Error
    } else {
        log::LevelFilter::Info
    };

    env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .init();

    if debug_mode {
        debug!("Debug logging enabled");
    }

    let format = matches
        .get_one::<String>("format")
        .expect("format has default value");
    let verbose = matches.get_flag("verbose");
    let target_pid = matches.get_one::<String>("pid");
    let target_process = matches.get_one::<String>("process");
    let output_file = matches.get_one::<String>("output");
    let config_file = matches.get_one::<String>("config");
    let _mitre_analysis = matches.get_flag("mitre-analysis");
    let mitre_stats = matches.get_flag("mitre-stats");
    let summary_mode = matches.get_flag("summary");
    let max_indicators = matches.get_one::<usize>("max-indicators").copied();
    let min_threat_level = matches.get_one::<String>("min-threat-level").cloned();

    // Build output configuration from CLI flags
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

    // Load configuration if specified, applying CLI output config
    let config = if let Some(config_path) = config_file {
        info!("Loading configuration from: {}", config_path);
        match DetectionConfig::load(config_path) {
            Ok(mut cfg) => {
                debug!("Configuration loaded successfully");
                // CLI flags override config file for output settings
                cfg.output = output_config.clone();
                Some(cfg)
            }
            Err(e) => {
                error!("Failed to load configuration from {}: {}", config_path, e);
                if !quiet {
                    eprintln!("Error: Failed to load configuration: {}", e);
                }
                return Err(e.into());
            }
        }
    } else {
        // Create default config with CLI output settings
        Some(DetectionConfig {
            output: output_config.clone(),
            ..DetectionConfig::default()
        })
    };

    info!("Starting Ghost process injection detection");
    debug!("Configuration - Format: {}, Verbose: {}, Quiet: {}, Summary: {}, Target PID: {:?}, Target Process: {:?}", 
           format, verbose, quiet, summary_mode, target_pid, target_process);

    if !quiet {
        println!(
            "Ghost v{} - Process Injection Detection\n",
            env!("CARGO_PKG_VERSION")
        );
    }

    let scan_start = Instant::now();
    let mut engine = DetectionEngine::with_config(config).map_err(|e| {
        error!("Failed to initialize detection engine: {}", e);
        anyhow::anyhow!("Detection engine initialization failed: {}", e)
    })?;

    // Display MITRE ATT&CK statistics if requested
    if mitre_stats {
        if !quiet {
            println!("MITRE ATT&CK Framework Statistics:");
            println!("==================================");
        }

        let (techniques, tactics, actors) = engine.get_mitre_stats();
        if !quiet {
            println!("Techniques: {}", techniques);
            println!("Tactics: {}", tactics);
            println!("Threat Actors: {}", actors);
            println!("Matrix Version: 13.1");
            println!("Framework Coverage:");
            println!("  - Process Injection (T1055)");
            println!("  - Process Hollowing (T1055.012)");
            println!("  - Defense Evasion (TA0004)");
            println!("  - Privilege Escalation (TA0005)");
            println!("  - APT29 (Cozy Bear)");
            println!();
        }

        // If only showing stats, exit here
        if mitre_stats && target_pid.is_none() && target_process.is_none() {
            return Ok(());
        }
    }

    let processes = if let Some(pid_str) = target_pid {
        let pid: u32 = pid_str.parse().map_err(|e| {
            error!("Invalid PID format '{}': {}", pid_str, e);
            anyhow::anyhow!("Invalid PID format: {}", pid_str)
        })?;
        info!("Targeting specific process ID: {}", pid);

        let all_processes = process::enumerate_processes()?;
        let filtered: Vec<_> = all_processes.into_iter().filter(|p| p.pid == pid).collect();

        if filtered.is_empty() {
            warn!("No process found with PID {}", pid);
            if !quiet {
                println!("Warning: No process found with PID {}", pid);
            }
        } else {
            debug!("Found target process: {}", filtered[0].name);
        }
        filtered
    } else if let Some(process_name) = target_process {
        info!("Targeting processes with name: {}", process_name);
        let all_processes = process::enumerate_processes()?;
        let filtered: Vec<_> = all_processes
            .into_iter()
            .filter(|p| p.name.to_lowercase().contains(&process_name.to_lowercase()))
            .collect();

        if filtered.is_empty() {
            warn!("No processes found matching name: {}", process_name);
            if !quiet {
                println!(
                    "Warning: No processes found matching name: {}",
                    process_name
                );
            }
        } else {
            info!(
                "Found {} processes matching name: {}",
                filtered.len(),
                process_name
            );
            debug!(
                "Matching processes: {:?}",
                filtered
                    .iter()
                    .map(|p| format!("{} ({})", p.name, p.pid))
                    .collect::<Vec<_>>()
            );
        }
        filtered
    } else {
        let all_processes = process::enumerate_processes()?;
        info!(
            "Enumerating all processes, found {} total",
            all_processes.len()
        );
        all_processes
    };

    if !quiet {
        println!("Scanning {} processes...\n", processes.len());
    }

    let mut detections = Vec::new();
    let mut scanned_count = 0;
    let mut error_count = 0;

    for proc in &processes {
        // Skip known safe system processes for performance
        if proc.name == "csrss.exe" || proc.name == "wininit.exe" || proc.name == "winlogon.exe" {
            debug!("Skipping safe system process: {}", proc.name);
            continue;
        }

        scanned_count += 1;
        debug!("Scanning process: {} (PID: {})", proc.name, proc.pid);

        match memory::enumerate_memory_regions(proc.pid) {
            Ok(regions) => {
                debug!(
                    "Found {} memory regions for process {}",
                    regions.len(),
                    proc.name
                );
                // Get thread information if available
                let threads = thread::enumerate_threads(proc.pid).ok();
                let result = engine.analyze_process(proc, &regions, threads.as_deref());

                if result.threat_level != ThreatLevel::Clean {
                    warn!(
                        "Suspicious activity detected in process {} (PID: {})",
                        proc.name, proc.pid
                    );
                    detections.push(result);
                } else {
                    debug!("Process {} (PID: {}) is clean", proc.name, proc.pid);
                }
            }
            Err(e) => {
                error_count += 1;
                error!(
                    "Failed to scan process {} (PID: {}): {}",
                    proc.name, proc.pid, e
                );
                if verbose && !quiet {
                    println!(
                        "Warning: Could not scan process {} (PID: {})",
                        proc.name, proc.pid
                    );
                }
            }
        }
    }

    if verbose && error_count > 0 && !quiet {
        warn!("Scan completed with {} access errors", error_count);
    }

    let scan_duration = scan_start.elapsed();

    info!(
        "Scan completed: {} processes scanned, {} suspicious processes found in {}ms",
        scanned_count,
        detections.len(),
        scan_duration.as_millis()
    );

    // Format output using OutputFormatter
    let formatter = OutputFormatter::new(output_config);
    let formatted =
        formatter.format_results(&detections, scanned_count, scan_duration.as_millis() as u64);

    let output_content = match format.as_str() {
        "json" => {
            if formatted.summary.is_some() || !detections.is_empty() {
                formatter.to_json(&formatted)
            } else {
                serde_json::json!({
                    "status": "clean",
                    "message": "No suspicious activity detected",
                    "processes_scanned": scanned_count,
                    "scan_duration_ms": scan_duration.as_millis()
                })
                .to_string()
            }
        }
        _ => formatter.to_table(&formatted),
    };

    if let Some(output_path) = output_file {
        use std::fs::File;
        use std::io::Write;

        info!("Writing results to file: {}", output_path);
        let mut file = File::create(output_path)?;
        file.write_all(output_content.as_bytes())?;
        if !quiet {
            println!("Results written to {}", output_path);
            if formatted.truncated {
                println!("Note: Output was truncated due to size limits");
            }
        }
    } else {
        debug!("Writing results to stdout");
        if !quiet || !detections.is_empty() {
            print!("{}", output_content);
        }
    }

    // Exit with appropriate code for automation
    let exit_code = if error_count > 0 {
        2 // Error occurred during scanning
    } else if !detections.is_empty() {
        1 // Suspicious processes found
    } else {
        0 // Clean scan
    };

    debug!("Exiting with code: {}", exit_code);
    std::process::exit(exit_code);
}

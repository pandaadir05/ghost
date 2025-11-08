use anyhow::Result;
use clap::{Arg, Command};
use ghost_core::{memory, process, thread, DetectionEngine, DetectionConfig, ThreatLevel};
use log::{debug, error, info, warn};
use serde_json;
use std::time::Instant;

fn main() -> Result<()> {
    env_logger::init();

    let matches = Command::new("ghost")
        .version("0.1.0")
        .about("Cross-Platform Process Injection Detection Framework")
        .long_about("Ghost scans running processes for signs of code injection, \
                     process hollowing, and other malicious techniques. \
                     Supports Windows and Linux platforms with kernel-level monitoring.")
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_name("FORMAT")
                .help("Output format: table, json")
                .default_value("table")
                .value_parser(["table", "json", "csv"])
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("pid")
                .short('p')
                .long("pid")
                .value_name("PID")
                .help("Target specific process ID")
        )
        .arg(
            Arg::new("process")
                .long("process")
                .value_name("NAME")
                .help("Target specific process name")
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
        .get_matches();

    // Initialize logging based on debug flag
    if matches.get_flag("debug") {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
        debug!("Debug logging enabled");
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    let format = matches.get_one::<String>("format").unwrap();
    let verbose = matches.get_flag("verbose");
    let quiet = matches.get_flag("quiet");
    let target_pid = matches.get_one::<String>("pid");
    let target_process = matches.get_one::<String>("process");
    let output_file = matches.get_one::<String>("output");
    let config_file = matches.get_one::<String>("config");

    // Load configuration if specified
    let config = if let Some(config_path) = config_file {
        info!("Loading configuration from: {}", config_path);
        match DetectionConfig::load(config_path) {
            Ok(cfg) => {
                debug!("Configuration loaded successfully");
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
        None
    };

    info!("Starting Ghost process injection detection");
    debug!("Configuration - Format: {}, Verbose: {}, Quiet: {}, Target PID: {:?}, Target Process: {:?}, Config: {:?}", 
           format, verbose, quiet, target_pid, target_process, config_file);

    if !quiet {
        println!("Ghost v0.1.0 - Process Injection Detection\n");
    }

    let scan_start = Instant::now();
    let mut engine = DetectionEngine::with_config(config).map_err(|e| {
        error!("Failed to initialize detection engine: {}", e);
        anyhow::anyhow!("Detection engine initialization failed: {}", e)
    })?;
    
    let processes = if let Some(pid_str) = target_pid {
        let pid: u32 = pid_str.parse().map_err(|e| {
            error!("Invalid PID format '{}': {}", pid_str, e);
            anyhow::anyhow!("Invalid PID format: {}", pid_str)
        })?;
        info!("Targeting specific process ID: {}", pid);
        
        let all_processes = process::enumerate_processes()?;
        let filtered: Vec<_> = all_processes
            .into_iter()
            .filter(|p| p.pid == pid)
            .collect();
        
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
                println!("Warning: No processes found matching name: {}", process_name);
            }
        } else {
            info!("Found {} processes matching name: {}", filtered.len(), process_name);
            debug!("Matching processes: {:?}", filtered.iter().map(|p| format!("{} ({})", p.name, p.pid)).collect::<Vec<_>>());
        }
        filtered
    } else {
        let all_processes = process::enumerate_processes()?;
        info!("Enumerating all processes, found {} total", all_processes.len());
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
                debug!("Found {} memory regions for process {}", regions.len(), proc.name);
                // Get thread information if available
                let threads = thread::enumerate_threads(proc.pid).ok();
                let result = engine.analyze_process(proc, &regions, threads.as_deref());

                if result.threat_level != ThreatLevel::Clean {
                    warn!("Suspicious activity detected in process {} (PID: {})", proc.name, proc.pid);
                    detections.push(result);
                } else {
                    debug!("Process {} (PID: {}) is clean", proc.name, proc.pid);
                }
            }
            Err(e) => {
                error_count += 1;
                error!("Failed to scan process {} (PID: {}): {}", proc.name, proc.pid, e);
                if verbose && !quiet {
                    println!("Warning: Could not scan process {} (PID: {})", proc.name, proc.pid);
                }
            }
        }
    }

    if verbose && error_count > 0 && !quiet {
        warn!("Scan completed with {} access errors", error_count);
        println!("Scan completed with {} access errors", error_count);
    }

    info!("Scan completed: {} processes scanned, {} suspicious processes found", scanned_count, detections.len());

    // Handle output
    let output_content = match format.as_str() {
        "json" => {
            if detections.is_empty() {
                serde_json::json!({
                    "status": "clean",
                    "message": "No suspicious activity detected",
                    "detections": []
                }).to_string()
            } else {
                serde_json::json!({
                    "status": "suspicious", 
                    "message": format!("Found {} suspicious processes", detections.len()),
                    "detections": &detections
                }).to_string()
            }
        }
        _ => {
            // Default table format
            if detections.is_empty() {
                "No suspicious activity detected.".to_string()
            } else {
                let mut content = format!("Found {} suspicious processes:\n\n", detections.len());

                for detection in &detections {
                    let level_str = match detection.threat_level {
                        ThreatLevel::Suspicious => "SUSPICIOUS",
                        ThreatLevel::Malicious => "MALICIOUS",
                        _ => "CLEAN",
                    };

                    content.push_str(&format!(
                        "[{}] {} (PID: {}) - Confidence: {:.1}%\n",
                        level_str,
                        detection.process.name,
                        detection.process.pid,
                        detection.confidence * 100.0
                    ));

                    for indicator in &detection.indicators {
                        content.push_str(&format!("  - {}\n", indicator));
                    }
                    content.push('\n');
                }
                content
            }
        }
    };

    if let Some(output_path) = output_file {
        use std::fs::File;
        use std::io::Write;
        
        info!("Writing results to file: {}", output_path);
        let mut file = File::create(output_path)?;
        file.write_all(output_content.as_bytes())?;
        if !quiet {
            println!("Results written to {}", output_path);
        }
    } else {
        debug!("Writing results to stdout");
        if !quiet || !detections.is_empty() {
            print!("{}", output_content);
        }
    }

    Ok(())
}

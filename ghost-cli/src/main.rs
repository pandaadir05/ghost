//! Ghost CLI - Process Injection Detection Framework
//!
//! A cross-platform command-line tool for detecting process injection,
//! process hollowing, and other malicious code injection techniques.

use anyhow::Result;
use clap::{Arg, Command};
use ghost_core::{memory, process, thread, DetectionConfig, DetectionEngine, ThreatLevel};
use log::{debug, error, info, warn};
use std::time::Instant;
use std::process::Command as ProcessCommand;

fn build_scan_args() -> Vec<Arg> {
    vec![
        Arg::new("format")
            .short('f')
            .long("format")
            .value_name("FORMAT")
            .help("Output format: table, json")
            .default_value("table")
            .value_parser(["table", "json", "csv"]),
        Arg::new("verbose")
            .short('v')
            .long("verbose")
            .help("Enable verbose output")
            .action(clap::ArgAction::SetTrue),
        Arg::new("pid")
            .short('p')
            .long("pid")
            .value_name("PID")
            .help("Target specific process ID"),
        Arg::new("process")
            .long("process")
            .value_name("NAME")
            .help("Target specific process name"),
        Arg::new("output")
            .short('o')
            .long("output")
            .value_name("FILE")
            .help("Write output to file instead of stdout"),
        Arg::new("debug")
            .short('d')
            .long("debug")
            .action(clap::ArgAction::SetTrue)
            .help("Enable debug logging"),
        Arg::new("quiet")
            .short('q')
            .long("quiet")
            .action(clap::ArgAction::SetTrue)
            .help("Suppress all output except errors"),
        Arg::new("config")
            .short('c')
            .long("config")
            .value_name("FILE")
            .help("Load configuration from file"),
        Arg::new("mitre-analysis")
            .long("mitre-analysis")
            .action(clap::ArgAction::SetTrue)
            .help("Enable MITRE ATT&CK framework analysis"),
        Arg::new("mitre-stats")
            .long("mitre-stats")
            .action(clap::ArgAction::SetTrue)
            .help("Show MITRE ATT&CK framework statistics"),
    ]
}

fn build_fuzz_args() -> Vec<Arg> {
    vec![
        Arg::new("target")
            .required(true)
            .help("Target binary to fuzz"),
        Arg::new("iterations")
            .long("iterations")
            .value_name("NUM")
            .help("Maximum fuzzing iterations")
            .default_value("10000"),
        Arg::new("timeout")
            .long("timeout")
            .value_name("SECONDS")
            .help("Execution timeout per test case")
            .default_value("5"),
        Arg::new("strategy")
            .long("strategy")
            .value_name("STRATEGY")
            .help("Fuzzing strategy: generation, mutation, hybrid")
            .default_value("hybrid")
            .value_parser(["generation", "mutation", "hybrid"]),
        Arg::new("corpus-dir")
            .long("corpus-dir")
            .value_name("DIR")
            .help("Directory for corpus")
            .default_value("output/corpus"),
        Arg::new("crash-dir")
            .long("crash-dir")
            .value_name("DIR")
            .help("Directory for crashes")
            .default_value("output/crashes"),
        Arg::new("seed")
            .long("seed")
            .value_name("NUM")
            .help("Random seed")
            .default_value("12345"),
        Arg::new("enable-taint")
            .long("enable-taint")
            .action(clap::ArgAction::SetTrue)
            .help("Enable taint tracking"),
        Arg::new("enable-symbolic")
            .long("enable-symbolic")
            .action(clap::ArgAction::SetTrue)
            .help("Enable symbolic execution"),
        Arg::new("ebpf")
            .long("ebpf")
            .action(clap::ArgAction::SetTrue)
            .help("Enable eBPF bytecode generation for fuzzing"),
        Arg::new("ebpf-instructions")
            .long("ebpf-instructions")
            .value_name("NUM")
            .help("Number of eBPF instructions to generate")
            .default_value("10"),
    ]
}

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
        .subcommand_required(true)
        .subcommand(
            Command::new("scan")
                .about("Scan for process injection")
                .args(&build_scan_args())
        )
        .subcommand(
            Command::new("fuzz")
                .about("Fuzz a target binary using VMDragonSlayer EBF fuzzer")
                .args(&build_fuzz_args())
        )
        .get_matches();

    match matches.subcommand() {
        Some(("scan", sub_matches)) => run_scan(sub_matches),
        Some(("fuzz", sub_matches)) => run_fuzz(sub_matches),
        _ => unreachable!("clap should ensure we don't get here"),
    }
}

fn run_scan(matches: &clap::ArgMatches) -> Result<()> {
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
        println!(
            "Ghost v{} - Process Injection Detection\n",
            env!("CARGO_PKG_VERSION")
        );
    }

    let _scan_start = Instant::now();
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
        println!("Scan completed with {} access errors", error_count);
    }

    info!(
        "Scan completed: {} processes scanned, {} suspicious processes found",
        scanned_count,
        detections.len()
    );

    // Handle output
    let output_content = match format.as_str() {
        "json" => {
            if detections.is_empty() {
                serde_json::json!({
                    "status": "clean",
                    "message": "No suspicious activity detected",
                    "detections": []
                })
                .to_string()
            } else {
                serde_json::json!({
                    "status": "suspicious",
                    "message": format!("Found {} suspicious processes", detections.len()),
                    "detections": &detections
                })
                .to_string()
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

fn run_fuzz(matches: &clap::ArgMatches) -> Result<()> {
    let target = matches.get_one::<String>("target").unwrap();
    let iterations = matches.get_one::<String>("iterations").unwrap();
    let timeout = matches.get_one::<String>("timeout").unwrap();
    let strategy = matches.get_one::<String>("strategy").unwrap();
    let corpus_dir = matches.get_one::<String>("corpus-dir").unwrap();
    let crash_dir = matches.get_one::<String>("crash-dir").unwrap();
    let seed = matches.get_one::<String>("seed").unwrap();
    let enable_taint = matches.get_flag("enable-taint");
    let enable_symbolic = matches.get_flag("enable-symbolic");
    let enable_ebpf = matches.get_flag("ebpf");
    let ebpf_instructions = matches.get_one::<String>("ebpf-instructions").unwrap();

    println!("Starting eBPF fuzzing with VMDragonSlayer");
    println!("Target: {}", target);
    println!("Iterations: {}", iterations);
    println!("Timeout: {}s", timeout);
    println!("Strategy: {}", strategy);
    println!("Corpus dir: {}", corpus_dir);
    println!("Crash dir: {}", crash_dir);
    println!("Seed: {}", seed);
    println!("Taint tracking: {}", enable_taint);
    println!("Symbolic execution: {}", enable_symbolic);
    println!("eBPF mode: {}", enable_ebpf);
    if enable_ebpf {
        println!("eBPF instructions: {}", ebpf_instructions);
    }
    println!();

    // Check if Python is available
    let python_check = ProcessCommand::new("python3")
        .arg("--version")
        .output();

    let python_cmd = if python_check.is_ok() {
        "python3"
    } else {
        "python"
    };

    // Run the fuzzer
    let mut cmd = ProcessCommand::new(python_cmd);
    cmd.arg("VMDragonSlayer/examples/fuzzing_example.py")
        .arg(target)
        .arg("--iterations")
        .arg(iterations)
        .arg("--timeout")
        .arg(timeout)
        .arg("--strategy")
        .arg(strategy)
        .arg("--corpus-dir")
        .arg(corpus_dir)
        .arg("--crash-dir")
        .arg(crash_dir)
        .arg("--seed")
        .arg(seed);

    if enable_taint {
        cmd.arg("--enable-taint");
    }
    if enable_symbolic {
        cmd.arg("--enable-symbolic");
    }
    if enable_ebpf {
        cmd.arg("--ebpf");
        cmd.arg("--ebpf-instructions").arg(ebpf_instructions);
    }

    let status = cmd.status()?;

    if status.success() {
        println!("Fuzzing completed successfully");
        Ok(())
    } else {
        eprintln!("Fuzzing failed with exit code: {}", status);
        Err(anyhow::anyhow!("Fuzzer exited with code {}", status))
    }
}

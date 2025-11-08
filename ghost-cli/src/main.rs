use anyhow::Result;
use clap::{Arg, Command};
use ghost_core::{memory, process, thread, DetectionEngine, ThreatLevel};
use std::time::Instant;

fn main() -> Result<()> {
    env_logger::init();

    let matches = Command::new("ghost")
        .version("0.1.0")
        .about("Cross-Platform Process Injection Detection Framework")
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
        .get_matches();

    let format = matches.get_one::<String>("format").unwrap();
    let verbose = matches.get_flag("verbose");
    let target_pid = matches.get_one::<String>("pid");

    println!("Ghost v0.1.0 - Process Injection Detection\n");

    let scan_start = Instant::now();
    let mut engine = DetectionEngine::new();
    
    let processes = if let Some(pid_str) = target_pid {
        let pid: u32 = pid_str.parse().expect("Invalid PID format");
        process::enumerate_processes()?
            .into_iter()
            .filter(|p| p.pid == pid)
            .collect()
    } else {
        process::enumerate_processes()?
    };

    println!("Scanning {} processes...\n", processes.len());

    let mut detections = Vec::new();

    for proc in &processes {
        // Skip known safe system processes for performance
        if proc.name == "csrss.exe" || proc.name == "wininit.exe" || proc.name == "winlogon.exe" {
            continue;
        }
        
        if let Ok(regions) = memory::enumerate_memory_regions(proc.pid) {
            // Get thread information if available
            let threads = thread::enumerate_threads(proc.pid).ok();
            let result = engine.analyze_process(proc, &regions, threads.as_deref());

            if result.threat_level != ThreatLevel::Clean {
                detections.push(result);
            }
        }
    }

    if detections.is_empty() {
        println!("No suspicious activity detected.");
    } else {
        println!("Found {} suspicious processes:\n", detections.len());

        for detection in detections {
            let level_str = match detection.threat_level {
                ThreatLevel::Suspicious => "SUSPICIOUS",
                ThreatLevel::Malicious => "MALICIOUS",
                _ => "CLEAN",
            };

            println!(
                "[{}] {} (PID: {}) - Confidence: {:.1}%",
                level_str,
                detection.process.name,
                detection.process.pid,
                detection.confidence * 100.0
            );

            for indicator in &detection.indicators {
                println!("  - {}", indicator);
            }
            println!();
        }
    }

    Ok(())
}

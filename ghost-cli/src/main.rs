use anyhow::Result;
use ghost_core::{memory, process, thread, DetectionEngine, ThreatLevel};

fn main() -> Result<()> {
    env_logger::init();

    println!("Ghost v0.1.0 - Process Injection Detection\n");

    let mut engine = DetectionEngine::new();
    let processes = process::enumerate_processes()?;

    println!("Scanning {} processes...\n", processes.len());

    let mut detections = Vec::new();

    for proc in &processes {
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

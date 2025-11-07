use crate::{MemoryProtection, MemoryRegion, ProcessInfo};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatLevel {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub process: ProcessInfo,
    pub threat_level: ThreatLevel,
    pub indicators: Vec<String>,
    pub confidence: f32,
}

pub struct DetectionEngine {
    baseline: HashMap<u32, ProcessBaseline>,
}

#[derive(Debug, Clone)]
struct ProcessBaseline {
    thread_count: u32,
    rwx_regions: usize,
}

impl DetectionEngine {
    pub fn new() -> Self {
        Self {
            baseline: HashMap::new(),
        }
    }

    /// Analyze process for injection indicators
    pub fn analyze_process(
        &mut self,
        process: &ProcessInfo,
        memory_regions: &[MemoryRegion],
    ) -> DetectionResult {
        let mut indicators = Vec::new();
        let mut confidence = 0.0;

        // Check for RWX memory regions
        let rwx_count = memory_regions
            .iter()
            .filter(|r| r.protection == MemoryProtection::ReadWriteExecute)
            .count();

        if rwx_count > 0 {
            indicators.push(format!("{} RWX memory regions detected", rwx_count));
            confidence += 0.3;
        }

        // Check for private executable memory
        let private_exec = memory_regions
            .iter()
            .filter(|r| {
                r.region_type == "PRIVATE"
                    && (r.protection == MemoryProtection::ReadWriteExecute
                        || r.protection == MemoryProtection::ReadExecute)
            })
            .count();

        if private_exec > 2 {
            indicators.push(format!(
                "{} private executable regions (possible shellcode)",
                private_exec
            ));
            confidence += 0.4;
        }

        // Update baseline
        if let Some(baseline) = self.baseline.get(&process.pid) {
            if process.thread_count > baseline.thread_count {
                let diff = process.thread_count - baseline.thread_count;
                indicators.push(format!("{} new threads created", diff));
                confidence += 0.2;
            }
        }

        self.baseline.insert(
            process.pid,
            ProcessBaseline {
                thread_count: process.thread_count,
                rwx_regions: rwx_count,
            },
        );

        let threat_level = if confidence >= 0.7 {
            ThreatLevel::Malicious
        } else if confidence >= 0.3 {
            ThreatLevel::Suspicious
        } else {
            ThreatLevel::Clean
        };

        DetectionResult {
            process: process.clone(),
            threat_level,
            indicators,
            confidence,
        }
    }
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}

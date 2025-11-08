use crate::{MemoryProtection, MemoryRegion, ProcessInfo, ThreadInfo};
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

    /// Analyze process for injection indicators with thread information
    pub fn analyze_process(
        &mut self,
        process: &ProcessInfo,
        memory_regions: &[MemoryRegion],
        threads: Option<&[ThreadInfo]>,
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

        // Check for thread count anomalies
        if let Some(baseline) = self.baseline.get(&process.pid) {
            if process.thread_count > baseline.thread_count {
                let diff = process.thread_count - baseline.thread_count;
                indicators.push(format!("{} new threads created", diff));
                confidence += 0.2;
            }
            
            // Detect significant RWX increase (possible injection)
            if rwx_count > baseline.rwx_regions + 1 {
                indicators.push("Rapid RWX region allocation".to_string());
                confidence += 0.5;
            }
        }
        
        // Check for unusual memory patterns
        self.check_memory_patterns(memory_regions, &mut indicators, &mut confidence);
        
        // Analyze threads if provided
        if let Some(thread_list) = threads {
            self.analyze_threads(thread_list, &mut indicators, &mut confidence);
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

    /// Check for suspicious memory patterns
    fn check_memory_patterns(
        &self,
        regions: &[MemoryRegion],
        indicators: &mut Vec<String>,
        confidence: &mut f32,
    ) {
        // Look for small executable allocations (typical shellcode size)
        let small_exec = regions
            .iter()
            .filter(|r| {
                r.size < 0x10000 // 64KB
                    && (r.protection == MemoryProtection::ReadExecute
                        || r.protection == MemoryProtection::ReadWriteExecute)
            })
            .count();

        if small_exec >= 3 {
            indicators.push("Multiple small executable allocations".to_string());
            *confidence += 0.3;
        }

        // Check for memory gaps that might indicate hollowing
        let mut sorted_regions: Vec<_> = regions.iter().collect();
        sorted_regions.sort_by_key(|r| r.base_address);
        
        for window in sorted_regions.windows(2) {
            let gap = window[1].base_address - (window[0].base_address + window[0].size);
            if gap > 0x100000 && gap < 0x1000000 {
                // 1MB to 16MB gap is suspicious
                indicators.push("Suspicious memory gaps detected".to_string());
                *confidence += 0.2;
                break;
            }
        }
    }

    /// Analyze thread patterns for injection indicators
    fn analyze_threads(
        &self,
        threads: &[ThreadInfo],
        indicators: &mut Vec<String>,
        confidence: &mut f32,
    ) {
        // Check for threads started from unusual locations
        let suspicious_threads = threads
            .iter()
            .filter(|t| {
                // Look for threads not started from main image
                t.start_address != 0 && (t.start_address & 0xFFFF_0000) != 0x7FF0_0000
            })
            .count();

        if suspicious_threads > 0 {
            indicators.push(format!(
                "{} threads with suspicious start addresses",
                suspicious_threads
            ));
            *confidence += 0.4;
        }

        // Check for abnormal thread creation time patterns
        let recent_threads = threads
            .iter()
            .filter(|t| t.creation_time > 0)
            .count();

        if recent_threads as f32 / threads.len() as f32 > 0.5 {
            indicators.push("High ratio of recently created threads".to_string());
            *confidence += 0.3;
        }
    }
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}

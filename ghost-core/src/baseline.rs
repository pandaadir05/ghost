//! Baseline management for differential detection.
//!
//! This module provides functionality to save and compare system states,
//! enabling detection of changes from a known-good baseline.

use crate::{DetectionResult, ProcessInfo, ThreatLevel};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

/// A snapshot of system state at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// When this baseline was created
    pub created_at: String,
    /// Hostname where baseline was captured
    pub hostname: String,
    /// Version of ghost that created this baseline
    pub version: String,
    /// Known processes and their threat assessments
    pub processes: HashMap<String, ProcessSnapshot>,
    /// Total processes at baseline time
    pub process_count: usize,
}

/// Snapshot of a single process for baseline comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    /// Process name
    pub name: String,
    /// Executable path (if available)
    pub path: Option<String>,
    /// Threat level at baseline time
    pub threat_level: ThreatLevel,
    /// Confidence score at baseline time
    pub confidence: f32,
    /// Indicators present at baseline
    pub indicators: Vec<String>,
}

/// Result of comparing current state against baseline.
#[derive(Debug, Clone)]
pub struct BaselineDiff {
    /// New processes not in baseline
    pub new_processes: Vec<DetectionResult>,
    /// Processes with elevated threat level
    pub escalated: Vec<EscalatedThreat>,
    /// Processes with new indicators
    pub new_indicators: Vec<NewIndicators>,
    /// Processes that disappeared (informational)
    pub disappeared: Vec<String>,
}

/// A process whose threat level increased since baseline.
#[derive(Debug, Clone)]
pub struct EscalatedThreat {
    pub process: ProcessInfo,
    pub baseline_level: ThreatLevel,
    pub current_level: ThreatLevel,
    pub baseline_confidence: f32,
    pub current_confidence: f32,
}

/// A process with new indicators not in baseline.
#[derive(Debug, Clone)]
pub struct NewIndicators {
    pub process: ProcessInfo,
    pub new_indicators: Vec<String>,
}

impl Baseline {
    /// Creates a new baseline from current detection results.
    pub fn from_detections(detections: &[DetectionResult], all_processes: &[ProcessInfo]) -> Self {
        let mut processes = HashMap::new();

        // Add detected processes
        for det in detections {
            let key = format!("{}:{}", det.process.name, det.process.pid);
            processes.insert(
                key,
                ProcessSnapshot {
                    name: det.process.name.clone(),
                    path: det.process.path.clone(),
                    threat_level: det.threat_level.clone(),
                    confidence: det.confidence,
                    indicators: det.indicators.clone(),
                },
            );
        }

        // Add clean processes
        for proc in all_processes {
            let key = format!("{}:{}", proc.name, proc.pid);
            if !processes.contains_key(&key) {
                processes.insert(
                    key,
                    ProcessSnapshot {
                        name: proc.name.clone(),
                        path: proc.path.clone(),
                        threat_level: ThreatLevel::Clean,
                        confidence: 0.0,
                        indicators: vec![],
                    },
                );
            }
        }

        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        Self {
            created_at: chrono::Local::now().to_rfc3339(),
            hostname,
            version: env!("CARGO_PKG_VERSION").to_string(),
            process_count: all_processes.len(),
            processes,
        }
    }

    /// Saves baseline to a JSON file.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, json)
    }

    /// Loads baseline from a JSON file.
    pub fn load<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let json = fs::read_to_string(path)?;
        serde_json::from_str(&json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Compares current detections against this baseline.
    pub fn compare(&self, current: &[DetectionResult], all_processes: &[ProcessInfo]) -> BaselineDiff {
        let mut new_processes = Vec::new();
        let mut escalated = Vec::new();
        let mut new_indicators = Vec::new();

        // Check each current detection
        for det in current {
            let key = format!("{}:{}", det.process.name, det.process.pid);
            
            // Also check by name only (PID may change between reboots)
            let by_name = self.processes.iter()
                .find(|(_, snap)| snap.name == det.process.name);

            match (self.processes.get(&key), by_name) {
                (Some(baseline), _) | (None, Some((_, baseline))) => {
                    // Check for escalation
                    if threat_level_value(&det.threat_level) > threat_level_value(&baseline.threat_level) {
                        escalated.push(EscalatedThreat {
                            process: det.process.clone(),
                            baseline_level: baseline.threat_level.clone(),
                            current_level: det.threat_level.clone(),
                            baseline_confidence: baseline.confidence,
                            current_confidence: det.confidence,
                        });
                    }

                    // Check for new indicators
                    let new_inds: Vec<_> = det.indicators.iter()
                        .filter(|i| !baseline.indicators.contains(i))
                        .cloned()
                        .collect();

                    if !new_inds.is_empty() {
                        new_indicators.push(NewIndicators {
                            process: det.process.clone(),
                            new_indicators: new_inds,
                        });
                    }
                }
                (None, None) => {
                    // New process not in baseline
                    new_processes.push(det.clone());
                }
            }
        }

        // Check for disappeared processes (informational)
        let current_names: std::collections::HashSet<_> = all_processes.iter()
            .map(|p| p.name.as_str())
            .collect();

        let disappeared: Vec<_> = self.processes.values()
            .filter(|snap| snap.threat_level != ThreatLevel::Clean)
            .filter(|snap| !current_names.contains(snap.name.as_str()))
            .map(|snap| snap.name.clone())
            .collect();

        BaselineDiff {
            new_processes,
            escalated,
            new_indicators,
            disappeared,
        }
    }
}

impl BaselineDiff {
    /// Returns true if there are any changes from baseline.
    pub fn has_changes(&self) -> bool {
        !self.new_processes.is_empty() 
            || !self.escalated.is_empty() 
            || !self.new_indicators.is_empty()
    }

    /// Returns total count of all changes.
    pub fn total_changes(&self) -> usize {
        self.new_processes.len() + self.escalated.len() + self.new_indicators.len()
    }
}

fn threat_level_value(level: &ThreatLevel) -> u8 {
    match level {
        ThreatLevel::Clean => 0,
        ThreatLevel::Suspicious => 1,
        ThreatLevel::Malicious => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baseline_creation() {
        let processes = vec![
            ProcessInfo {
                pid: 1234,
                name: "test.exe".to_string(),
                path: Some("/usr/bin/test".to_string()),
                parent_pid: Some(1),
            },
        ];

        let baseline = Baseline::from_detections(&[], &processes);
        assert_eq!(baseline.process_count, 1);
        assert!(baseline.processes.contains_key("test.exe:1234"));
    }

    #[test]
    fn test_diff_new_process() {
        let baseline = Baseline {
            created_at: "2024-01-01T00:00:00Z".to_string(),
            hostname: "test".to_string(),
            version: "0.1.0".to_string(),
            processes: HashMap::new(),
            process_count: 0,
        };

        let detection = DetectionResult {
            process: ProcessInfo {
                pid: 1234,
                name: "malware.exe".to_string(),
                path: None,
                parent_pid: None,
            },
            threat_level: ThreatLevel::Malicious,
            confidence: 0.9,
            indicators: vec!["RWX memory".to_string()],
            threat_context: None,
            evasion_analysis: None,
            mitre_analysis: None,
        };

        let diff = baseline.compare(&[detection], &[]);
        assert_eq!(diff.new_processes.len(), 1);
        assert!(diff.has_changes());
    }
}

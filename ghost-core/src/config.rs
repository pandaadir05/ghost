//! Configuration management for the Ghost detection engine.
//!
//! This module provides configuration structures for customizing detection
//! behavior, process filtering, and performance tuning.

use crate::GhostError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Output verbosity levels for controlling log and result detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OutputVerbosity {
    /// Minimal output: only critical findings and summary statistics.
    Minimal,
    /// Normal output: findings with limited indicators per detection.
    #[default]
    Normal,
    /// Verbose output: full indicator details and debug information.
    Verbose,
}

/// Output configuration for controlling result size and verbosity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Output verbosity level.
    #[serde(default)]
    pub verbosity: OutputVerbosity,
    /// Maximum number of indicators to include per detection (0 = unlimited).
    #[serde(default = "OutputConfig::default_max_indicators")]
    pub max_indicators_per_detection: usize,
    /// Only output detections at or above this threat level.
    #[serde(default)]
    pub min_threat_level: Option<String>,
    /// Deduplicate similar indicators within a detection.
    #[serde(default = "OutputConfig::default_dedupe")]
    pub deduplicate_indicators: bool,
    /// Enable summary mode: outputs aggregated statistics instead of full details.
    #[serde(default)]
    pub summary_mode: bool,
    /// Maximum total output size in bytes (0 = unlimited). Truncates after limit.
    #[serde(default)]
    pub max_output_size: usize,
}

impl OutputConfig {
    fn default_max_indicators() -> usize {
        10
    }

    fn default_dedupe() -> bool {
        true
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            verbosity: OutputVerbosity::Normal,
            max_indicators_per_detection: 10,
            min_threat_level: None,
            deduplicate_indicators: true,
            summary_mode: false,
            max_output_size: 0,
        }
    }
}

/// Configuration options for the detection engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Enable shellcode pattern detection.
    pub shellcode_detection: bool,
    /// Enable process hollowing detection.
    pub hollowing_detection: bool,
    /// Enable Windows hook injection detection.
    pub hook_detection: bool,
    /// Minimum confidence threshold for suspicious classification (0.0 - 1.0).
    pub confidence_threshold: f32,
    /// Skip known safe system processes.
    pub skip_system_processes: bool,
    /// Maximum memory size to scan per process in bytes.
    pub max_memory_scan_size: usize,
    /// Enable thread behavior analysis.
    pub thread_analysis_enabled: bool,
    /// Enable evasion technique detection.
    pub evasion_detection: bool,
    /// Enable MITRE ATT&CK mapping.
    pub mitre_mapping: bool,
    /// Scan interval in milliseconds for continuous monitoring.
    pub scan_interval_ms: u64,
    /// Process filter configuration.
    pub process_filter: Option<ProcessFilter>,
    /// Output configuration for controlling verbosity and result size.
    #[serde(default)]
    pub output: OutputConfig,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            shellcode_detection: true,
            hollowing_detection: true,
            hook_detection: true,
            confidence_threshold: 0.3,
            skip_system_processes: true,
            max_memory_scan_size: 100 * 1024 * 1024, // 100MB
            thread_analysis_enabled: true,
            evasion_detection: true,
            mitre_mapping: true,
            scan_interval_ms: 2000,
            process_filter: None,
            output: OutputConfig::default(),
        }
    }
}

impl DetectionConfig {
    /// Loads configuration from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, GhostError> {
        let content = fs::read_to_string(path)?;
        let config: DetectionConfig = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Loads configuration from a file, returning default on error.
    pub fn load_or_default<P: AsRef<Path>>(path: P) -> Self {
        Self::load(path).unwrap_or_default()
    }

    /// Saves configuration to a TOML file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), GhostError> {
        let content = toml::to_string_pretty(self).map_err(|e| GhostError::Configuration {
            message: e.to_string(),
        })?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Validates the configuration values.
    pub fn validate(&self) -> Result<(), GhostError> {
        if self.confidence_threshold < 0.0 || self.confidence_threshold > 1.0 {
            return Err(GhostError::Configuration {
                message: "confidence_threshold must be between 0.0 and 1.0".into(),
            });
        }

        if self.max_memory_scan_size == 0 {
            return Err(GhostError::Configuration {
                message: "max_memory_scan_size must be greater than 0".into(),
            });
        }

        Ok(())
    }

    /// Creates a configuration optimized for high performance (less thorough).
    pub fn performance_mode() -> Self {
        Self {
            shellcode_detection: true,
            hollowing_detection: false,
            hook_detection: false,
            confidence_threshold: 0.5,
            skip_system_processes: true,
            max_memory_scan_size: 10 * 1024 * 1024, // 10MB
            thread_analysis_enabled: false,
            evasion_detection: false,
            mitre_mapping: false,
            scan_interval_ms: 5000,
            process_filter: None,
            output: OutputConfig::default(),
        }
    }

    /// Creates a configuration optimized for thorough detection (slower).
    pub fn thorough_mode() -> Self {
        Self {
            shellcode_detection: true,
            hollowing_detection: true,
            hook_detection: true,
            confidence_threshold: 0.2,
            skip_system_processes: false,
            max_memory_scan_size: 500 * 1024 * 1024, // 500MB
            thread_analysis_enabled: true,
            evasion_detection: true,
            mitre_mapping: true,
            scan_interval_ms: 1000,
            process_filter: None,
            output: OutputConfig {
                verbosity: OutputVerbosity::Verbose,
                max_indicators_per_detection: 0, // unlimited
                ..OutputConfig::default()
            },
        }
    }

    /// Creates a configuration optimized for minimal output (summary only).
    pub fn summary_mode() -> Self {
        Self {
            output: OutputConfig {
                verbosity: OutputVerbosity::Minimal,
                summary_mode: true,
                max_indicators_per_detection: 3,
                ..OutputConfig::default()
            },
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessFilter {
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>,
    pub system_processes: Vec<String>,
}

impl Default for ProcessFilter {
    fn default() -> Self {
        Self {
            whitelist: vec![],
            blacklist: vec![],
            system_processes: vec![
                "csrss.exe".to_string(),
                "wininit.exe".to_string(),
                "winlogon.exe".to_string(),
                "dwm.exe".to_string(),
                "explorer.exe".to_string(),
            ],
        }
    }
}

impl ProcessFilter {
    pub fn should_scan(&self, process_name: &str) -> bool {
        // If whitelist is not empty, only scan whitelisted processes
        if !self.whitelist.is_empty() {
            return self
                .whitelist
                .iter()
                .any(|name| process_name.contains(name));
        }

        // Skip blacklisted processes
        if self
            .blacklist
            .iter()
            .any(|name| process_name.contains(name))
        {
            return false;
        }

        // Skip system processes if configured
        if self
            .system_processes
            .iter()
            .any(|name| process_name == name)
        {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DetectionConfig::default();
        assert!(config.shellcode_detection);
        assert_eq!(config.confidence_threshold, 0.3);
    }

    #[test]
    fn test_process_filter() {
        let filter = ProcessFilter::default();
        assert!(!filter.should_scan("csrss.exe"));
        assert!(filter.should_scan("notepad.exe"));
    }

    #[test]
    fn test_whitelist_filter() {
        let filter = ProcessFilter {
            whitelist: vec!["notepad.exe".to_string()],
            blacklist: vec![],
            system_processes: vec![],
        };
        assert!(filter.should_scan("notepad.exe"));
        assert!(!filter.should_scan("malware.exe"));
    }
}

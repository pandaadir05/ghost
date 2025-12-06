//! Output formatting and verbosity control for detection results.
//!
//! This module provides utilities for controlling the size and verbosity
//! of detection output, including summary mode, indicator deduplication,
//! and output size limits.

use crate::{DetectionResult, OutputConfig, OutputVerbosity, ThreatLevel};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Summary statistics for a scan session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_processes_scanned: usize,
    pub clean_processes: usize,
    pub suspicious_processes: usize,
    pub malicious_processes: usize,
    pub total_indicators: usize,
    pub unique_indicator_types: usize,
    pub scan_duration_ms: u64,
    pub top_indicators: Vec<IndicatorSummary>,
    pub threat_distribution: HashMap<String, usize>,
}

/// Summary of a specific indicator type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorSummary {
    pub indicator_type: String,
    pub count: usize,
    pub affected_processes: usize,
}

/// Formatted output ready for display or file writing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormattedOutput {
    pub summary: Option<ScanSummary>,
    pub detections: Vec<FormattedDetection>,
    pub truncated: bool,
    pub total_size_bytes: usize,
}

/// A detection result formatted according to output configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormattedDetection {
    pub process_name: String,
    pub pid: u32,
    pub threat_level: ThreatLevel,
    pub confidence: f32,
    pub indicators: Vec<String>,
    pub indicator_count_total: usize,
    pub indicators_truncated: bool,
}

/// Output formatter that applies verbosity settings to detection results.
pub struct OutputFormatter {
    config: OutputConfig,
}

impl OutputFormatter {
    /// Creates a new output formatter with the given configuration.
    pub fn new(config: OutputConfig) -> Self {
        Self { config }
    }

    /// Creates a formatter with default configuration.
    pub fn default_config() -> Self {
        Self::new(OutputConfig::default())
    }

    /// Formats a list of detection results according to the output configuration.
    pub fn format_results(
        &self,
        results: &[DetectionResult],
        total_scanned: usize,
        scan_duration_ms: u64,
    ) -> FormattedOutput {
        let mut formatted_detections = Vec::new();
        let mut total_size: usize = 0;
        let mut truncated = false;

        // Filter by threat level if configured
        let filtered_results: Vec<&DetectionResult> = results
            .iter()
            .filter(|r| self.passes_threat_filter(r))
            .collect();

        for result in &filtered_results {
            if self.config.max_output_size > 0 && total_size >= self.config.max_output_size {
                truncated = true;
                break;
            }

            let formatted = self.format_detection(result);
            total_size += self.estimate_detection_size(&formatted);
            formatted_detections.push(formatted);
        }

        let summary = if self.config.summary_mode {
            Some(self.build_summary(results, total_scanned, scan_duration_ms))
        } else {
            None
        };

        FormattedOutput {
            summary,
            detections: formatted_detections,
            truncated,
            total_size_bytes: total_size,
        }
    }

    /// Formats a single detection result with indicator limiting.
    fn format_detection(&self, result: &DetectionResult) -> FormattedDetection {
        let total_indicators = result.indicators.len();
        let mut indicators = result.indicators.clone();

        // Deduplicate indicators if configured
        if self.config.deduplicate_indicators {
            indicators = self.deduplicate_indicators(&indicators);
        }

        // Limit indicators if configured
        let indicators_truncated = if self.config.max_indicators_per_detection > 0
            && indicators.len() > self.config.max_indicators_per_detection
        {
            indicators.truncate(self.config.max_indicators_per_detection);
            true
        } else {
            false
        };

        // In minimal mode, only keep the most important indicator
        if self.config.verbosity == OutputVerbosity::Minimal && !indicators.is_empty() {
            indicators = vec![indicators[0].clone()];
        }

        FormattedDetection {
            process_name: result.process.name.clone(),
            pid: result.process.pid,
            threat_level: result.threat_level,
            confidence: result.confidence,
            indicators,
            indicator_count_total: total_indicators,
            indicators_truncated,
        }
    }

    /// Deduplicates indicators by normalizing and removing duplicates.
    fn deduplicate_indicators(&self, indicators: &[String]) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut result = Vec::new();

        for indicator in indicators {
            // Normalize indicator for comparison (remove addresses, counts)
            let normalized = self.normalize_indicator(indicator);
            if seen.insert(normalized) {
                result.push(indicator.clone());
            }
        }

        result
    }

    /// Normalizes an indicator string for deduplication.
    fn normalize_indicator(&self, indicator: &str) -> String {
        // Remove hex addresses like 0x1234abcd
        let without_addresses = regex_lite::Regex::new(r"0x[0-9a-fA-F]+")
            .map(|re| re.replace_all(indicator, "0x...").to_string())
            .unwrap_or_else(|_| indicator.to_string());

        // Remove specific counts/numbers
        let without_counts = regex_lite::Regex::new(r"\b\d+\b")
            .map(|re| re.replace_all(&without_addresses, "N").to_string())
            .unwrap_or(without_addresses);

        without_counts
    }

    /// Checks if a detection passes the threat level filter.
    fn passes_threat_filter(&self, result: &DetectionResult) -> bool {
        if let Some(ref min_level) = self.config.min_threat_level {
            let min = match min_level.to_lowercase().as_str() {
                "clean" => ThreatLevel::Clean,
                "suspicious" => ThreatLevel::Suspicious,
                "malicious" => ThreatLevel::Malicious,
                _ => ThreatLevel::Clean,
            };
            result.threat_level >= min
        } else {
            true
        }
    }

    /// Builds a summary of the scan results.
    fn build_summary(
        &self,
        results: &[DetectionResult],
        total_scanned: usize,
        scan_duration_ms: u64,
    ) -> ScanSummary {
        let mut clean = 0;
        let mut suspicious = 0;
        let mut malicious = 0;
        let mut indicator_counts: HashMap<String, (usize, HashSet<u32>)> = HashMap::new();
        let mut threat_dist: HashMap<String, usize> = HashMap::new();

        for result in results {
            match result.threat_level {
                ThreatLevel::Clean => clean += 1,
                ThreatLevel::Suspicious => suspicious += 1,
                ThreatLevel::Malicious => malicious += 1,
            }

            *threat_dist
                .entry(format!("{:?}", result.threat_level))
                .or_insert(0) += 1;

            for indicator in &result.indicators {
                let key = self.extract_indicator_type(indicator);
                let entry = indicator_counts.entry(key).or_insert((0, HashSet::new()));
                entry.0 += 1;
                entry.1.insert(result.process.pid);
            }
        }

        let mut top_indicators: Vec<IndicatorSummary> = indicator_counts
            .into_iter()
            .map(|(k, (count, pids))| IndicatorSummary {
                indicator_type: k,
                count,
                affected_processes: pids.len(),
            })
            .collect();

        top_indicators.sort_by(|a, b| b.count.cmp(&a.count));
        top_indicators.truncate(10);

        let total_indicators: usize = results.iter().map(|r| r.indicators.len()).sum();
        let unique_types = top_indicators.len();

        ScanSummary {
            total_processes_scanned: total_scanned,
            clean_processes: clean,
            suspicious_processes: suspicious,
            malicious_processes: malicious,
            total_indicators,
            unique_indicator_types: unique_types,
            scan_duration_ms,
            top_indicators,
            threat_distribution: threat_dist,
        }
    }

    /// Extracts the type/category from an indicator string.
    fn extract_indicator_type(&self, indicator: &str) -> String {
        // Extract the first part of the indicator as its type
        if let Some(colon_pos) = indicator.find(':') {
            indicator[..colon_pos].trim().to_string()
        } else if let Some(bracket_pos) = indicator.find('[') {
            indicator[..bracket_pos].trim().to_string()
        } else {
            // Use first few words as type
            indicator
                .split_whitespace()
                .take(3)
                .collect::<Vec<_>>()
                .join(" ")
        }
    }

    /// Estimates the size of a formatted detection in bytes.
    fn estimate_detection_size(&self, detection: &FormattedDetection) -> usize {
        let mut size = detection.process_name.len() + 50; // base overhead
        for indicator in &detection.indicators {
            size += indicator.len() + 4;
        }
        size
    }

    /// Formats the output as a table string.
    pub fn to_table(&self, output: &FormattedOutput) -> String {
        let mut result = String::new();

        if let Some(ref summary) = output.summary {
            result.push_str(&self.format_summary_table(summary));
            result.push('\n');
        }

        if output.detections.is_empty() {
            if output.summary.is_none() {
                result.push_str("No suspicious activity detected.\n");
            }
            return result;
        }

        if self.config.verbosity != OutputVerbosity::Minimal || output.summary.is_none() {
            result.push_str(&format!(
                "Found {} suspicious processes:\n\n",
                output.detections.len()
            ));

            for detection in &output.detections {
                let level_str = match detection.threat_level {
                    ThreatLevel::Suspicious => "SUSPICIOUS",
                    ThreatLevel::Malicious => "MALICIOUS",
                    ThreatLevel::Clean => "CLEAN",
                };

                result.push_str(&format!(
                    "[{}] {} (PID: {}) - Confidence: {:.1}%\n",
                    level_str, detection.process_name, detection.pid, detection.confidence * 100.0
                ));

                if self.config.verbosity != OutputVerbosity::Minimal {
                    for indicator in &detection.indicators {
                        result.push_str(&format!("  - {}\n", indicator));
                    }

                    if detection.indicators_truncated {
                        result.push_str(&format!(
                            "  ... and {} more indicators\n",
                            detection.indicator_count_total - detection.indicators.len()
                        ));
                    }
                }
                result.push('\n');
            }
        }

        if output.truncated {
            result.push_str("\n[Output truncated due to size limit]\n");
        }

        result
    }

    /// Formats the summary as a table string.
    fn format_summary_table(&self, summary: &ScanSummary) -> String {
        let mut result = String::new();

        result.push_str("Scan Summary\n");
        result.push_str("============\n");
        result.push_str(&format!(
            "Processes scanned: {}\n",
            summary.total_processes_scanned
        ));
        result.push_str(&format!("Clean: {}\n", summary.clean_processes));
        result.push_str(&format!("Suspicious: {}\n", summary.suspicious_processes));
        result.push_str(&format!("Malicious: {}\n", summary.malicious_processes));
        result.push_str(&format!("Duration: {}ms\n", summary.scan_duration_ms));
        result.push_str(&format!("Total indicators: {}\n", summary.total_indicators));

        if !summary.top_indicators.is_empty() {
            result.push_str("\nTop Indicators:\n");
            for (i, ind) in summary.top_indicators.iter().take(5).enumerate() {
                result.push_str(&format!(
                    "  {}. {} ({} occurrences, {} processes)\n",
                    i + 1,
                    ind.indicator_type,
                    ind.count,
                    ind.affected_processes
                ));
            }
        }

        result
    }

    /// Formats the output as JSON string.
    pub fn to_json(&self, output: &FormattedOutput) -> String {
        serde_json::to_string_pretty(output).unwrap_or_else(|_| "{}".to_string())
    }

    /// Formats the output as compact JSON (for summary files).
    pub fn to_json_compact(&self, output: &FormattedOutput) -> String {
        serde_json::to_string(output).unwrap_or_else(|_| "{}".to_string())
    }
}

impl Default for OutputFormatter {
    fn default() -> Self {
        Self::default_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProcessInfo;

    fn create_test_detection(name: &str, pid: u32, indicators: Vec<&str>) -> DetectionResult {
        DetectionResult {
            process: ProcessInfo {
                pid,
                ppid: 0,
                name: name.to_string(),
                path: None,
                thread_count: 1,
            },
            threat_level: ThreatLevel::Suspicious,
            indicators: indicators.into_iter().map(String::from).collect(),
            confidence: 0.75,
            threat_context: None,
            evasion_analysis: None,
            mitre_analysis: None,
        }
    }

    #[test]
    fn test_indicator_limiting() {
        let config = OutputConfig {
            max_indicators_per_detection: 2,
            ..Default::default()
        };
        let formatter = OutputFormatter::new(config);

        let detection =
            create_test_detection("test.exe", 1234, vec!["ind1", "ind2", "ind3", "ind4"]);

        let output = formatter.format_results(&[detection], 1, 100);
        assert_eq!(output.detections[0].indicators.len(), 2);
        assert!(output.detections[0].indicators_truncated);
        assert_eq!(output.detections[0].indicator_count_total, 4);
    }

    #[test]
    fn test_summary_mode() {
        let config = OutputConfig {
            summary_mode: true,
            ..Default::default()
        };
        let formatter = OutputFormatter::new(config);

        let detections = vec![
            create_test_detection("test1.exe", 1, vec!["type1: detail"]),
            create_test_detection("test2.exe", 2, vec!["type1: other", "type2: data"]),
        ];

        let output = formatter.format_results(&detections, 10, 500);
        assert!(output.summary.is_some());

        let summary = output.summary.unwrap();
        assert_eq!(summary.total_processes_scanned, 10);
        assert_eq!(summary.suspicious_processes, 2);
    }

    #[test]
    fn test_deduplication() {
        let config = OutputConfig {
            deduplicate_indicators: true,
            ..Default::default()
        };
        let formatter = OutputFormatter::new(config);

        let detection = create_test_detection(
            "test.exe",
            1,
            vec![
                "RWX memory at 0x12345678",
                "RWX memory at 0xabcdef00",
                "Different indicator",
            ],
        );

        let output = formatter.format_results(&[detection], 1, 100);
        // Should deduplicate the two RWX memory indicators
        assert!(output.detections[0].indicators.len() <= 2);
    }
}

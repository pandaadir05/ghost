use crate::{GhostError, ProcessInfo, Result};
use chrono::Timelike;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessFeatures {
    pub pid: u32,
    pub parent_pid: u32,
    pub thread_count: u32,
    pub memory_regions: usize,
    pub executable_regions: usize,
    pub rwx_regions: usize,
    pub private_regions: usize,
    pub image_regions: usize,
    pub total_memory_size: usize,
    pub largest_region_size: usize,
    pub memory_fragmentation: f64,
    pub thread_creation_rate: f64,
    pub api_call_frequency: f64,
    pub entropy_score: f64,
    pub creation_time_hours: f64,
    pub parent_child_ratio: f64,
}

#[derive(Debug, Clone)]
pub struct AnomalyScore {
    pub overall_score: f64,
    pub component_scores: HashMap<String, f64>,
    pub outlier_features: Vec<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct ProcessProfile {
    pub name: String,
    pub feature_means: HashMap<String, f64>,
    pub feature_stds: HashMap<String, f64>,
    pub sample_count: usize,
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

/// Advanced ML-based anomaly detection for process behavior
pub struct AnomalyDetector {
    process_profiles: HashMap<String, ProcessProfile>,
    global_baseline: Option<ProcessProfile>,
    detection_threshold: f64,
    outlier_threshold: f64,
    min_samples_for_profile: usize,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            process_profiles: HashMap::new(),
            global_baseline: None,
            detection_threshold: 0.7,
            outlier_threshold: 2.5, // Standard deviations
            min_samples_for_profile: 10,
        }
    }

    /// Extract behavioral features from process data
    pub fn extract_features(
        &self,
        process: &ProcessInfo,
        memory_regions: &[crate::MemoryRegion],
        threads: Option<&[crate::ThreadInfo]>,
    ) -> ProcessFeatures {
        let executable_regions = memory_regions
            .iter()
            .filter(|r| matches!(
                r.protection,
                crate::MemoryProtection::ReadExecute | crate::MemoryProtection::ReadWriteExecute
            ))
            .count();

        let rwx_regions = memory_regions
            .iter()
            .filter(|r| r.protection == crate::MemoryProtection::ReadWriteExecute)
            .count();

        let private_regions = memory_regions
            .iter()
            .filter(|r| r.region_type == "PRIVATE")
            .count();

        let image_regions = memory_regions
            .iter()
            .filter(|r| r.region_type == "IMAGE")
            .count();

        let total_memory_size: usize = memory_regions.iter().map(|r| r.size).sum();
        let largest_region_size = memory_regions
            .iter()
            .map(|r| r.size)
            .max()
            .unwrap_or(0);

        // Calculate memory fragmentation (std dev of region sizes)
        let mean_size = if memory_regions.is_empty() {
            0.0
        } else {
            total_memory_size as f64 / memory_regions.len() as f64
        };

        let variance = memory_regions
            .iter()
            .map(|r| {
                let diff = r.size as f64 - mean_size;
                diff * diff
            })
            .sum::<f64>()
            / memory_regions.len().max(1) as f64;

        let memory_fragmentation = variance.sqrt() / mean_size.max(1.0);

        // Thread-based features
        let thread_creation_rate = if let Some(thread_list) = threads {
            let recent_threads = thread_list
                .iter()
                .filter(|t| t.creation_time > 0)
                .count();
            recent_threads as f64 / thread_list.len().max(1) as f64
        } else {
            0.0
        };

        // Simulate API call frequency (in real implementation, would track actual calls)
        let api_call_frequency = self.estimate_api_call_frequency(process, memory_regions);

        // Calculate entropy score based on memory content patterns
        let entropy_score = self.calculate_entropy_score(memory_regions);

        // Time-based features
        let creation_time_hours = chrono::Utc::now().time().hour() as f64;

        // Parent-child relationship analysis
        let parent_child_ratio = if process.ppid == 0 {
            0.0
        } else {
            process.pid as f64 / process.ppid as f64
        };

        ProcessFeatures {
            pid: process.pid,
            parent_pid: process.ppid,
            thread_count: process.thread_count,
            memory_regions: memory_regions.len(),
            executable_regions,
            rwx_regions,
            private_regions,
            image_regions,
            total_memory_size,
            largest_region_size,
            memory_fragmentation,
            thread_creation_rate,
            api_call_frequency,
            entropy_score,
            creation_time_hours,
            parent_child_ratio,
        }
    }

    /// Analyze process for anomalies using ML techniques
    pub fn analyze_anomaly(
        &mut self,
        process: &ProcessInfo,
        features: &ProcessFeatures,
    ) -> Result<AnomalyScore> {
        // Update process profile with new data
        self.update_process_profile(&process.name, features);

        // Calculate anomaly scores
        let mut component_scores = HashMap::new();
        let mut outlier_features = Vec::new();

        // Get baseline for comparison
        let baseline = self
            .process_profiles
            .get(&process.name)
            .or(self.global_baseline.as_ref());

        if let Some(profile) = baseline {
            if profile.sample_count >= self.min_samples_for_profile {
                // Analyze each feature for anomalies
                self.analyze_feature_anomaly(
                    "thread_count",
                    features.thread_count as f64,
                    profile,
                    &mut component_scores,
                    &mut outlier_features,
                );

                self.analyze_feature_anomaly(
                    "rwx_regions",
                    features.rwx_regions as f64,
                    profile,
                    &mut component_scores,
                    &mut outlier_features,
                );

                self.analyze_feature_anomaly(
                    "memory_fragmentation",
                    features.memory_fragmentation,
                    profile,
                    &mut component_scores,
                    &mut outlier_features,
                );

                self.analyze_feature_anomaly(
                    "thread_creation_rate",
                    features.thread_creation_rate,
                    profile,
                    &mut component_scores,
                    &mut outlier_features,
                );

                self.analyze_feature_anomaly(
                    "api_call_frequency",
                    features.api_call_frequency,
                    profile,
                    &mut component_scores,
                    &mut outlier_features,
                );

                self.analyze_feature_anomaly(
                    "entropy_score",
                    features.entropy_score,
                    profile,
                    &mut component_scores,
                    &mut outlier_features,
                );
            }
        }

        // Calculate overall anomaly score
        let overall_score = if component_scores.is_empty() {
            0.0 // Not enough data for analysis
        } else {
            // Weighted average of component scores
            let weighted_sum: f64 = component_scores
                .iter()
                .map(|(feature, score)| {
                    let weight = match feature.as_str() {
                        "rwx_regions" => 0.3,        // High weight for RWX regions
                        "thread_creation_rate" => 0.25, // High weight for thread anomalies
                        "entropy_score" => 0.2,      // Medium weight for entropy
                        "api_call_frequency" => 0.15, // Medium weight for API calls
                        "memory_fragmentation" => 0.1, // Lower weight for fragmentation
                        _ => 0.05,                    // Low weight for other features
                    };
                    score * weight
                })
                .sum();

            weighted_sum.min(1.0)
        };

        // Calculate confidence based on sample size and feature coverage
        let confidence = if let Some(profile) = baseline {
            (profile.sample_count as f64 / 100.0).min(1.0) * 
            (component_scores.len() as f64 / 6.0).min(1.0)
        } else {
            0.0
        };

        Ok(AnomalyScore {
            overall_score,
            component_scores,
            outlier_features,
            confidence,
        })
    }

    fn analyze_feature_anomaly(
        &self,
        feature_name: &str,
        value: f64,
        profile: &ProcessProfile,
        component_scores: &mut HashMap<String, f64>,
        outlier_features: &mut Vec<String>,
    ) {
        if let (Some(&mean), Some(&std)) = (
            profile.feature_means.get(feature_name),
            profile.feature_stds.get(feature_name),
        ) {
            if std > 0.0 {
                // Calculate z-score
                let z_score = (value - mean).abs() / std;
                
                // Convert z-score to anomaly score (0-1)
                let anomaly_score = (z_score / 4.0).min(1.0); // Cap at 4 standard deviations
                
                component_scores.insert(feature_name.to_string(), anomaly_score);
                
                // Mark as outlier if beyond threshold
                if z_score > self.outlier_threshold {
                    outlier_features.push(format!(
                        "{}: {:.2} (μ={:.2}, σ={:.2}, z={:.2})",
                        feature_name, value, mean, std, z_score
                    ));
                }
            }
        }
    }

    fn update_process_profile(&mut self, process_name: &str, features: &ProcessFeatures) {
        let profile = self
            .process_profiles
            .entry(process_name.to_string())
            .or_insert_with(|| ProcessProfile {
                name: process_name.to_string(),
                feature_means: HashMap::new(),
                feature_stds: HashMap::new(),
                sample_count: 0,
                last_updated: chrono::Utc::now(),
            });

        // Update running statistics (using Welford's online algorithm)
        profile.sample_count += 1;
        let n = profile.sample_count as f64;

        // Define features to track
        let feature_values = vec![
            ("thread_count", features.thread_count as f64),
            ("memory_regions", features.memory_regions as f64),
            ("rwx_regions", features.rwx_regions as f64),
            ("memory_fragmentation", features.memory_fragmentation),
            ("thread_creation_rate", features.thread_creation_rate),
            ("api_call_frequency", features.api_call_frequency),
            ("entropy_score", features.entropy_score),
        ];

        for (feature_name, value) in feature_values {
            // Update mean
            let old_mean = profile.feature_means.get(feature_name).copied().unwrap_or(0.0);
            let new_mean = old_mean + (value - old_mean) / n;
            profile.feature_means.insert(feature_name.to_string(), new_mean);

            // Update standard deviation (using variance)
            if n > 1.0 {
                let old_std = profile.feature_stds.get(feature_name).copied().unwrap_or(0.0);
                let old_variance = old_std * old_std;
                let new_variance = ((n - 2.0) * old_variance + (value - old_mean) * (value - new_mean)) / (n - 1.0);
                let new_std = new_variance.max(0.0).sqrt();
                profile.feature_stds.insert(feature_name.to_string(), new_std);
            }
        }

        profile.last_updated = chrono::Utc::now();
    }

    fn estimate_api_call_frequency(&self, _process: &ProcessInfo, memory_regions: &[crate::MemoryRegion]) -> f64 {
        // Heuristic: More executable regions might indicate more API calls
        let executable_count = memory_regions
            .iter()
            .filter(|r| matches!(
                r.protection,
                crate::MemoryProtection::ReadExecute | crate::MemoryProtection::ReadWriteExecute
            ))
            .count();

        (executable_count as f64 / memory_regions.len().max(1) as f64) * 100.0
    }

    fn calculate_entropy_score(&self, memory_regions: &[crate::MemoryRegion]) -> f64 {
        // Simplified entropy calculation based on region size distribution
        if memory_regions.is_empty() {
            return 0.0;
        }

        let total_size: usize = memory_regions.iter().map(|r| r.size).sum();
        if total_size == 0 {
            return 0.0;
        }

        let entropy: f64 = memory_regions
            .iter()
            .map(|r| {
                let p = r.size as f64 / total_size as f64;
                if p > 0.0 {
                    -p * p.log2()
                } else {
                    0.0
                }
            })
            .sum();

        entropy / 10.0 // Normalize to 0-1 range approximately
    }

    pub fn is_anomalous(&self, score: &AnomalyScore) -> bool {
        score.overall_score > self.detection_threshold && score.confidence > 0.5
    }

    pub fn get_process_profile(&self, process_name: &str) -> Option<&ProcessProfile> {
        self.process_profiles.get(process_name)
    }

    pub fn set_detection_threshold(&mut self, threshold: f64) {
        self.detection_threshold = threshold.clamp(0.0, 1.0);
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}
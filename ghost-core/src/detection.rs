//! Core detection engine for process injection analysis.
//!
//! This module provides the main detection orchestration, combining multiple
//! analysis techniques including memory scanning, shellcode detection,
//! process hollowing detection, and behavioral anomaly analysis.

#[cfg(all(target_os = "linux", feature = "ebpf-detection"))]
use crate::EbpfDetector;
use crate::{
    detect_hook_injection, AnomalyDetector, DetectionConfig, DynamicYaraEngine, EvasionDetector,
    EvasionResult, GhostError, HollowingDetector, MemoryProtection, MemoryRegion,
    MitreAnalysisResult, MitreAttackEngine, ProcessInfo, ShellcodeDetector, ThreadInfo,
    ThreatContext, ThreatIntelligence,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Threat classification levels for detected processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum ThreatLevel {
    /// Process appears normal with no suspicious indicators.
    Clean,
    /// Process exhibits potentially malicious behavior requiring investigation.
    Suspicious,
    /// Process shows strong indicators of malicious activity.
    Malicious,
}

impl ThreatLevel {
    /// Returns a human-readable description of the threat level.
    pub fn description(&self) -> &'static str {
        match self {
            ThreatLevel::Clean => "No threats detected",
            ThreatLevel::Suspicious => "Potential security concern",
            ThreatLevel::Malicious => "High confidence malicious activity",
        }
    }
}

/// Result of analyzing a process for injection indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    /// Information about the analyzed process.
    pub process: ProcessInfo,
    /// Overall threat classification.
    pub threat_level: ThreatLevel,
    /// List of specific indicators that contributed to the detection.
    pub indicators: Vec<String>,
    /// Confidence score from 0.0 to 1.0 indicating detection certainty.
    pub confidence: f32,
    /// Optional threat intelligence context with IOC matches.
    pub threat_context: Option<ThreatContext>,
    /// Optional analysis of evasion techniques used.
    pub evasion_analysis: Option<EvasionResult>,
    /// Optional MITRE ATT&CK framework mapping.
    pub mitre_analysis: Option<MitreAnalysisResult>,
}

/// Main detection engine that orchestrates all analysis components.
#[derive(Debug)]
pub struct DetectionEngine {
    baseline: HashMap<u32, ProcessBaseline>,
    shellcode_detector: ShellcodeDetector,
    hollowing_detector: HollowingDetector,
    anomaly_detector: AnomalyDetector,
    threat_intelligence: ThreatIntelligence,
    evasion_detector: EvasionDetector,
    mitre_engine: MitreAttackEngine,
    yara_engine: Option<DynamicYaraEngine>,
    _config: Option<DetectionConfig>,
    #[cfg(all(target_os = "linux", feature = "ebpf-detection"))]
    ebpf_detector: Option<EbpfDetector>,
}

/// Baseline metrics for a process used to detect behavioral changes.
#[derive(Debug, Clone)]
struct ProcessBaseline {
    thread_count: u32,
    rwx_regions: usize,
}

impl DetectionEngine {
    /// Creates a new detection engine with default configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the MITRE ATT&CK engine fails to initialize.
    pub fn new() -> Result<Self, GhostError> {
        Self::with_config(None)
    }

    /// Creates a new detection engine with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Optional configuration for filtering and tuning detection behavior.
    ///
    /// # Errors
    ///
    /// Returns an error if the MITRE ATT&CK engine fails to initialize.
    pub fn with_config(config: Option<DetectionConfig>) -> Result<Self, GhostError> {
        let shellcode_detector = ShellcodeDetector::new();
        let hollowing_detector = HollowingDetector::new();
        let anomaly_detector = AnomalyDetector::new();
        let threat_intelligence = ThreatIntelligence::new();
        let evasion_detector = EvasionDetector::new();
        let mitre_engine = MitreAttackEngine::new()?;

        // Initialize YARA engine with default rules directory
        let yara_engine = match DynamicYaraEngine::new(Some("rules")) {
            Ok(engine) => {
                if engine.is_compiled() {
                    log::info!(
                        "YARA engine initialized with {} rules",
                        engine.get_rule_count()
                    );
                    Some(engine)
                } else {
                    if cfg!(feature = "yara-scanning") {
                        log::warn!("YARA rules not compiled, engine disabled");
                    } else {
                        log::warn!(
                            "YARA scanning is disabled (build with --features yara-scanning)"
                        );
                    }
                    None
                }
            }
            Err(e) => {
                log::warn!("Failed to initialize YARA engine: {:?}", e);
                None
            }
        };

        #[cfg(all(target_os = "linux", feature = "ebpf-detection"))]
        let ebpf_detector = match EbpfDetector::new() {
            Ok(mut detector) => {
                if let Err(e) = detector.initialize() {
                    log::warn!("Failed to initialize eBPF detector: {:?}", e);
                    None
                } else {
                    log::info!("eBPF detector initialized successfully");
                    Some(detector)
                }
            }
            Err(e) => {
                log::warn!("Failed to create eBPF detector: {:?}", e);
                None
            }
        };

        Ok(DetectionEngine {
            baseline: HashMap::new(),
            shellcode_detector,
            hollowing_detector,
            anomaly_detector,
            threat_intelligence,
            evasion_detector,
            mitre_engine,
            yara_engine,
            _config: config,
            #[cfg(all(target_os = "linux", feature = "ebpf-detection"))]
            ebpf_detector,
        })
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

        // Check for RWX memory regions (focus on PRIVATE regions; IMAGE pages can be legitimately executable)
        let private_rwx_count = memory_regions
            .iter()
            .filter(|r| r.region_type == "PRIVATE" && r.protection == MemoryProtection::ReadWriteExecute)
            .count();

        if private_rwx_count > 0 {
            // RWX can occur in benign software (e.g., JITs); treat as a weak standalone signal.
            indicators.push(format!(
                "{} PRIVATE RWX memory regions detected",
                private_rwx_count
            ));
            // No confidence boost without corroborating execution evidence.
        }

        // Check for thread count anomalies
        if let Some(baseline) = self.baseline.get(&process.pid) {
            if process.thread_count > baseline.thread_count {
                let diff = process.thread_count - baseline.thread_count;
                indicators.push(format!("{} new threads created", diff));
                confidence += 0.2;
            }

            // Detect significant RWX increase (possible injection)
            if private_rwx_count > baseline.rwx_regions + 1 {
                indicators.push("Rapid RWX region allocation".to_string());
                confidence += 0.2;
            }
        }

        // Check for unusual memory patterns
        self.check_memory_patterns(memory_regions, &mut indicators, &mut confidence);

        // Analyze threads if provided
        if let Some(thread_list) = threads {
            self.analyze_threads(thread_list, memory_regions, &mut indicators, &mut confidence);
        }

        // Check for Windows hook injection
        if let Ok(hook_result) = detect_hook_injection(process.pid) {
            if hook_result.suspicious_count > 0 {
                indicators.push(format!(
                    "{} suspicious Windows hooks detected",
                    hook_result.suspicious_count
                ));
                confidence += 0.6; // High confidence for hook-based injection
            }

            if hook_result.global_hooks > 8 {
                indicators.push("Excessive global hooks (possible system compromise)".to_string());
                confidence += 0.3;
            }
        }

        // Scan for shellcode patterns in executable memory regions.
        // To reduce false positives in JIT-heavy applications, focus on regions that contain
        // a thread's start address (a stronger signal of injected execution).
        let shellcode_detections = self.scan_for_shellcode(process.pid, memory_regions, threads);
        if !shellcode_detections.is_empty() {
            for detection in &shellcode_detections {
                indicators.push(format!(
                    "Shellcode detected at {:#x}: {}",
                    detection.address,
                    detection.signature_matches.join(", ")
                ));
                confidence += detection.confidence;
            }
        }

        // Check for process hollowing
        if let Ok(Some(hollowing_detection)) = self
            .hollowing_detector
            .analyze_process(process, memory_regions)
        {
            for indicator in &hollowing_detection.indicators {
                indicators.push(format!("Process hollowing: {}", indicator));
            }
            confidence += hollowing_detection.confidence;
        }

        // YARA rule scanning
        if let Some(yara_engine) = &self.yara_engine {
            let yara_result = match tokio::runtime::Handle::try_current() {
                Ok(handle) => handle
                    .block_on(async { yara_engine.scan_process(process, memory_regions).await }),
                Err(_) => match tokio::runtime::Runtime::new() {
                    Ok(runtime) => runtime.block_on(async {
                        yara_engine.scan_process(process, memory_regions).await
                    }),
                    Err(e) => {
                        log::error!("Failed to create async runtime: {}", e);
                        return DetectionResult {
                            process: process.clone(),
                            threat_level: ThreatLevel::Clean,
                            indicators: vec!["YARA scan failed due to runtime error".to_string()],
                            confidence: 0.0,
                            threat_context: None,
                            evasion_analysis: None,
                            mitre_analysis: None,
                        };
                    }
                },
            };

            if let Ok(yara_result) = yara_result {
                if !yara_result.matches.is_empty() {
                    log::debug!(
                        "YARA scan found {} matches in {} ms",
                        yara_result.matches.len(),
                        yara_result.scan_time_ms
                    );

                    // De-duplicate by rule name and cap contribution to prevent runaway confidence.
                    let mut per_rule: HashMap<String, (crate::yara_engine::ThreatLevel, usize)> =
                        HashMap::new();
                    for m in &yara_result.matches {
                        let entry = per_rule
                            .entry(m.rule_name.clone())
                            .or_insert((m.threat_level, 0));
                        entry.1 += 1;
                        if (m.threat_level as u8) > (entry.0 as u8) {
                            entry.0 = m.threat_level;
                        }
                    }

                    let mut yara_confidence = 0.0f32;
                    for (rule_name, (threat_level, hit_count)) in per_rule {
                        indicators.push(format!(
                            "YARA: {} matched ({} hit(s), threat level: {:?})",
                            rule_name, hit_count, threat_level
                        ));

                        let threat_boost = match threat_level {
                            crate::yara_engine::ThreatLevel::Critical => 0.5,
                            crate::yara_engine::ThreatLevel::High => 0.4,
                            crate::yara_engine::ThreatLevel::Medium => 0.25,
                            crate::yara_engine::ThreatLevel::Low => 0.15,
                            crate::yara_engine::ThreatLevel::Info => 0.05,
                        };

                        yara_confidence += threat_boost;
                    }

                    confidence += yara_confidence.min(0.6);
                }
            }
        }

        // ML-based anomaly detection
        let features = self
            .anomaly_detector
            .extract_features(process, memory_regions, threads);
        if let Ok(anomaly_score) = self.anomaly_detector.analyze_anomaly(process, &features) {
            if self.anomaly_detector.is_anomalous(&anomaly_score) {
                indicators.push(format!(
                    "ML anomaly detected: {:.1}% confidence",
                    anomaly_score.overall_score * 100.0
                ));

                for outlier in &anomaly_score.outlier_features {
                    indicators.push(format!("Outlier: {}", outlier));
                }

                confidence += (anomaly_score.overall_score * anomaly_score.confidence) as f32;
            }
        }

        // Advanced evasion detection
        let evasion_result =
            self.evasion_detector
                .analyze_evasion(process, memory_regions, threads.unwrap_or(&[]));
        if evasion_result.confidence > 0.3 {
            for technique in &evasion_result.evasion_techniques {
                indicators.push(format!(
                    "Evasion technique: {} (confidence: {:.1}%)",
                    technique.technique_name,
                    technique.confidence * 100.0
                ));
            }

            for indicator in &evasion_result.anti_analysis_indicators {
                indicators.push(format!("Anti-analysis: {}", indicator));
            }

            // Increase confidence based on evasion sophistication
            confidence += evasion_result.confidence * 0.4;

            // Boost threat level for sophisticated evasion
            if evasion_result.sophistication_score > 0.7 {
                confidence += 0.2; // Additional boost for advanced evasion
            }
        }

        self.baseline.insert(
            process.pid,
            ProcessBaseline {
                thread_count: process.thread_count,
                rwx_regions: private_rwx_count,
            },
        );

        // Normalize confidence to [0, 1] to avoid nonsensical percentages.
        confidence = confidence.clamp(0.0, 1.0);

        let threat_level = if confidence >= 0.7 {
            ThreatLevel::Malicious
        } else if confidence >= 0.3 {
            ThreatLevel::Suspicious
        } else {
            ThreatLevel::Clean
        };

        // Create initial detection result

        // Enrich with threat intelligence (async operation would be handled by caller)
        // For now, we'll set a placeholder that can be enriched later
        DetectionResult {
            process: process.clone(),
            threat_level,
            indicators,
            confidence,
            threat_context: None,
            evasion_analysis: None,
            mitre_analysis: None,
        }
    }

    /// Enrich detection result with threat intelligence
    pub async fn enrich_with_threat_intel(
        &self,
        mut detection: DetectionResult,
    ) -> DetectionResult {
        let threat_context = self.threat_intelligence.enrich_detection(&detection).await;

        // Update threat level based on threat intelligence findings
        if threat_context.risk_score > 0.8 {
            detection.threat_level = ThreatLevel::Malicious;
            detection.confidence = (detection.confidence + threat_context.risk_score) / 2.0;
        } else if threat_context.risk_score > 0.5 {
            detection.threat_level = ThreatLevel::Suspicious;
            detection.confidence = (detection.confidence + threat_context.risk_score * 0.7) / 2.0;
        }

        // Add threat intelligence indicators
        for ioc in &threat_context.matched_iocs {
            detection
                .indicators
                .push(format!("IOC Match: {} ({})", ioc.value, ioc.source));
        }

        if let Some(actor) = &threat_context.threat_actor {
            detection
                .indicators
                .push(format!("Attributed to: {}", actor.name));
        }

        detection.threat_context = Some(threat_context);
        detection
    }

    /// Perform comprehensive analysis including evasion detection
    pub fn analyze_process_comprehensive(
        &mut self,
        process: &ProcessInfo,
        memory_regions: &[MemoryRegion],
        threads: &[ThreadInfo],
    ) -> DetectionResult {
        // Perform standard detection
        let mut detection_result = self.analyze_process(process, memory_regions, Some(threads));

        // Add evasion analysis
        let evasion_result =
            self.evasion_detector
                .analyze_evasion(process, memory_regions, threads);

        // Update threat level based on evasion analysis
        if evasion_result.confidence > 0.7 {
            detection_result.threat_level = ThreatLevel::Malicious;
            detection_result.confidence =
                (detection_result.confidence + evasion_result.confidence) / 2.0;
        } else if evasion_result.confidence > 0.4 {
            detection_result.threat_level = ThreatLevel::Suspicious;
            detection_result.confidence =
                (detection_result.confidence + evasion_result.confidence * 0.7) / 2.0;
        }

        detection_result.evasion_analysis = Some(evasion_result);
        detection_result
    }

    /// Process eBPF detection events (Linux only)
    #[cfg(all(target_os = "linux", feature = "ebpf-detection"))]
    pub fn process_ebpf_events(&mut self) -> Result<Vec<DetectionResult>, GhostError> {
        if let Some(ref mut ebpf_detector) = self.ebpf_detector {
            match ebpf_detector.process_events() {
                Ok(ebpf_events) => {
                    let mut detection_results = Vec::new();

                    for ebpf_event in ebpf_events {
                        // Convert eBPF detection event to standard DetectionResult
                        let detection_result = DetectionResult {
                            process: ebpf_event.process_info,
                            threat_level: match ebpf_event.severity {
                                crate::ebpf::EventSeverity::Info => ThreatLevel::Clean,
                                crate::ebpf::EventSeverity::Low => ThreatLevel::Clean,
                                crate::ebpf::EventSeverity::Medium => ThreatLevel::Suspicious,
                                crate::ebpf::EventSeverity::High => ThreatLevel::Malicious,
                                crate::ebpf::EventSeverity::Critical => ThreatLevel::Malicious,
                            },
                            indicators: ebpf_event.indicators,
                            confidence: ebpf_event.confidence,
                            threat_context: None,
                            evasion_analysis: None,
                            mitre_analysis: None,
                        };

                        detection_results.push(detection_result);
                    }

                    Ok(detection_results)
                }
                Err(e) => {
                    log::error!("eBPF event processing error: {:?}", e);
                    Ok(Vec::new())
                }
            }
        } else {
            Ok(Vec::new())
        }
    }

    /// Get eBPF detector statistics (Linux only)
    #[cfg(all(target_os = "linux", feature = "ebpf-detection"))]
    pub fn get_ebpf_statistics(&self) -> Option<crate::ebpf::EbpfStatistics> {
        self.ebpf_detector
            .as_ref()
            .map(|detector| detector.get_statistics())
    }

    /// Check for suspicious memory patterns
    fn check_memory_patterns(
        &self,
        regions: &[MemoryRegion],
        indicators: &mut Vec<String>,
        _confidence: &mut f32,
    ) {
        // Look for small executable allocations (typical shellcode size)
        let small_exec = regions
            .iter()
            .filter(|r| {
                r.region_type == "PRIVATE"
                    && r.protection == MemoryProtection::ReadWriteExecute
                    &&
                r.size < 0x10000 // 64KB
            })
            .count();

        if small_exec >= 3 {
            indicators.push("Multiple small executable allocations".to_string());
            // Do not increase confidence by itself; JIT workloads commonly allocate many small
            // executable pages. Treat as supporting evidence only.
        }
    }

    /// Analyze thread patterns for injection indicators
    fn analyze_threads(
        &self,
        threads: &[ThreadInfo],
        regions: &[MemoryRegion],
        indicators: &mut Vec<String>,
        confidence: &mut f32,
    ) {
        // Flag threads that start executing from suspicious locations.
        // On modern OSes, module base addresses vary (ASLR), so fixed-range heuristics cause massive false positives.
        let mut private_exec_starts = 0usize;
        let mut unmapped_starts = 0usize;
        let mut private_non_exec_starts = 0usize;

        for t in threads {
            if t.start_address == 0 {
                continue;
            }

            let region = regions.iter().find(|r| {
                t.start_address >= r.base_address && t.start_address < r.base_address + r.size
            });

            match region {
                None => {
                    unmapped_starts += 1;
                }
                // Only treat non-executable *PRIVATE* starts as suspicious.
                // IMAGE-backed non-exec pages can appear due to guard/metadata regions and should not be flagged.
                Some(r) if r.region_type == "PRIVATE" && !r.protection.is_executable() => {
                    private_non_exec_starts += 1;
                }
                Some(r) if r.region_type == "PRIVATE" && r.protection.is_executable() => {
                    private_exec_starts += 1;
                }
                Some(_) => {}
            }
        }

        if private_exec_starts > 0 {
            indicators.push(format!(
                "{} thread(s) started in PRIVATE executable memory",
                private_exec_starts
            ));
            *confidence += 0.6;
        }

        if unmapped_starts > 0 {
            indicators.push(format!(
                "{} thread(s) started at unmapped addresses",
                unmapped_starts
            ));
            // Can happen with limited visibility; treat as a supporting signal.
            *confidence += 0.2;
        }

        if private_non_exec_starts > 0 {
            indicators.push(format!(
                "{} thread(s) started in non-executable PRIVATE memory",
                private_non_exec_starts
            ));
            // One-off cases can be measurement artifacts; require stronger corroboration elsewhere.
            *confidence += if private_non_exec_starts >= 2 { 0.25 } else { 0.1 };
        }
    }

    /// Scan memory regions for shellcode patterns
    fn scan_for_shellcode(
        &self,
        pid: u32,
        regions: &[MemoryRegion],
        threads: Option<&[ThreadInfo]>,
    ) -> Vec<crate::ShellcodeDetection> {
        use crate::memory::read_process_memory;

        let mut all_detections = Vec::new();

        for region in regions {
            // Only scan executable regions that might contain shellcode
            if matches!(
                region.protection,
                MemoryProtection::ReadExecute | MemoryProtection::ReadWriteExecute
            ) && region.region_type == "PRIVATE"
                && region.size < 0x100000
            {
                // Strongly prefer regions that are plausibly used for injected execution.
                // Many benign processes have private executable pages (e.g., JIT), but threads
                // typically start in IMAGE-backed code.
                let has_thread_start_in_region = threads.map_or(false, |thread_list| {
                    thread_list.iter().any(|t| {
                        t.start_address != 0
                            && t.start_address >= region.base_address
                            && t.start_address < region.base_address + region.size
                    })
                });

                if !has_thread_start_in_region {
                    continue;
                }

                // Read actual memory content from the process
                if let Ok(memory_data) = read_process_memory(pid, region.base_address, region.size)
                {
                    let detections = self
                        .shellcode_detector
                        .scan_memory_region(&memory_data, region.base_address);
                    all_detections.extend(detections);
                }
            }
        }

        all_detections
    }

    /// Perform comprehensive MITRE ATT&CK analysis
    pub async fn analyze_with_mitre(
        &self,
        process: &ProcessInfo,
        memory_regions: &[MemoryRegion],
        threads: &[ThreadInfo],
    ) -> Result<MitreAnalysisResult, GhostError> {
        self.mitre_engine
            .analyze_attack_patterns(process, memory_regions, threads)
            .await
    }

    /// Enrich detection result with MITRE ATT&CK analysis
    pub async fn enrich_with_mitre_analysis(
        &self,
        mut detection: DetectionResult,
        memory_regions: &[MemoryRegion],
        threads: &[ThreadInfo],
    ) -> DetectionResult {
        if let Ok(mitre_analysis) = self
            .mitre_engine
            .analyze_attack_patterns(&detection.process, memory_regions, threads)
            .await
        {
            // Update threat level based on MITRE analysis
            if mitre_analysis.risk_assessment.overall_risk_score > 0.8 {
                detection.threat_level = ThreatLevel::Malicious;
            } else if mitre_analysis.risk_assessment.overall_risk_score > 0.5
                && detection.threat_level == ThreatLevel::Clean
            {
                detection.threat_level = ThreatLevel::Suspicious;
            }

            // Add MITRE technique indicators
            for technique in &mitre_analysis.detected_techniques {
                detection.indicators.push(format!(
                    "MITRE {}: {} (confidence: {:.1}%)",
                    technique.technique.id,
                    technique.technique.name,
                    technique.confidence * 100.0
                ));
            }

            // Add threat actor matches
            for actor_match in &mitre_analysis.threat_actor_matches {
                detection.indicators.push(format!(
                    "Threat Actor Pattern: {} (match: {:.1}%)",
                    actor_match.threat_actor.name,
                    actor_match.match_confidence * 100.0
                ));
            }

            // Update confidence with MITRE insights
            detection.confidence =
                (detection.confidence + mitre_analysis.risk_assessment.overall_risk_score) / 2.0;
            detection.mitre_analysis = Some(mitre_analysis);
        }

        detection
    }

    pub fn get_mitre_stats(&self) -> (usize, usize, usize) {
        self.mitre_engine.get_framework_stats()
    }
}

impl Default for DetectionEngine {
    fn default() -> Self {
        // For Default trait, we need to provide a working instance.
        // If this fails, we'll have to panic as Default cannot return Error.
        Self::new().unwrap_or_else(|e| {
            panic!("Failed to create default DetectionEngine: {}", e);
        })
    }
}

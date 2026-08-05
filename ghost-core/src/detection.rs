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

        // Initialize YARA engine with the resolved rules directory
        let rules_dir = Self::resolve_rules_dir();
        let yara_engine = match DynamicYaraEngine::new(rules_dir.as_deref()) {
            Ok(engine) => {
                if engine.is_compiled() {
                    log::info!(
                        "YARA engine initialized with {} rules",
                        engine.get_rule_count()
                    );
                    Some(engine)
                } else {
                    log::warn!("YARA rules not compiled, engine disabled");
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

        // Check for RWX memory regions. Unbacked (MEM_PRIVATE) RWX is the
        // meaningful case: image-backed RWX sections exist in some legitimate
        // modules, while writable+executable private memory is where injected
        // code lives. JIT runtimes also allocate it, so this is a moderate
        // signal that needs corroboration - never a verdict on its own.
        let rwx_count = memory_regions
            .iter()
            .filter(|r| r.protection == MemoryProtection::ReadWriteExecute)
            .count();
        let unbacked_rwx = memory_regions
            .iter()
            .filter(|r| {
                r.protection == MemoryProtection::ReadWriteExecute && r.region_type == "PRIVATE"
            })
            .count();

        if unbacked_rwx > 0 {
            indicators.push(format!(
                "{} unbacked RWX memory regions detected",
                unbacked_rwx
            ));
            confidence += 0.35;
        } else if rwx_count > 0 {
            indicators.push(format!("{} image-backed RWX regions detected", rwx_count));
            confidence += 0.1;
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
            self.analyze_threads(
                thread_list,
                memory_regions,
                &mut indicators,
                &mut confidence,
            );
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
        // Matches are collapsed per signature: a single JIT region can
        // contain hundreds of hits for one pattern, and scoring each
        // occurrence separately was the source of both the 100+ indicator
        // lists and the runaway confidence.
        let shellcode_detections = self.scan_for_shellcode(process.pid, memory_regions);
        if !shellcode_detections.is_empty() {
            let mut by_signature: std::collections::BTreeMap<String, (usize, usize, f32)> =
                std::collections::BTreeMap::new();
            for detection in &shellcode_detections {
                for sig in &detection.signature_matches {
                    let entry = by_signature.entry(sig.clone()).or_insert((
                        0,
                        detection.address,
                        detection.confidence,
                    ));
                    entry.0 += 1;
                    entry.2 = entry.2.max(detection.confidence);
                }
            }

            let mut shellcode_score = 0.0f32;
            for (sig, (count, first_addr, conf)) in &by_signature {
                if *count < Self::min_occurrences_for(sig) {
                    continue;
                }
                indicators.push(format!(
                    "Shellcode signature '{}' matched {}x (first at {:#x})",
                    sig, count, first_addr
                ));
                shellcode_score += conf;
            }
            // Cap the whole category so pattern volume cannot dominate.
            confidence += shellcode_score.min(0.5);
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
                    log::info!(
                        "YARA scan found {} matches in {} ms",
                        yara_result.matches.len(),
                        yara_result.scan_time_ms
                    );

                    for yara_match in &yara_result.matches {
                        indicators.push(format!(
                            "YARA: {} matched at {:#x} (threat level: {:?})",
                            yara_match.rule_name, yara_match.offset, yara_match.threat_level
                        ));

                        // Adjust confidence based on threat level
                        let threat_boost = match yara_match.threat_level {
                            crate::yara_engine::ThreatLevel::Critical => 0.8,
                            crate::yara_engine::ThreatLevel::High => 0.6,
                            crate::yara_engine::ThreatLevel::Medium => 0.4,
                            crate::yara_engine::ThreatLevel::Low => 0.2,
                            crate::yara_engine::ThreatLevel::Info => 0.1,
                        };
                        confidence += threat_boost;
                    }
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
                rwx_regions: rwx_count,
            },
        );

        // Each indicator adds to the score, so a process with many of them
        // accumulates well past 1.0 - clamp before it is reported as a
        // percentage (unclamped scores rendered as e.g. "7679.2%").
        let confidence = confidence.clamp(0.0, 1.0);

        // Promotion gate: a verdict needs corroboration, not just volume.
        // Scoring alone let a pile of weak heuristics reach "Malicious",
        // which is how a clean desktop produced 187 malicious verdicts.
        // At least one high-confidence indicator must be present before a
        // process can be called malicious.
        let strong_signals = indicators
            .iter()
            .filter(|i| Self::is_strong_indicator(i))
            .count();

        let threat_level = if confidence >= 0.7 && strong_signals >= 1 {
            ThreatLevel::Malicious
        } else if confidence >= 0.3 || strong_signals >= 1 {
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
        confidence: &mut f32,
    ) {
        // Small executable allocations only mean something when the memory
        // is unbacked (MEM_PRIVATE). Without that filter every mapped DLL
        // contributed its own sub-64KB .text section, so any process with
        // three loaded modules tripped this.
        let small_unbacked_exec = regions
            .iter()
            .filter(|r| {
                r.region_type == "PRIVATE"
                    && r.size < 0x10000 // 64KB
                    && (r.protection == MemoryProtection::ReadExecute
                        || r.protection == MemoryProtection::ReadWriteExecute)
            })
            .count();

        // JIT runtimes (CLR, V8) legitimately produce a handful of small
        // private executable allocations, so require a meaningful cluster.
        if small_unbacked_exec >= 8 {
            indicators.push(format!(
                "{} small unbacked executable allocations",
                small_unbacked_exec
            ));
            *confidence += 0.15;
        }

        // NOTE: a "suspicious memory gaps" check used to live here, firing on
        // any 1-16MB gap between committed regions. That is the size of a
        // default thread stack reservation, so it matched essentially every
        // process. Gaps in the address space carry no injection signal.
    }

    /// Analyze thread patterns for injection indicators.
    ///
    /// The strongest user-mode injection signal available is a thread whose
    /// entry point lies in executable memory that is not backed by a mapped
    /// image (see Elastic's Get-InjectedThread research). Legitimate JIT
    /// runtimes place *code* in private executable memory but do not
    /// normally start *threads* there, which is what makes the start-address
    /// form of this test safe where a raw region test would not be.
    fn analyze_threads(
        &self,
        threads: &[ThreadInfo],
        regions: &[MemoryRegion],
        indicators: &mut Vec<String>,
        confidence: &mut f32,
    ) {
        let unbacked_start_threads = threads
            .iter()
            .filter(|t| {
                t.start_address != 0 && Self::is_unbacked_executable(regions, t.start_address)
            })
            .count();

        if unbacked_start_threads > 0 {
            indicators.push(format!(
                "{} thread(s) starting in unbacked executable memory",
                unbacked_start_threads
            ));
            *confidence += 0.6;
        }

        // NOTE: two checks used to live here and both fired on every process.
        // One tested `start_address & 0xFFFF_0000 != 0x7FF0_0000`, a 32-bit
        // era constant that no 64-bit address satisfies. The other counted
        // threads with `creation_time > 0` as "recently created", but that
        // field is an absolute FILETIME, so it is non-zero for every live
        // thread and the ratio was always 1.0.
    }

    /// Locates the YARA rules directory.
    ///
    /// The path used to be the bare relative literal "rules", so the engine
    /// silently disabled itself whenever ghost ran from any directory other
    /// than the source tree - which is every installed deployment. Look
    /// next to the executable first, then at an explicit override, then the
    /// working directory.
    fn resolve_rules_dir() -> Option<String> {
        if let Ok(dir) = std::env::var("GHOST_RULES_DIR") {
            if std::path::Path::new(&dir).is_dir() {
                return Some(dir);
            }
            log::warn!("GHOST_RULES_DIR is set but not a directory: {}", dir);
        }

        if let Ok(exe) = std::env::current_exe() {
            for base in exe.parent().into_iter().chain(
                exe.parent()
                    .and_then(|p| p.parent())
                    .and_then(|p| p.parent()),
            ) {
                let candidate = base.join("rules");
                if candidate.is_dir() {
                    return candidate.to_str().map(str::to_string);
                }
            }
        }

        if std::path::Path::new("rules").is_dir() {
            return Some("rules".to_string());
        }

        log::warn!(
            "No YARA rules directory found (set GHOST_RULES_DIR or place 'rules' \
             next to the executable); signature scanning is disabled"
        );
        None
    }

    /// How many times a signature must appear in one process before it is
    /// worth reporting.
    ///
    /// Some byte sequences are individually ordinary and only become
    /// meaningful in bulk. A single `mov r10,rcx ; mov eax,imm32` is the
    /// prologue of every ntdll stub and shows up in copied thunks and JIT
    /// output; a *table* of them in private memory is a generated syscall
    /// stub set, which is the thing worth flagging.
    fn min_occurrences_for(signature: &str) -> usize {
        match signature {
            "Direct Syscall Setup (x64)" => 3,
            "NOP Sled" => 2,
            _ => 1,
        }
    }

    /// Indicators that carry a low base rate on clean systems, and so are
    /// allowed to promote a process to a malicious verdict. Everything else
    /// is corroborating context only.
    fn is_strong_indicator(indicator: &str) -> bool {
        // These must match the indicator text produced above verbatim.
        const STRONG: &[&str] = &[
            "thread(s) starting in unbacked executable memory",
            "suspicious Windows hooks detected",
            "Main executable image appears unmapped",
        ];

        // Only high-specificity shellcode signatures may promote a verdict.
        // Generic ones (syscall prologues, NOP runs, stack setup) describe
        // shapes that ordinary code also has.
        const STRONG_SIGNATURES: &[&str] = &[
            "Metasploit",
            "Shikata Ga Nai",
            "ROR13",
            "Egg Hunter",
            "Cobalt",
            "Reflective",
        ];

        if indicator.starts_with("Shellcode signature") {
            return STRONG_SIGNATURES.iter().any(|s| indicator.contains(s));
        }

        STRONG.iter().any(|s| indicator.contains(s))
    }

    /// True when `address` falls inside a committed, executable region that
    /// is not backed by a mapped image or file.
    fn is_unbacked_executable(regions: &[MemoryRegion], address: usize) -> bool {
        regions.iter().any(|r| {
            address >= r.base_address
                && address < r.base_address.saturating_add(r.size)
                && r.region_type == "PRIVATE"
                && r.protection.is_executable()
        })
    }

    /// Scan memory regions for shellcode patterns
    fn scan_for_shellcode(
        &self,
        pid: u32,
        regions: &[MemoryRegion],
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

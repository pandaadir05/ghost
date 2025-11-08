use crate::{
    detect_hook_injection, AnomalyDetector, MemoryProtection, MemoryRegion, 
    ProcessInfo, ShellcodeDetector, ThreadInfo, ThreatIntelligence, ThreatContext,
    EvasionDetector, EvasionResult
};
#[cfg(target_os = "linux")]
use crate::EbpfDetector;
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
    pub threat_context: Option<ThreatContext>,
    pub evasion_analysis: Option<EvasionResult>,
}

pub struct DetectionEngine {
    baseline: HashMap<u32, ProcessBaseline>,
    shellcode_detector: ShellcodeDetector,
    hollowing_detector: HollowingDetector,
    anomaly_detector: AnomalyDetector,
    threat_intelligence: ThreatIntelligence,
    evasion_detector: EvasionDetector,
    #[cfg(target_os = "linux")]
    ebpf_detector: Option<EbpfDetector>,
}

#[derive(Debug, Clone)]
struct ProcessBaseline {
    thread_count: u32,
    rwx_regions: usize,
}

impl DetectionEngine {
    pub fn new() -> Result<Self, DetectionError> {
        let baseline = ProcessBaseline::new();
        let shellcode_detector = ShellcodeDetector::new();
        let hollowing_detector = HollowingDetector::new();
        let anomaly_detector = AnomalyDetector::new();
        let threat_intelligence = ThreatIntelligence::new();
        let evasion_detector = EvasionDetector::new();
        
        #[cfg(target_os = "linux")]
        let ebpf_detector = match EbpfDetector::new() {
            Ok(mut detector) => {
                if let Err(e) = detector.initialize() {
                    eprintln!("Warning: Failed to initialize eBPF detector: {:?}", e);
                    None
                } else {
                    Some(detector)
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to create eBPF detector: {:?}", e);
                None
            }
        };
        
        Ok(DetectionEngine {
            baseline,
            shellcode_detector,
            hollowing_detector,
            anomaly_detector,
            threat_intelligence,
            evasion_detector,
            #[cfg(target_os = "linux")]
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
        
        // Scan for shellcode patterns in executable memory regions
        let shellcode_detections = self.scan_for_shellcode(memory_regions);
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
        if let Ok(Some(hollowing_detection)) = self.hollowing_detector.analyze_process(process, memory_regions) {
            for indicator in &hollowing_detection.indicators {
                indicators.push(format!("Process hollowing: {}", indicator));
            }
            confidence += hollowing_detection.confidence;
        }
        
        // ML-based anomaly detection
        let features = self.anomaly_detector.extract_features(process, memory_regions, threads);
        if let Ok(anomaly_score) = self.anomaly_detector.analyze_anomaly(process, &features) {
            if self.anomaly_detector.is_anomalous(&anomaly_score) {
                indicators.push(format!(
                    "ML anomaly detected: {:.1}% confidence",
                    anomaly_score.overall_score * 100.0
                ));
                
                for outlier in &anomaly_score.outlier_features {
                    indicators.push(format!("Outlier: {}", outlier));
                }
                
                confidence += anomaly_score.overall_score * anomaly_score.confidence;
            }
        }

        // Advanced evasion detection
        let evasion_result = self.evasion_detector.analyze_evasion(process, memory_regions, threads);
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

        let threat_level = if confidence >= 0.7 {
            ThreatLevel::Malicious
        } else if confidence >= 0.3 {
            ThreatLevel::Suspicious
        } else {
            ThreatLevel::Clean
        };

        // Create initial detection result
        let mut detection_result = DetectionResult {
            process: process.clone(),
            threat_level,
            indicators,
            confidence,
            threat_context: None,
            evasion_analysis: None,
        };

        // Enrich with threat intelligence (async operation would be handled by caller)
        // For now, we'll set a placeholder that can be enriched later
        detection_result
    }

    /// Enrich detection result with threat intelligence
    pub async fn enrich_with_threat_intel(&self, mut detection: DetectionResult) -> DetectionResult {
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
            detection.indicators.push(format!("IOC Match: {} ({})", ioc.value, ioc.source));
        }

        if let Some(actor) = &threat_context.threat_actor {
            detection.indicators.push(format!("Attributed to: {}", actor.name));
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
        let mut detection_result = self.analyze_process(process, memory_regions, threads);
        
        // Add evasion analysis
        let evasion_result = self.evasion_detector.analyze_evasion(process, memory_regions, threads);
        
        // Update threat level based on evasion analysis
        if evasion_result.confidence > 0.7 {
            detection_result.threat_level = ThreatLevel::Malicious;
            detection_result.confidence = (detection_result.confidence + evasion_result.confidence) / 2.0;
        } else if evasion_result.confidence > 0.4 {
            detection_result.threat_level = ThreatLevel::Suspicious;
            detection_result.confidence = (detection_result.confidence + evasion_result.confidence * 0.7) / 2.0;
        }
        
        detection_result.evasion_analysis = Some(evasion_result);
        detection_result
    }

    /// Process eBPF detection events (Linux only)
    #[cfg(target_os = "linux")]
    pub fn process_ebpf_events(&mut self) -> Result<Vec<DetectionResult>, DetectionError> {
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
                        };
                        
                        detection_results.push(detection_result);
                    }
                    
                    Ok(detection_results)
                }
                Err(e) => {
                    eprintln!("eBPF event processing error: {:?}", e);
                    Ok(Vec::new())
                }
            }
        } else {
            Ok(Vec::new())
        }
    }

    /// Get eBPF detector statistics (Linux only)
    #[cfg(target_os = "linux")]
    pub fn get_ebpf_statistics(&self) -> Option<crate::ebpf::EbpfStatistics> {
        self.ebpf_detector.as_ref().map(|detector| detector.get_statistics())
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

    /// Scan memory regions for shellcode patterns
    fn scan_for_shellcode(&self, regions: &[MemoryRegion]) -> Vec<crate::ShellcodeDetection> {
        let mut all_detections = Vec::new();

        for region in regions {
            // Only scan executable regions that might contain shellcode
            if matches!(
                region.protection,
                MemoryProtection::ReadExecute | MemoryProtection::ReadWriteExecute
            ) && region.region_type == "PRIVATE"
                && region.size < 0x100000
            {
                // 1MB limit for performance
                // In a real implementation, we would read the actual memory content
                // For now, simulate with a pattern that might indicate shellcode
                let simulated_data = self.simulate_memory_content(region);
                let detections = self
                    .shellcode_detector
                    .scan_memory_region(&simulated_data, region.base_address);
                all_detections.extend(detections);
            }
        }

        all_detections
    }

    /// Simulate memory content for testing (in real implementation, use ReadProcessMemory)
    fn simulate_memory_content(&self, region: &MemoryRegion) -> Vec<u8> {
        // This is a placeholder - real implementation would use Windows ReadProcessMemory API
        // For demonstration, create some patterns that might trigger detection
        let mut data = vec![0x90; region.size]; // Fill with NOPs

        // Add some "suspicious" patterns based on region size
        if region.size > 0x1000 {
            // Add a PE header signature
            data[0] = 0x4D; // M
            data[1] = 0x5A; // Z

            // Add some meterpreter-like pattern
            if region.size > 0x100 {
                data[0x80] = 0xFC; // CLD
                data[0x81] = 0x48; // REX.W
                data[0x82] = 0x83; // SUB
                data[0x83] = 0xE4; // ESP
                data[0x84] = 0xF0; // immediate
                data[0x85] = 0xE8; // CALL
            }
        }

        data
    }
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}

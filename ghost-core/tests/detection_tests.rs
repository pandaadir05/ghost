//! Integration tests for Ghost detection engine.

#[cfg(test)]
mod tests {
    use ghost_core::{
        config::DetectionConfig, DetectionEngine, MemoryProtection, MemoryRegion, ProcessInfo,
        ThreatLevel,
    };

    fn create_test_process() -> ProcessInfo {
        ProcessInfo {
            pid: 1234,
            ppid: 4,
            name: "test.exe".to_string(),
            path: Some("C:\\Windows\\System32\\test.exe".to_string()),
            thread_count: 1,
        }
    }

    fn create_rwx_region() -> MemoryRegion {
        MemoryRegion {
            base_address: 0x10000000,
            size: 0x1000,
            protection: MemoryProtection::ReadWriteExecute,
            region_type: "PRIVATE".to_string(),
        }
    }

    #[test]
    fn test_rwx_region_detection() {
        let mut engine = DetectionEngine::new().expect("Failed to create engine");
        let process = create_test_process();
        let regions = vec![create_rwx_region()];

        let result = engine.analyze_process(&process, &regions, None);
        assert_ne!(result.threat_level, ThreatLevel::Clean);
        assert!(!result.indicators.is_empty());
        assert!(result.indicators[0].contains("RWX"));
    }

    /// `DetectionConfig` used to be stored in a field named `_config` and
    /// never read, so every toggle a user set was silently ignored.
    #[test]
    fn test_detector_toggles_are_honored() {
        let process = create_test_process();
        let regions = small_private_exec_regions(12);

        let disabled = DetectionConfig {
            shellcode_detection: false,
            hollowing_detection: false,
            hook_detection: false,
            thread_analysis_enabled: false,
            ..Default::default()
        };
        let mut engine =
            DetectionEngine::with_config(Some(disabled)).expect("Failed to create engine");
        let result = engine.analyze_process(&process, &regions, None);

        assert!(
            !result
                .indicators
                .iter()
                .any(|i| i.contains("Process hollowing") || i.contains("Shellcode signature")),
            "disabled detectors must not contribute indicators, got: {:?}",
            result.indicators
        );
    }

    /// A stricter confidence threshold must not make verdicts harsher.
    #[test]
    fn test_lower_threshold_does_not_create_malicious_verdicts() {
        let process = create_test_process();
        let mut regions = vec![MemoryRegion {
            base_address: 0x7FF6_0000_0000,
            size: 0x10_0000,
            protection: MemoryProtection::ReadExecute,
            region_type: "IMAGE".to_string(),
        }];
        regions.extend(small_private_exec_regions(12));

        let sensitive = DetectionConfig {
            confidence_threshold: 0.05,
            ..Default::default()
        };
        let mut engine =
            DetectionEngine::with_config(Some(sensitive)).expect("Failed to create engine");
        let result = engine.analyze_process(&process, &regions, None);

        assert_ne!(
            result.threat_level,
            ThreatLevel::Malicious,
            "a lower threshold should surface more for triage, not promote to Malicious"
        );
    }

    /// Regression guard for the false-positive flood.
    ///
    /// A clean-system scan once returned 187 of ~330 processes as Malicious
    /// at 100% confidence because weak heuristics accumulated past the
    /// threshold with nothing corroborating them. Memory-shape signals alone
    /// must never reach a Malicious verdict.
    #[test]
    fn test_weak_signals_alone_never_reach_malicious() {
        let mut engine = DetectionEngine::new().expect("Failed to create engine");
        let process = create_test_process();

        // A normally mapped main image, as every real process has.
        let mut regions = vec![MemoryRegion {
            base_address: 0x7FF6_0000_0000,
            size: 0x10_0000,
            protection: MemoryProtection::ReadExecute,
            region_type: "IMAGE".to_string(),
        }];

        // Pile on every weak memory signal at once: many RWX regions plus a
        // large cluster of small private executable allocations - the shape
        // a JIT-heavy process (browser, .NET host) legitimately produces.
        regions.extend((0..12).map(|i| MemoryRegion {
            base_address: 0x5000_0000 + i * 0x10_0000,
            size: 0x2000,
            protection: MemoryProtection::ReadWriteExecute,
            region_type: "PRIVATE".to_string(),
        }));
        regions.extend(small_private_exec_regions(12));

        let result = engine.analyze_process(&process, &regions, None);

        assert_ne!(
            result.threat_level,
            ThreatLevel::Malicious,
            "weak signals alone must not produce a Malicious verdict, got {:?} at {} with {:?}",
            result.threat_level,
            result.confidence,
            result.indicators
        );
    }

    /// Confidence is a probability and must stay in range; it was once
    /// reported to users as values like "7679.2%".
    #[test]
    fn test_confidence_never_exceeds_one() {
        let mut engine = DetectionEngine::new().expect("Failed to create engine");
        let process = create_test_process();
        let mut regions = small_private_exec_regions(40);
        regions.extend((0..40).map(|i| MemoryRegion {
            base_address: 0x9000_0000 + i * 0x10_0000,
            size: 0x1000,
            protection: MemoryProtection::ReadWriteExecute,
            region_type: "PRIVATE".to_string(),
        }));

        let result = engine.analyze_process(&process, &regions, None);

        assert!(
            (0.0..=1.0).contains(&result.confidence),
            "confidence out of range: {}",
            result.confidence
        );
    }

    /// Builds `count` small private executable regions at distinct addresses.
    fn small_private_exec_regions(count: usize) -> Vec<MemoryRegion> {
        (0..count)
            .map(|i| MemoryRegion {
                base_address: 0x1000_0000 + i * 0x1000_0000,
                size: 0x800, // well under the 64KB "small" cutoff
                protection: MemoryProtection::ReadExecute,
                region_type: "PRIVATE".to_string(),
            })
            .collect()
    }

    /// A handful of small private executable allocations is what a JIT
    /// runtime produces during normal operation, so it must not raise the
    /// indicator on its own.
    #[test]
    fn test_few_small_executable_regions_not_flagged() {
        let mut engine = DetectionEngine::new().expect("Failed to create engine");
        let process = create_test_process();

        let result = engine.analyze_process(&process, &small_private_exec_regions(3), None);

        assert!(
            !result
                .indicators
                .iter()
                .any(|i| i.contains("small unbacked executable")),
            "3 small private regions is JIT-normal and must not be flagged, got: {:?}",
            result.indicators
        );
    }

    /// A larger cluster is not explained by ordinary JIT behaviour.
    #[test]
    fn test_many_small_executable_regions_flagged() {
        let mut engine = DetectionEngine::new().expect("Failed to create engine");
        let process = create_test_process();

        let result = engine.analyze_process(&process, &small_private_exec_regions(10), None);

        assert!(result.confidence > 0.0);
        assert!(
            result
                .indicators
                .iter()
                .any(|i| i.contains("small unbacked executable")),
            "10 small private regions should be flagged, got: {:?}",
            result.indicators
        );
    }

    /// Image-backed regions are ordinary loaded modules: every DLL has a
    /// sub-64KB .text section, so counting them was the original defect.
    #[test]
    fn test_small_image_backed_regions_not_flagged() {
        let mut engine = DetectionEngine::new().expect("Failed to create engine");
        let process = create_test_process();
        let regions: Vec<MemoryRegion> = small_private_exec_regions(20)
            .into_iter()
            .map(|mut r| {
                r.region_type = "IMAGE".to_string();
                r
            })
            .collect();

        let result = engine.analyze_process(&process, &regions, None);

        assert!(
            !result
                .indicators
                .iter()
                .any(|i| i.contains("small unbacked executable")),
            "image-backed regions are loaded modules, got: {:?}",
            result.indicators
        );
    }

    #[test]
    fn test_multiple_rwx_regions_high_severity() {
        let mut engine = DetectionEngine::new().expect("Failed to create engine");
        let process = create_test_process();
        let regions = vec![
            MemoryRegion {
                base_address: 0x10000000,
                size: 0x1000,
                protection: MemoryProtection::ReadWriteExecute,
                region_type: "PRIVATE".to_string(),
            },
            MemoryRegion {
                base_address: 0x20000000,
                size: 0x2000,
                protection: MemoryProtection::ReadWriteExecute,
                region_type: "PRIVATE".to_string(),
            },
            MemoryRegion {
                base_address: 0x30000000,
                size: 0x3000,
                protection: MemoryProtection::ReadWriteExecute,
                region_type: "PRIVATE".to_string(),
            },
        ];

        let result = engine.analyze_process(&process, &regions, None);
        // Multiple unbacked RWX regions are worth surfacing, but they are
        // also what a JIT runtime (browser, .NET host) produces during
        // normal operation. This used to assert Malicious, which is how a
        // clean desktop ended up with 187 malicious verdicts. Memory shape
        // alone tops out at Suspicious; promotion needs a corroborating
        // signal such as a thread starting in unbacked memory.
        assert_eq!(result.threat_level, ThreatLevel::Suspicious);
        assert!(result.confidence >= 0.5);
    }

    #[test]
    fn test_memory_protection_display() {
        assert_eq!(format!("{}", MemoryProtection::NoAccess), "---");
        assert_eq!(format!("{}", MemoryProtection::ReadOnly), "R--");
        assert_eq!(format!("{}", MemoryProtection::ReadWrite), "RW-");
        assert_eq!(format!("{}", MemoryProtection::ReadExecute), "R-X");
        assert_eq!(format!("{}", MemoryProtection::ReadWriteExecute), "RWX");
        assert_eq!(format!("{}", MemoryProtection::Execute), "--X");
    }

    #[test]
    fn test_process_info_display() {
        let process = create_test_process();
        let display = format!("{}", process);
        assert!(display.contains("1234"));
        assert!(display.contains("test.exe"));
    }

    #[test]
    fn test_memory_region_display() {
        let region = create_rwx_region();
        let display = format!("{}", region);
        assert!(display.contains("RWX"));
        assert!(display.contains("PRIVATE"));
    }

    #[test]
    fn test_threat_level_ordering() {
        assert!(ThreatLevel::Clean < ThreatLevel::Suspicious);
        assert!(ThreatLevel::Suspicious < ThreatLevel::Malicious);
    }

    #[test]
    fn test_detection_config_validation() {
        let config = DetectionConfig::default();
        assert!(config.validate().is_ok());

        let mut invalid_config = DetectionConfig {
            confidence_threshold: 1.5, // Invalid
            ..Default::default()
        };
        assert!(invalid_config.validate().is_err());

        invalid_config.confidence_threshold = -0.1; // Invalid
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_process_is_system_process() {
        let mut process = create_test_process();
        assert!(!process.is_system_process());

        process.pid = 0;
        assert!(process.is_system_process());

        process.pid = 4;
        assert!(process.is_system_process());

        process.pid = 100;
        process.name = "System".to_string();
        assert!(process.is_system_process());
    }

    #[test]
    fn test_engine_with_custom_config() {
        let config = DetectionConfig {
            hook_detection: false,
            ..Default::default()
        };

        let mut engine =
            DetectionEngine::with_config(Some(config)).expect("Failed to create engine");
        let process = create_test_process();
        let regions = vec![create_rwx_region()];

        // Engine should still detect RWX regions even with hook detection disabled
        let result = engine.analyze_process(&process, &regions, None);
        assert_ne!(result.threat_level, ThreatLevel::Clean);
    }

    #[test]
    fn test_large_memory_region() {
        let mut engine = DetectionEngine::new().expect("Failed to create engine");
        let process = create_test_process();
        let regions = vec![MemoryRegion {
            base_address: 0x10000000,
            size: 100 * 1024 * 1024, // 100MB region
            protection: MemoryProtection::ReadWriteExecute,
            region_type: "PRIVATE".to_string(),
        }];

        let result = engine.analyze_process(&process, &regions, None);
        assert_ne!(result.threat_level, ThreatLevel::Clean);
    }

    #[test]
    fn test_image_vs_private_region() {
        let mut engine = DetectionEngine::new().expect("Failed to create engine");
        let process = create_test_process();

        // IMAGE region with RX is normal - should not trigger high severity alerts
        let image_regions = vec![MemoryRegion {
            base_address: 0x400000,
            size: 0x10000, // Smaller, more realistic size
            protection: MemoryProtection::ReadExecute,
            region_type: "IMAGE".to_string(),
        }];

        let result = engine.analyze_process(&process, &image_regions, None);
        // IMAGE regions may trigger ML heuristics, but should not be flagged as Malicious
        assert_ne!(
            result.threat_level,
            ThreatLevel::Malicious,
            "IMAGE region should not be malicious"
        );

        // PRIVATE region with RWX is highly suspicious
        let private_regions = vec![MemoryRegion {
            base_address: 0x10000000,
            size: 0x1000,
            protection: MemoryProtection::ReadWriteExecute,
            region_type: "PRIVATE".to_string(),
        }];

        let result2 = engine.analyze_process(&process, &private_regions, None);
        assert_ne!(
            result2.threat_level,
            ThreatLevel::Clean,
            "RWX private region should be suspicious"
        );
        assert!(
            result2.confidence > 0.3,
            "RWX private region should have high confidence"
        );
    }
}

#[cfg(test)]
mod mitre_tests {
    use ghost_core::MitreAttackEngine;

    #[test]
    fn test_mitre_engine_creation() {
        let engine = MitreAttackEngine::new();
        assert!(engine.is_ok());
    }

    #[test]
    fn test_mitre_framework_stats() {
        let engine = MitreAttackEngine::new().expect("Failed to create MITRE engine");
        let (techniques, tactics, actors) = engine.get_framework_stats();
        assert!(techniques > 0);
        assert!(tactics > 0);
        assert!(actors > 0);
    }

    #[test]
    fn test_technique_lookup() {
        let engine = MitreAttackEngine::new().expect("Failed to create MITRE engine");
        let technique = engine.get_technique("T1055");
        assert!(technique.is_some());
        if let Some(tech) = technique {
            assert_eq!(tech.id, "T1055");
            assert_eq!(tech.name, "Process Injection");
        }
    }
}

#[cfg(test)]
mod threat_intel_tests {
    use ghost_core::ThreatLevel;

    #[test]
    fn test_threat_level_description() {
        assert_eq!(ThreatLevel::Clean.description(), "No threats detected");
        assert_eq!(
            ThreatLevel::Suspicious.description(),
            "Potential security concern"
        );
        assert_eq!(
            ThreatLevel::Malicious.description(),
            "High confidence malicious activity"
        );
    }

    #[test]
    fn test_threat_level_serialization() {
        let level = ThreatLevel::Suspicious;
        let serialized = serde_json::to_string(&level).expect("Failed to serialize");
        assert!(serialized.contains("Suspicious"));

        let deserialized: ThreatLevel =
            serde_json::from_str(&serialized).expect("Failed to deserialize");
        assert_eq!(deserialized, level);
    }
}

#[cfg(test)]
mod config_tests {
    use ghost_core::config::DetectionConfig;

    #[test]
    fn test_default_config() {
        let config = DetectionConfig::default();
        assert!(config.shellcode_detection);
        assert!(config.hollowing_detection);
        assert!(config.thread_analysis_enabled);
        assert!(config.hook_detection);
    }

    #[test]
    fn test_config_serialization() {
        let config = DetectionConfig::default();
        let json = serde_json::to_string(&config).expect("Failed to serialize");
        let deserialized: DetectionConfig =
            serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(config.hook_detection, deserialized.hook_detection);
    }

    #[test]
    fn test_config_toml_format() {
        let config = DetectionConfig::default();
        let toml_str = toml::to_string(&config).expect("Failed to serialize to TOML");
        assert!(toml_str.contains("shellcode_detection"));
        assert!(toml_str.contains("confidence_threshold"));
    }
}

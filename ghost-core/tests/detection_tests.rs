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

    #[test]
    fn test_multiple_small_executable_regions() {
        let mut engine = DetectionEngine::new().expect("Failed to create engine");
        let process = create_test_process();
        let regions = vec![
            MemoryRegion {
                base_address: 0x10000000,
                size: 0x800, // Small size
                protection: MemoryProtection::ReadExecute,
                region_type: "PRIVATE".to_string(),
            },
            MemoryRegion {
                base_address: 0x20000000,
                size: 0x600, // Small size
                protection: MemoryProtection::ReadExecute,
                region_type: "PRIVATE".to_string(),
            },
            MemoryRegion {
                base_address: 0x30000000,
                size: 0x400, // Small size
                protection: MemoryProtection::ReadExecute,
                region_type: "PRIVATE".to_string(),
            },
        ];

        let result = engine.analyze_process(&process, &regions, None);
        assert!(result.confidence > 0.0);
        assert!(result
            .indicators
            .iter()
            .any(|i| i.contains("small executable")));
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
        // Multiple RWX regions should be highly suspicious
        assert_eq!(result.threat_level, ThreatLevel::Malicious);
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

        let mut invalid_config = DetectionConfig::default();
        invalid_config.confidence_threshold = 1.5; // Invalid
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
        let mut config = DetectionConfig::default();
        config.hook_detection = false;

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

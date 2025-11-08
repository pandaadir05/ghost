#[cfg(test)]
mod tests {
    use ghost_core::{DetectionEngine, MemoryProtection, MemoryRegion, ProcessInfo, ThreatLevel};

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
    fn test_clean_process_detection() {
        let mut engine = DetectionEngine::new();
        let process = create_test_process();
        let regions = vec![MemoryRegion {
            base_address: 0x400000,
            size: 0x10000,
            protection: MemoryProtection::ReadExecute,
            region_type: "IMAGE".to_string(),
        }];

        let result = engine.analyze_process(&process, &regions, None);
        assert_eq!(result.threat_level, ThreatLevel::Clean);
        assert!(result.indicators.is_empty());
    }

    #[test]
    fn test_rwx_region_detection() {
        let mut engine = DetectionEngine::new();
        let process = create_test_process();
        let regions = vec![create_rwx_region()];

        let result = engine.analyze_process(&process, &regions, None);
        assert_ne!(result.threat_level, ThreatLevel::Clean);
        assert!(!result.indicators.is_empty());
        assert!(result.indicators[0].contains("RWX"));
    }

    #[test]
    fn test_multiple_small_executable_regions() {
        let mut engine = DetectionEngine::new();
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
    fn test_baseline_tracking() {
        let mut engine = DetectionEngine::new();
        let mut process = create_test_process();
        let regions = vec![];

        // First scan establishes baseline
        let result1 = engine.analyze_process(&process, &regions, None);
        assert_eq!(result1.threat_level, ThreatLevel::Clean);

        // Second scan with increased thread count
        process.thread_count = 5;
        let result2 = engine.analyze_process(&process, &regions, None);
        assert!(result2
            .indicators
            .iter()
            .any(|i| i.contains("new threads")));
    }
}
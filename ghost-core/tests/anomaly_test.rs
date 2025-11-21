use ghost_core::{AnomalyDetector, MemoryProtection, MemoryRegion, ProcessInfo};
use std::path::PathBuf;

#[test]
fn test_anomaly_detector_creation() {
    let detector = AnomalyDetector::new();
    assert!(detector.get_all_profiles().is_empty());
}

#[test]
fn test_feature_extraction() {
    let detector = AnomalyDetector::new();

    let process = ProcessInfo {
        pid: 1234,
        ppid: 1,
        name: "test_process".to_string(),
        path: Some("/usr/bin/test".to_string()),
        thread_count: 5,
    };

    let regions = vec![
        MemoryRegion {
            base_address: 0x1000,
            size: 4096,
            protection: MemoryProtection::ReadExecute,
            region_type: "IMAGE".to_string(),
        },
        MemoryRegion {
            base_address: 0x2000,
            size: 8192,
            protection: MemoryProtection::ReadWrite,
            region_type: "PRIVATE".to_string(),
        },
    ];

    let features = detector.extract_features(&process, &regions, None);

    assert_eq!(features.pid, 1234);
    assert_eq!(features.memory_regions, 2);
    assert_eq!(features.executable_regions, 1);
}

#[test]
fn test_anomaly_analysis() {
    let mut detector = AnomalyDetector::new();

    let process = ProcessInfo {
        pid: 1234,
        ppid: 1,
        name: "test_process".to_string(),
        path: Some("/usr/bin/test".to_string()),
        thread_count: 5,
    };

    let regions = vec![MemoryRegion {
        base_address: 0x1000,
        size: 4096,
        protection: MemoryProtection::ReadExecute,
        region_type: "IMAGE".to_string(),
    }];

    let features = detector.extract_features(&process, &regions, None);

    let result = detector.analyze_anomaly(&process, &features);
    assert!(result.is_ok());

    let score = result.unwrap();
    assert!(score.overall_score >= 0.0 && score.overall_score <= 1.0);
    assert!(score.confidence >= 0.0 && score.confidence <= 1.0);
}

#[test]
fn test_profile_persistence() {
    let mut detector = AnomalyDetector::new();

    let process = ProcessInfo {
        pid: 1234,
        ppid: 1,
        name: "test_process".to_string(),
        path: Some("/usr/bin/test".to_string()),
        thread_count: 5,
    };

    let regions = vec![MemoryRegion {
        base_address: 0x1000,
        size: 4096,
        protection: MemoryProtection::ReadExecute,
        region_type: "IMAGE".to_string(),
    }];

    for _ in 0..15 {
        let features = detector.extract_features(&process, &regions, None);
        let _ = detector.analyze_anomaly(&process, &features);
    }

    let temp_path = PathBuf::from("/tmp/ghost_test_profiles.json");

    let save_result = detector.save_profiles(&temp_path);
    assert!(
        save_result.is_ok(),
        "Failed to save profiles: {:?}",
        save_result.err()
    );

    let mut detector2 = AnomalyDetector::new();
    let load_result = detector2.load_profiles(&temp_path);
    assert!(
        load_result.is_ok(),
        "Failed to load profiles: {:?}",
        load_result.err()
    );

    assert!(!detector2.get_all_profiles().is_empty());

    let _ = std::fs::remove_file(temp_path);
}

#[test]
fn test_global_baseline_computation() {
    let mut detector = AnomalyDetector::new();

    for i in 0..3 {
        let process = ProcessInfo {
            pid: 1000 + i,
            ppid: 1,
            name: format!("process_{}", i),
            path: Some(format!("/usr/bin/process_{}", i)),
            thread_count: 5,
        };

        let regions = vec![MemoryRegion {
            base_address: 0x1000,
            size: 4096,
            protection: MemoryProtection::ReadExecute,
            region_type: "IMAGE".to_string(),
        }];

        for _ in 0..15 {
            let features = detector.extract_features(&process, &regions, None);
            let _ = detector.analyze_anomaly(&process, &features);
        }
    }

    detector.compute_global_baseline();

    assert_eq!(detector.get_all_profiles().len(), 3);
}

#[test]
fn test_profile_cleanup() {
    let mut detector = AnomalyDetector::new();

    let process = ProcessInfo {
        pid: 1234,
        ppid: 1,
        name: "test_process".to_string(),
        path: Some("/usr/bin/test".to_string()),
        thread_count: 5,
    };

    let regions = vec![MemoryRegion {
        base_address: 0x1000,
        size: 4096,
        protection: MemoryProtection::ReadExecute,
        region_type: "IMAGE".to_string(),
    }];

    for _ in 0..15 {
        let features = detector.extract_features(&process, &regions, None);
        let _ = detector.analyze_anomaly(&process, &features);
    }

    assert_eq!(detector.get_all_profiles().len(), 1);

    detector.cleanup_old_profiles(0);

    assert_eq!(detector.get_all_profiles().len(), 0);
}

#[test]
fn test_nan_guards() {
    let mut detector = AnomalyDetector::new();

    let process = ProcessInfo {
        pid: 1234,
        ppid: 1,
        name: "test_process".to_string(),
        path: Some("/usr/bin/test".to_string()),
        thread_count: 5,
    };

    let regions = vec![];

    let features = detector.extract_features(&process, &regions, None);
    let result = detector.analyze_anomaly(&process, &features);

    assert!(result.is_ok());
    let score = result.unwrap();
    assert!(score.overall_score.is_finite());
    assert!(score.confidence.is_finite());
}

use ghost_core::{DetectionEngine, MemoryProtection, MemoryRegion, ProcessInfo, ThreadInfo};
use ghost_core::thread::ThreadState;

#[test]
fn system_pids_do_not_report_hollowing_when_memory_unknown() {
    let mut engine = DetectionEngine::new().expect("engine init");

    // PID 4 is the Windows System process. Our memory enumerator intentionally returns no regions,
    // and we should not treat that as "hollowing".
    let process = ProcessInfo {
        pid: 4,
        ppid: 0,
        name: "System".to_string(),
        path: None,
        thread_count: 0,
    };

    let result = engine.analyze_process(&process, &[], None);

    assert!(
        !result
            .indicators
            .iter()
            .any(|s| s.to_lowercase().contains("hollowing")),
        "unexpected hollowing indicator(s): {:?}",
        result.indicators
    );
}

#[test]
fn execute_writecopy_is_treated_as_executable() {
    // Regression test: PAGE_EXECUTE_WRITECOPY must be executable.
    assert!(MemoryProtection::ExecuteWriteCopy.is_executable());
    assert!(MemoryProtection::ExecuteWriteCopy.is_readable());
    assert!(MemoryProtection::ExecuteWriteCopy.is_writable());
}

#[test]
fn thread_start_in_non_exec_image_region_is_not_flagged_as_private_non_exec() {
    let mut engine = DetectionEngine::new().expect("engine init");

    let process = ProcessInfo::new(1234, 0, "benign.exe".to_string());

    let regions = vec![MemoryRegion {
        base_address: 0x1000,
        size: 0x1000,
        protection: MemoryProtection::ReadOnly,
        region_type: "IMAGE".to_string(),
    }];

    let threads = vec![ThreadInfo {
        tid: 1,
        owner_pid: process.pid,
        start_address: 0x1800,
        creation_time: 0,
        state: ThreadState::Running,
    }];

    let result = engine.analyze_process(&process, &regions, Some(&threads));

    assert!(
        !result
            .indicators
            .iter()
            .any(|s| s.contains("non-executable PRIVATE")),
        "unexpected indicator(s): {:?}",
        result.indicators
    );
}

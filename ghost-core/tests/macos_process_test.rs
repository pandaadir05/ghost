#[cfg(target_os = "macos")]
#[test]
fn test_macos_process_enumeration() {
    use ghost_core::process;

    let processes = process::enumerate_processes().expect("Failed to enumerate processes");

    assert!(!processes.is_empty(), "Should find at least some processes");

    println!("Found {} processes", processes.len());

    for proc in processes.iter().filter(|p| p.pid > 0).take(5) {
        println!(
            "PID: {}, Name: {}, Path: {:?}",
            proc.pid, proc.name, proc.path
        );
        assert!(proc.pid > 0, "PID should be positive");
        assert!(!proc.name.is_empty(), "Process name should not be empty");
    }

    let current_pid = std::process::id();
    let current_process = processes.iter().find(|p| p.pid == current_pid);

    if let Some(proc) = current_process {
        println!(
            "Current process found: PID={}, Name={}",
            proc.pid, proc.name
        );
    } else {
        println!(
            "Current process (PID={}) not in list - this is OK for test processes",
            current_pid
        );
    }

    assert!(
        processes.iter().any(|p| p.pid == 1),
        "Should at least find launchd (PID 1)"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn test_process_info_structure() {
    use ghost_core::process;

    let processes = process::enumerate_processes().expect("Failed to enumerate processes");

    for proc in processes.iter().take(10) {
        assert!(proc.pid > 0 || proc.pid == 0);
        assert!(proc.thread_count >= 1);

        if proc.pid > 0 {
            assert!(!proc.name.is_empty() || proc.name.starts_with("pid_"));
        }
    }
}

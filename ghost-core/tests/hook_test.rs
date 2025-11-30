//! Tests for hook detection

#[cfg(test)]
mod tests {
    use ghost_core::hooks::{HookDetector, HookType};

    #[test]
    fn test_hook_detector_creation() {
        let detector = HookDetector::new();
        assert!(detector.is_ok());
    }

    #[test]
    fn test_hook_type_display() {
        assert_eq!(format!("{}", HookType::InlineHook), "Inline Hook");
        assert_eq!(format!("{}", HookType::IatHook), "IAT Hook");
        assert_eq!(format!("{}", HookType::LdPreload), "LD_PRELOAD");
        assert_eq!(format!("{}", HookType::Ptrace), "ptrace");
        assert_eq!(
            format!("{}", HookType::DyldInsertLibraries),
            "DYLD_INSERT_LIBRARIES"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_dyld_detection_clean_process() {
        // Test on current process which should not have DYLD_INSERT_LIBRARIES
        let detector = HookDetector::new().expect("Failed to create detector");
        let current_pid = std::process::id();

        let result = detector.detect_hooks(current_pid);
        assert!(result.is_ok());

        let hook_result = result.unwrap();
        // Current test process should not have DYLD hooks
        assert!(
            !hook_result
                .hooks
                .iter()
                .any(|h| matches!(h.hook_type, HookType::DyldInsertLibraries)),
            "Test process should not have DYLD_INSERT_LIBRARIES"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_dyld_hook_type() {
        // Just verify the hook type exists and can be created
        let hook_type = HookType::DyldInsertLibraries;
        assert_eq!(format!("{}", hook_type), "DYLD_INSERT_LIBRARIES");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_inline_hook_detection_framework() {
        // Test that inline hook detection runs without crashing
        let detector = HookDetector::new().expect("Failed to create detector");
        let current_pid = std::process::id();

        let result = detector.detect_hooks(current_pid);
        assert!(result.is_ok());

        // Inline hook detection framework should be present
        // Even if it doesn't find hooks in the test process
        let hook_result = result.unwrap();
        assert_eq!(hook_result.inline_hooks, 0);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn test_hook_detector_on_current_platform() {
        let detector = HookDetector::new().expect("Failed to create detector");
        let current_pid = std::process::id();

        let result = detector.detect_hooks(current_pid);
        // Should succeed on all platforms
        assert!(result.is_ok());
    }
}

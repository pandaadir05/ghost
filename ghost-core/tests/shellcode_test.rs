//! Tests for shellcode detection

#[cfg(test)]
mod tests {
    use ghost_core::ShellcodeDetector;

    #[test]
    fn test_shellcode_detector_creation() {
        let detector = ShellcodeDetector::new();
        assert!(detector.signature_count() > 0);
    }

    #[test]
    fn test_detect_x86_peb_access() {
        let detector = ShellcodeDetector::new();

        // x86 PEB access: mov edx, fs:[0x30]
        let shellcode = vec![0x64, 0x8B, 0x15, 0x30, 0x00, 0x00, 0x00];

        let detections = detector.scan_memory_region(&shellcode, 0x10000000);
        assert!(!detections.is_empty(), "Should detect x86 PEB access pattern");
        assert!(detections[0].signature_matches.iter().any(|s| s.contains("PEB")));
    }

    #[test]
    fn test_detect_x64_peb_access() {
        let detector = ShellcodeDetector::new();

        // x64 PEB access: mov rax, gs:[0x60]
        let shellcode = vec![0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00];

        let detections = detector.scan_memory_region(&shellcode, 0x10000000);
        assert!(!detections.is_empty(), "Should detect x64 PEB access pattern");
    }

    #[test]
    fn test_detect_metasploit_signature() {
        let detector = ShellcodeDetector::new();

        // Common Metasploit pattern: CLD; SUB ESP
        let shellcode = vec![0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8];

        let detections = detector.scan_memory_region(&shellcode, 0x10000000);
        assert!(!detections.is_empty(), "Should detect Metasploit pattern");
    }

    #[test]
    fn test_no_false_positive_on_clean_data() {
        let detector = ShellcodeDetector::new();

        // Random clean data that shouldn't match
        let clean_data = vec![0x00; 256];

        let detections = detector.scan_memory_region(&clean_data, 0x10000000);
        assert!(detections.is_empty(), "Clean data should not trigger detection");
    }

    #[test]
    fn test_scan_empty_buffer() {
        let detector = ShellcodeDetector::new();
        let empty = vec![];

        let detections = detector.scan_memory_region(&empty, 0x10000000);
        assert!(detections.is_empty());
    }

    #[test]
    fn test_detection_confidence_scores() {
        let detector = ShellcodeDetector::new();

        // PEB access pattern has high confidence
        let peb_pattern = vec![0x64, 0x8B, 0x15, 0x30, 0x00, 0x00, 0x00];
        let detections = detector.scan_memory_region(&peb_pattern, 0x10000000);

        if !detections.is_empty() {
            assert!(detections[0].confidence > 0.7, "PEB access should have high confidence");
        }
    }

    #[test]
    fn test_multiple_patterns_in_buffer() {
        let detector = ShellcodeDetector::new();

        let mut buffer = vec![0x90; 512]; // NOPs

        // Insert x86 PEB access at offset 100
        buffer[100] = 0x64;
        buffer[101] = 0x8B;
        buffer[102] = 0x15;
        buffer[103] = 0x30;

        // Insert another pattern at offset 200
        buffer[200] = 0xFC; // CLD
        buffer[201] = 0x48;
        buffer[202] = 0x83;

        let detections = detector.scan_memory_region(&buffer, 0x10000000);
        assert!(!detections.is_empty(), "Should detect patterns in buffer");
    }
}

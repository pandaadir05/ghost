use crate::{GhostError, Result};

#[derive(Debug, Clone)]
pub struct ShellcodeSignature {
    pub pattern: Vec<u8>,
    pub mask: Vec<u8>,
    pub name: &'static str,
    pub confidence: f32,
}

#[derive(Debug, Clone)]
pub struct ShellcodeDetection {
    pub address: usize,
    pub size: usize,
    pub signature_matches: Vec<String>,
    pub confidence: f32,
}

/// Common shellcode patterns and signatures
pub struct ShellcodeDetector {
    signatures: Vec<ShellcodeSignature>,
}

impl ShellcodeDetector {
    pub fn new() -> Self {
        let mut detector = Self {
            signatures: Vec::new(),
        };
        detector.initialize_signatures();
        detector
    }

    fn initialize_signatures(&mut self) {
        // GetProcAddress hash resolution pattern (common in position-independent code)
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x64, 0x8B, 0x25, 0x30, 0x00, 0x00, 0x00], // mov esp, fs:[0x30]
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00],
            name: "PEB Access Pattern",
            confidence: 0.7,
        });

        // Common x64 shellcode prologue
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x48, 0x83, 0xEC, 0x00, 0x48, 0x89], // sub rsp, XX; mov
            mask: vec![0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF],
            name: "x64 Stack Setup",
            confidence: 0.6,
        });

        // Egg hunter pattern (searches for specific marker in memory)
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x66, 0x81, 0x3F], // cmp word ptr [edi], XXXX
            mask: vec![0xFF, 0xFF, 0xFF],
            name: "Egg Hunter Pattern",
            confidence: 0.8,
        });

        // API hashing pattern (djb2 hash commonly used)
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0xC1, 0xCF, 0x0D, 0x01, 0xC7], // ror edi, 0xD; add edi, eax
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            name: "DJB2 Hash Algorithm",
            confidence: 0.9,
        });

        // Common Windows API call pattern
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0xFF, 0x15], // call [address]
            mask: vec![0xFF, 0xFF],
            name: "Indirect API Call",
            confidence: 0.4,
        });

        // NOP sled detection (common in exploits)
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x90, 0x90, 0x90, 0x90, 0x90, 0x90], // Multiple NOPs
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            name: "NOP Sled",
            confidence: 0.5,
        });

        // String loading pattern (common in shellcode)
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0xE8, 0x00, 0x00, 0x00, 0x00, 0x5E], // call $+5; pop esi
            mask: vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF],
            name: "String Loading Technique",
            confidence: 0.8,
        });

        // PE header in memory (process hollowing indicator)
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x4D, 0x5A], // MZ header
            mask: vec![0xFF, 0xFF],
            name: "PE Header in Memory",
            confidence: 0.6,
        });

        // Common metasploit meterpreter pattern
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8], // CLD; and rsp, -16; call
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            name: "Meterpreter Payload Pattern",
            confidence: 0.95,
        });
    }

    /// Scan memory region for shellcode patterns
    pub fn scan_memory_region(&self, data: &[u8], base_address: usize) -> Vec<ShellcodeDetection> {
        let mut detections = Vec::new();

        if data.len() < 16 {
            return detections; // Too small to contain meaningful shellcode
        }

        // Look for signature matches
        for sig in &self.signatures {
            let matches = self.find_pattern_matches(data, &sig.pattern, &sig.mask);
            for match_offset in matches {
                // Check if we already have a detection at this location
                let address = base_address + match_offset;
                if !detections.iter().any(|d| d.address == address) {
                    let mut detection = ShellcodeDetection {
                        address,
                        size: sig.pattern.len(),
                        signature_matches: vec![sig.name.to_string()],
                        confidence: sig.confidence,
                    };

                    // Look for additional patterns in the vicinity
                    self.enhance_detection(data, match_offset, &mut detection);
                    detections.push(detection);
                }
            }
        }

        // Perform heuristic analysis
        let heuristic_detections = self.heuristic_analysis(data, base_address);
        detections.extend(heuristic_detections);

        detections
    }

    fn find_pattern_matches(&self, data: &[u8], pattern: &[u8], mask: &[u8]) -> Vec<usize> {
        let mut matches = Vec::new();

        if pattern.len() > data.len() {
            return matches;
        }

        for i in 0..=(data.len() - pattern.len()) {
            let mut match_found = true;
            for j in 0..pattern.len() {
                if mask[j] == 0xFF && data[i + j] != pattern[j] {
                    match_found = false;
                    break;
                }
            }
            if match_found {
                matches.push(i);
            }
        }

        matches
    }

    fn enhance_detection(&self, data: &[u8], offset: usize, detection: &mut ShellcodeDetection) {
        // Look for additional patterns within 256 bytes of the initial match
        let search_start = offset.saturating_sub(128);
        let search_end = std::cmp::min(offset + 128, data.len());

        for sig in &self.signatures {
            if sig.name == detection.signature_matches[0] {
                continue; // Skip the signature we already matched
            }

            let region = &data[search_start..search_end];
            let matches = self.find_pattern_matches(region, &sig.pattern, &sig.mask);
            
            if !matches.is_empty() {
                detection.signature_matches.push(sig.name.to_string());
                detection.confidence = (detection.confidence + sig.confidence).min(1.0);
                detection.size = std::cmp::max(detection.size, search_end - search_start);
            }
        }
    }

    fn heuristic_analysis(&self, data: &[u8], base_address: usize) -> Vec<ShellcodeDetection> {
        let mut detections = Vec::new();

        // Check for high entropy regions (encrypted/packed code)
        if let Some(entropy_detection) = self.check_entropy(data, base_address) {
            detections.push(entropy_detection);
        }

        // Check for suspicious instruction sequences
        if let Some(instruction_detection) = self.check_instruction_patterns(data, base_address) {
            detections.push(instruction_detection);
        }

        detections
    }

    fn check_entropy(&self, data: &[u8], base_address: usize) -> Option<ShellcodeDetection> {
        if data.len() < 64 {
            return None;
        }

        // Calculate Shannon entropy
        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let length = data.len() as f64;
        let entropy: f64 = counts
            .iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / length;
                -p * p.log2()
            })
            .sum();

        // High entropy (> 7.0) might indicate encrypted or compressed code
        if entropy > 7.0 {
            Some(ShellcodeDetection {
                address: base_address,
                size: data.len(),
                signature_matches: vec!["High Entropy Region".to_string()],
                confidence: ((entropy - 6.0) / 2.0).min(0.8) as f32,
            })
        } else {
            None
        }
    }

    fn check_instruction_patterns(&self, data: &[u8], base_address: usize) -> Option<ShellcodeDetection> {
        if data.len() < 32 {
            return None;
        }

        let mut suspicious_instructions = 0;
        let mut i = 0;

        while i < data.len() - 4 {
            // Look for suspicious instruction patterns
            match data[i] {
                0xEB => suspicious_instructions += 1, // Short jump
                0xE9 => suspicious_instructions += 1, // Near jump
                0xFF if data.get(i + 1).map_or(false, |&b| (b & 0x38) == 0x20) => {
                    suspicious_instructions += 2; // Indirect jump
                }
                0x0F if data.get(i + 1).map_or(false, |&b| b == 0x05) => {
                    suspicious_instructions += 2; // SYSCALL
                }
                _ => {}
            }
            i += 1;
        }

        let density = suspicious_instructions as f32 / data.len() as f32;
        if density > 0.1 {
            // More than 10% suspicious instructions
            Some(ShellcodeDetection {
                address: base_address,
                size: data.len(),
                signature_matches: vec!["Suspicious Instruction Density".to_string()],
                confidence: (density * 5.0).min(0.9),
            })
        } else {
            None
        }
    }
}

impl Default for ShellcodeDetector {
    fn default() -> Self {
        Self::new()
    }
}
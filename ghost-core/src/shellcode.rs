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
#[derive(Debug)]
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
        // ===== PEB/TEB Access Patterns (Windows) =====

        // x86 PEB Access via FS segment
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x64, 0x8B, 0x15, 0x30, 0x00, 0x00, 0x00], // mov edx, fs:[0x30]
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00],
            name: "x86 PEB Access (fs:[0x30])",
            confidence: 0.85,
        });

        // x86 PEB Access variant
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x64, 0xA1, 0x30, 0x00, 0x00, 0x00], // mov eax, fs:[0x30]
            mask: vec![0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00],
            name: "x86 PEB Access (fs:[0x30] via eax)",
            confidence: 0.85,
        });

        // x64 PEB Access via GS segment
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00], // mov rax, gs:[0x60]
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00],
            name: "x64 PEB Access (gs:[0x60])",
            confidence: 0.9,
        });

        // x64 TEB Access
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00], // mov rax, gs:[0x30]
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00],
            name: "x64 TEB Access (gs:[0x30])",
            confidence: 0.8,
        });

        // ===== API Hashing Patterns =====

        // ROR 13 hash (Metasploit style)
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0xC1, 0xCF, 0x0D, 0x01, 0xC7], // ror edi, 0xD; add edi, eax
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            name: "ROR13 API Hash (Metasploit)",
            confidence: 0.95,
        });

        // ROR 13 hash variant
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0xC1, 0xCA, 0x0D, 0x01, 0xC2], // ror edx, 0xD; add edx, eax
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            name: "ROR13 API Hash Variant",
            confidence: 0.95,
        });

        // x64 ROR 13 hash
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x48, 0xC1, 0xC9, 0x0D], // ror rcx, 0xD
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
            name: "x64 ROR13 API Hash",
            confidence: 0.9,
        });

        // FNV-1a hash pattern
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x69, 0xC0, 0x01, 0x00, 0x01, 0x00], // imul eax, eax, 0x01000193
            mask: vec![0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
            name: "FNV-1a Hash Pattern",
            confidence: 0.85,
        });

        // ===== Shellcode Prologues =====

        // Metasploit x64 staged reverse TCP
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8], // CLD; and rsp, -16; call
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            name: "Metasploit x64 Reverse TCP",
            confidence: 0.98,
        });

        // Metasploit x86 staged reverse TCP
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00], // CLD; call $+0x82
            mask: vec![0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
            name: "Metasploit x86 Reverse TCP",
            confidence: 0.95,
        });

        // Cobalt Strike beacon
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC8, 0x00, 0x00, 0x00],
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
            name: "Cobalt Strike Beacon Prologue",
            confidence: 0.98,
        });

        // Common x64 shellcode prologue
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x48, 0x83, 0xEC, 0x28, 0x48, 0x83, 0xE4, 0xF0], // sub rsp, 0x28; and rsp, -16
            mask: vec![0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF],
            name: "x64 Stack Setup Pattern",
            confidence: 0.7,
        });

        // ===== Position-Independent Code Patterns =====

        // Call-pop technique (get current EIP/RIP)
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0xE8, 0x00, 0x00, 0x00, 0x00, 0x58], // call $+5; pop eax
            mask: vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF],
            name: "Call-Pop GetPC (eax)",
            confidence: 0.9,
        });

        self.signatures.push(ShellcodeSignature {
            pattern: vec![0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B], // call $+5; pop ebx
            mask: vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF],
            name: "Call-Pop GetPC (ebx)",
            confidence: 0.9,
        });

        self.signatures.push(ShellcodeSignature {
            pattern: vec![0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D], // call $+5; pop ebp
            mask: vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF],
            name: "Call-Pop GetPC (ebp)",
            confidence: 0.9,
        });

        self.signatures.push(ShellcodeSignature {
            pattern: vec![0xE8, 0x00, 0x00, 0x00, 0x00, 0x5E], // call $+5; pop esi
            mask: vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF],
            name: "Call-Pop GetPC (esi)",
            confidence: 0.9,
        });

        // FPU-based GetPC (classic technique)
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0xD9, 0xEE, 0xD9, 0x74, 0x24, 0xF4], // fldz; fnstenv [esp-12]
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            name: "FPU GetPC Technique",
            confidence: 0.95,
        });

        // ===== Egg Hunter Patterns =====

        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x66, 0x81, 0xCA, 0xFF, 0x0F], // or dx, 0x0FFF (page alignment)
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            name: "Egg Hunter Page Scan",
            confidence: 0.9,
        });

        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x6A, 0x02, 0x58, 0xCD, 0x2E], // push 2; pop eax; int 0x2E
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            name: "Egg Hunter NtAccessCheckAndAuditAlarm",
            confidence: 0.95,
        });

        // ===== Windows API Function Resolution =====

        // Walking InMemoryOrderModuleList
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x8B, 0x52, 0x0C, 0x8B, 0x52, 0x14], // mov edx, [edx+0x0C]; mov edx, [edx+0x14]
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            name: "PEB_LDR_DATA Walk (x86)",
            confidence: 0.92,
        });

        // x64 LDR walk
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20], // mov rdx, [rdx+0x18]; mov rdx, [rdx+0x20]
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            name: "PEB_LDR_DATA Walk (x64)",
            confidence: 0.92,
        });

        // ===== Syscall Patterns =====

        // Direct syscall (x64 Windows)
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x4C, 0x8B, 0xD1, 0xB8], // mov r10, rcx; mov eax, <syscall_num>
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
            name: "Direct Syscall Setup (x64)",
            confidence: 0.9,
        });

        // int 0x2E syscall (legacy Windows)
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0xCD, 0x2E], // int 0x2E
            mask: vec![0xFF, 0xFF],
            name: "Legacy Syscall (int 0x2E)",
            confidence: 0.85,
        });

        // sysenter (x86)
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x0F, 0x34], // sysenter
            mask: vec![0xFF, 0xFF],
            name: "Sysenter Instruction",
            confidence: 0.8,
        });

        // syscall (x64)
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x0F, 0x05], // syscall
            mask: vec![0xFF, 0xFF],
            name: "Syscall Instruction",
            confidence: 0.75,
        });

        // ===== Anti-Analysis Patterns =====

        // IsDebuggerPresent check pattern
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x64, 0x8B, 0x15, 0x30, 0x00, 0x00, 0x00, 0x8B, 0x52, 0x02], // PEB->BeingDebugged
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF],
            name: "IsDebuggerPresent Check",
            confidence: 0.85,
        });

        // ===== Exploit Patterns =====

        // NOP sled detection (various NOP equivalents)
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90], // 8 NOPs
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            name: "NOP Sled",
            confidence: 0.6,
        });

        // PUSH/RET technique (for control flow hijacking)
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x68], // push imm32
            mask: vec![0xFF],
            name: "PUSH/RET Control Flow",
            confidence: 0.3, // Low confidence as standalone
        });

        // ===== Process Hollowing/Injection Indicators =====

        // PE header in memory
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x4D, 0x5A, 0x90, 0x00], // MZ header with typical padding
            mask: vec![0xFF, 0xFF, 0x00, 0x00],
            name: "PE Header (MZ) in Memory",
            confidence: 0.7,
        });

        // PE signature
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x50, 0x45, 0x00, 0x00], // PE\0\0
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
            name: "PE Signature in Memory",
            confidence: 0.8,
        });

        // ===== Linux Shellcode Patterns =====

        // Linux x86 execve("/bin/sh")
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x31, 0xC0, 0x50, 0x68, 0x2F, 0x2F, 0x73, 0x68], // xor eax, eax; push eax; push "//sh"
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            name: "Linux x86 execve /bin/sh",
            confidence: 0.98,
        });

        // Linux x64 execve pattern
        self.signatures.push(ShellcodeSignature {
            pattern: vec![
                0x48, 0x31, 0xD2, 0x48, 0xBB, 0xFF, 0x2F, 0x62, 0x69, 0x6E, 0x2F, 0x73, 0x68,
            ], // xor rdx, rdx; mov rbx, "/bin/sh"
            mask: vec![
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            ],
            name: "Linux x64 execve /bin/sh",
            confidence: 0.98,
        });

        // Linux connect-back pattern
        self.signatures.push(ShellcodeSignature {
            pattern: vec![0x6A, 0x66, 0x58, 0x6A, 0x01, 0x5B], // push 0x66; pop eax; push 1; pop ebx (socketcall)
            mask: vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            name: "Linux socketcall Pattern",
            confidence: 0.9,
        });

        // ===== Indirect API Call Patterns =====

        self.signatures.push(ShellcodeSignature {
            pattern: vec![0xFF, 0xD0], // call eax
            mask: vec![0xFF, 0xFF],
            name: "Indirect Call (eax)",
            confidence: 0.5,
        });

        self.signatures.push(ShellcodeSignature {
            pattern: vec![0xFF, 0xD3], // call ebx
            mask: vec![0xFF, 0xFF],
            name: "Indirect Call (ebx)",
            confidence: 0.5,
        });

        self.signatures.push(ShellcodeSignature {
            pattern: vec![0xFF, 0x15], // call [address]
            mask: vec![0xFF, 0xFF],
            name: "Indirect API Call",
            confidence: 0.4,
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

    fn check_instruction_patterns(
        &self,
        data: &[u8],
        base_address: usize,
    ) -> Option<ShellcodeDetection> {
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
                0xFF if data.get(i + 1).is_some_and(|&b| (b & 0x38) == 0x20) => {
                    suspicious_instructions += 2; // Indirect jump
                }
                0x0F if data.get(i + 1).is_some_and(|&b| b == 0x05) => {
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

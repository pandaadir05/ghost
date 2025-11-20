use crate::{GhostError, MemoryRegion, ProcessInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use yara::{Compiler, Rules};

#[derive(Serialize, Deserialize)]
pub struct DynamicYaraEngine {
    rules_path: Option<PathBuf>,
    #[serde(skip)]
    compiled_rules: Option<Rules>,
    rule_metadata: Vec<YaraRuleMetadata>,
    scan_cache: HashMap<String, CachedScanResult>,
}

impl std::fmt::Debug for DynamicYaraEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicYaraEngine")
            .field("rules_path", &self.rules_path)
            .field("has_compiled_rules", &self.compiled_rules.is_some())
            .field("rule_metadata", &self.rule_metadata)
            .field("scan_cache", &self.scan_cache)
            .finish()
    }
}

impl Clone for DynamicYaraEngine {
    fn clone(&self) -> Self {
        DynamicYaraEngine {
            rules_path: self.rules_path.clone(),
            compiled_rules: None, // Rules cannot be cloned, will need to recompile
            rule_metadata: self.rule_metadata.clone(),
            scan_cache: self.scan_cache.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleMetadata {
    pub name: String,
    pub file_path: String,
    pub threat_level: ThreatLevel,
    pub last_updated: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraScanResult {
    pub matches: Vec<RuleMatch>,
    pub scan_time_ms: u64,
    pub bytes_scanned: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_name: String,
    pub namespace: String,
    pub threat_level: ThreatLevel,
    pub offset: u64,
    pub length: u32,
    pub metadata: HashMap<String, String>,
    pub matched_strings: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatLevel {
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

impl ThreatLevel {
    pub fn from_metadata(metadata: &HashMap<String, String>) -> Self {
        metadata
            .get("threat_level")
            .and_then(|s| match s.to_lowercase().as_str() {
                "info" => Some(ThreatLevel::Info),
                "low" => Some(ThreatLevel::Low),
                "medium" => Some(ThreatLevel::Medium),
                "high" => Some(ThreatLevel::High),
                "critical" => Some(ThreatLevel::Critical),
                _ => None,
            })
            .unwrap_or(ThreatLevel::Medium)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedScanResult {
    result: YaraScanResult,
    timestamp: SystemTime,
}

impl DynamicYaraEngine {
    /// Create a new YARA engine with optional custom rules directory
    pub fn new(rules_path: Option<&str>) -> Result<Self, GhostError> {
        let rules_path = rules_path.map(PathBuf::from);

        let mut engine = DynamicYaraEngine {
            rules_path,
            compiled_rules: None,
            rule_metadata: Vec::new(),
            scan_cache: HashMap::new(),
        };

        // Attempt to load rules if path is provided
        if engine.rules_path.is_some() {
            if let Err(e) = engine.compile_rules() {
                log::warn!("Failed to compile YARA rules: {:?}", e);
            }
        }

        Ok(engine)
    }

    /// Compile all YARA rules from the rules directory
    pub fn compile_rules(&mut self) -> Result<usize, GhostError> {
        let rules_dir = self
            .rules_path
            .as_ref()
            .ok_or_else(|| GhostError::Configuration {
                message: "No rules directory configured".to_string(),
            })?;

        if !rules_dir.exists() {
            return Err(GhostError::Configuration {
                message: format!("Rules directory does not exist: {}", rules_dir.display()),
            });
        }

        let mut compiler = Compiler::new().map_err(|e| GhostError::Configuration {
            message: format!("YARA compiler error: {}", e),
        })?;

        let mut rule_count = 0;
        self.rule_metadata.clear();

        // Recursively find and compile all .yar and .yara files
        let rule_files = Self::find_rule_files(rules_dir)?;

        for rule_file in &rule_files {
            match fs::read_to_string(rule_file) {
                Ok(content) => {
                    let namespace = rule_file
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("default");

                    match compiler.add_rules_str_with_namespace(&content, namespace) {
                        Ok(_) => {
                            log::info!("Compiled YARA rule: {}", rule_file.display());

                            self.rule_metadata.push(YaraRuleMetadata {
                                name: namespace.to_string(),
                                file_path: rule_file.display().to_string(),
                                threat_level: ThreatLevel::Medium,
                                last_updated: SystemTime::now(),
                            });

                            rule_count += 1;
                        }
                        Err(e) => {
                            log::error!("Failed to compile {}: {}", rule_file.display(), e);
                        }
                    }
                }
                Err(e) => {
                    log::error!("Failed to read {}: {}", rule_file.display(), e);
                }
            }
        }

        if rule_count == 0 {
            return Err(GhostError::Configuration {
                message: "No YARA rules were successfully compiled".to_string(),
            });
        }

        self.compiled_rules = Some(
            compiler
                .compile_rules()
                .map_err(|e| GhostError::Configuration {
                    message: format!("Rule compilation failed: {}", e),
                })?,
        );

        log::info!("Successfully compiled {} YARA rules", rule_count);
        Ok(rule_count)
    }

    /// Find all YARA rule files in the given directory
    fn find_rule_files(dir: &Path) -> Result<Vec<PathBuf>, GhostError> {
        let mut rule_files = Vec::new();

        if !dir.is_dir() {
            return Ok(rule_files);
        }

        let entries = fs::read_dir(dir).map_err(|e| GhostError::Configuration {
            message: format!("Failed to read rules directory: {}", e),
        })?;

        for entry in entries.flatten() {
            let path = entry.path();

            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "yar" || ext == "yara" {
                        rule_files.push(path);
                    }
                }
            } else if path.is_dir() {
                // Recursively search subdirectories
                rule_files.extend(Self::find_rule_files(&path)?);
            }
        }

        Ok(rule_files)
    }

    /// Scan process memory regions with compiled YARA rules
    pub async fn scan_process(
        &self,
        process: &ProcessInfo,
        memory_regions: &[MemoryRegion],
    ) -> Result<YaraScanResult, GhostError> {
        let start_time = SystemTime::now();

        let rules = self
            .compiled_rules
            .as_ref()
            .ok_or_else(|| GhostError::Configuration {
                message: "YARA rules not compiled".to_string(),
            })?;

        let mut all_matches = Vec::new();
        let mut bytes_scanned = 0u64;

        // Scan each executable memory region
        for region in memory_regions.iter() {
            // Only scan executable regions with reasonable size
            if !region.protection.is_executable() {
                continue;
            }

            if region.size > 100 * 1024 * 1024 {
                log::debug!(
                    "Skipping large region at {:#x} (size: {} MB)",
                    region.base_address,
                    region.size / (1024 * 1024)
                );
                continue;
            }

            // Read memory content
            let memory_content = match Self::read_process_memory(process.pid, region) {
                Ok(data) => data,
                Err(e) => {
                    log::debug!(
                        "Failed to read memory at {:#x}: {:?}",
                        region.base_address,
                        e
                    );
                    continue;
                }
            };

            bytes_scanned += memory_content.len() as u64;

            // Perform YARA scan on this memory region
            match Self::scan_memory_with_yara(rules, &memory_content, region.base_address) {
                Ok(mut matches) => {
                    all_matches.append(&mut matches);
                }
                Err(e) => {
                    log::debug!("YARA scan error at {:#x}: {:?}", region.base_address, e);
                }
            }
        }

        let scan_time_ms = start_time.elapsed().unwrap_or_default().as_millis() as u64;

        Ok(YaraScanResult {
            matches: all_matches,
            scan_time_ms,
            bytes_scanned,
        })
    }

    /// Scan a memory buffer with YARA rules
    fn scan_memory_with_yara(
        rules: &Rules,
        data: &[u8],
        base_address: usize,
    ) -> Result<Vec<RuleMatch>, GhostError> {
        let scan_results = rules
            .scan_mem(data, 300)
            .map_err(|e| GhostError::Detection {
                message: format!("Scan failed: {}", e),
            })?;

        let mut matches = Vec::new();

        for rule in scan_results {
            let rule_name = rule.identifier.to_string();
            let namespace = rule.namespace.to_string();

            // Extract metadata
            let mut metadata = HashMap::new();
            for meta in rule.metadatas {
                let value = match meta.value {
                    yara::MetadataValue::Integer(i) => i.to_string(),
                    yara::MetadataValue::String(ref s) => s.to_string(),
                    yara::MetadataValue::Boolean(b) => b.to_string(),
                };
                metadata.insert(meta.identifier.to_string(), value);
            }

            let threat_level = ThreatLevel::from_metadata(&metadata);

            // Extract matched strings
            let mut matched_strings = Vec::new();
            for string in rule.strings {
                let identifier = string.identifier.to_string();
                for m in string.matches {
                    matched_strings.push(format!(
                        "{} at offset {:#x}",
                        identifier,
                        base_address + m.offset
                    ));

                    // Create a match entry for each string match
                    matches.push(RuleMatch {
                        rule_name: rule_name.clone(),
                        namespace: namespace.clone(),
                        threat_level,
                        offset: (base_address + m.offset) as u64,
                        length: m.length as u32,
                        metadata: metadata.clone(),
                        matched_strings: vec![identifier.clone()],
                    });
                }
            }
        }

        Ok(matches)
    }

    /// Read memory from a specific process and region
    #[cfg(target_os = "windows")]
    fn read_process_memory(pid: u32, region: &MemoryRegion) -> Result<Vec<u8>, GhostError> {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};

        unsafe {
            let handle = OpenProcess(PROCESS_VM_READ, false, pid).map_err(|e| {
                GhostError::MemoryEnumeration {
                    reason: format!("OpenProcess failed: {}", e),
                }
            })?;

            let mut buffer = vec![0u8; region.size];
            let mut bytes_read = 0;

            let result = ReadProcessMemory(
                handle,
                region.base_address as *const _,
                buffer.as_mut_ptr() as *mut _,
                region.size,
                Some(&mut bytes_read),
            );

            let _ = CloseHandle(handle);

            if result.is_ok() && bytes_read > 0 {
                buffer.truncate(bytes_read);
                Ok(buffer)
            } else {
                Err(GhostError::MemoryReadError(
                    "ReadProcessMemory failed".to_string(),
                ))
            }
        }
    }

    /// Read memory from a specific process and region (Linux implementation)
    #[cfg(target_os = "linux")]
    fn read_process_memory(pid: u32, region: &MemoryRegion) -> Result<Vec<u8>, GhostError> {
        use std::fs::File;
        use std::io::{Read, Seek, SeekFrom};

        let mem_path = format!("/proc/{}/mem", pid);
        let mut file = File::open(&mem_path).map_err(|e| GhostError::MemoryEnumeration {
            reason: format!("Failed to open {}: {}", mem_path, e),
        })?;

        file.seek(SeekFrom::Start(region.base_address as u64))
            .map_err(|e| GhostError::MemoryEnumeration {
                reason: format!("Seek failed: {}", e),
            })?;

        let mut buffer = vec![0u8; region.size];
        file.read_exact(&mut buffer)
            .map_err(|e| GhostError::MemoryEnumeration {
                reason: format!("Read failed: {}", e),
            })?;

        Ok(buffer)
    }

    /// Read memory from a specific process and region (macOS implementation)
    #[cfg(target_os = "macos")]
    fn read_process_memory(_pid: u32, _region: &MemoryRegion) -> Result<Vec<u8>, GhostError> {
        Err(GhostError::NotImplemented(
            "Memory reading not implemented for macOS".to_string(),
        ))
    }

    pub fn get_rule_count(&self) -> usize {
        self.rule_metadata.len()
    }

    pub fn get_rule_metadata(&self) -> &[YaraRuleMetadata] {
        &self.rule_metadata
    }

    pub fn is_compiled(&self) -> bool {
        self.compiled_rules.is_some()
    }
}

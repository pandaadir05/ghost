use crate::{MemoryRegion, ProcessInfo, Result};

#[cfg(windows)]
use crate::memory::{validate_pe_header, PEHeaderValidation};

#[derive(Debug, Clone)]
pub struct HollowingDetection {
    pub pid: u32,
    pub process_name: String,
    pub indicators: Vec<HollowingIndicator>,
    pub confidence: f32,
}

#[derive(Debug, Clone)]
pub enum HollowingIndicator {
    UnmappedMainImage,
    SuspiciousImageBase,
    MemoryLayoutAnomaly {
        expected_size: usize,
        actual_size: usize,
    },
    MismatchedPEHeader,
    InvalidPEHeader {
        validation: String,
    },
    CorruptedPEStructure {
        address: usize,
        reason: String,
    },
    UnusualEntryPoint {
        address: usize,
    },
    SuspiciousMemoryGaps {
        gap_count: usize,
        largest_gap: usize,
    },
    SectionHashMismatch {
        section_name: String,
        expected_hash: String,
        actual_hash: String,
    },
    ModifiedCodeSection {
        section_name: String,
        modification_percentage: f32,
    },
    ImportTableMismatch,
    ExportTableCorrupted,
}

impl std::fmt::Display for HollowingIndicator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnmappedMainImage => write!(f, "Main executable image appears unmapped"),
            Self::SuspiciousImageBase => write!(f, "Image base address is suspicious"),
            Self::MemoryLayoutAnomaly {
                expected_size,
                actual_size,
            } => {
                write!(
                    f,
                    "Memory layout anomaly: expected {:#x}, found {:#x}",
                    expected_size, actual_size
                )
            }
            Self::MismatchedPEHeader => write!(f, "PE header mismatch detected"),
            Self::InvalidPEHeader { validation } => {
                write!(f, "Invalid PE header: {}", validation)
            }
            Self::CorruptedPEStructure { address, reason } => {
                write!(f, "Corrupted PE structure at {:#x}: {}", address, reason)
            }
            Self::UnusualEntryPoint { address } => {
                write!(f, "Entry point at unusual location: {:#x}", address)
            }
            Self::SuspiciousMemoryGaps {
                gap_count,
                largest_gap,
            } => {
                write!(
                    f,
                    "{} memory gaps detected, largest: {:#x} bytes",
                    gap_count, largest_gap
                )
            }
            Self::SectionHashMismatch {
                section_name,
                expected_hash,
                actual_hash,
            } => {
                write!(
                    f,
                    "Section '{}' hash mismatch - expected: {}, actual: {}",
                    section_name, expected_hash, actual_hash
                )
            }
            Self::ModifiedCodeSection {
                section_name,
                modification_percentage,
            } => {
                write!(
                    f,
                    "Section '{}' modified ({:.1}% different from disk)",
                    section_name, modification_percentage
                )
            }
            Self::ImportTableMismatch => {
                write!(f, "Import table differs from disk version")
            }
            Self::ExportTableCorrupted => {
                write!(f, "Export table is corrupted or invalid")
            }
        }
    }
}

/// Process hollowing detection engine
#[derive(Debug)]
pub struct HollowingDetector;

impl HollowingDetector {
    pub fn new() -> Self {
        Self
    }

    /// Analyze process for signs of hollowing
    pub fn analyze_process(
        &self,
        process: &ProcessInfo,
        memory_regions: &[MemoryRegion],
    ) -> Result<Option<HollowingDetection>> {
        let mut indicators = Vec::new();
        let mut confidence: f32 = 0.0;

        // Check for main image unmapping
        if let Some(indicator) = self.check_main_image_unmapping(process, memory_regions) {
            indicators.push(indicator);
            confidence += 0.8;
        }

        // Check memory layout anomalies
        if let Some(indicator) = self.check_memory_layout_anomalies(memory_regions) {
            indicators.push(indicator);
            confidence += 0.6;
        }

        // Check for suspicious memory gaps
        if let Some(indicator) = self.check_memory_gaps(memory_regions) {
            indicators.push(indicator);
            confidence += 0.4;
        }

        // Check for PE header anomalies (heuristic-based)
        if let Some(indicator) = self.check_pe_header_anomalies(memory_regions) {
            indicators.push(indicator);
            confidence += 0.7;
        }

        // Validate actual PE headers (deep inspection)
        if let Some(indicator) = self.validate_pe_headers(process.pid, memory_regions) {
            indicators.push(indicator);
            confidence += 0.9; // Higher confidence for actual PE validation
        }

        // Check entry point location
        if let Some(indicator) = self.check_entry_point_anomalies(process, memory_regions) {
            indicators.push(indicator);
            confidence += 0.5;
        }

        // Deep PE comparison with section hashing (Windows only)
        if let Some(mut deep_indicators) = self.deep_pe_comparison(process) {
            let indicator_count = deep_indicators.len() as f32;
            confidence += 0.9 * (indicator_count / 3.0).min(1.0);
            indicators.append(&mut deep_indicators);
        }

        if !indicators.is_empty() {
            Ok(Some(HollowingDetection {
                pid: process.pid,
                process_name: process.name.clone(),
                indicators,
                confidence: confidence.min(1.0),
            }))
        } else {
            Ok(None)
        }
    }

    fn check_main_image_unmapping(
        &self,
        _process: &ProcessInfo,
        regions: &[MemoryRegion],
    ) -> Option<HollowingIndicator> {
        // Look for the main executable image region
        let main_image_regions: Vec<_> = regions
            .iter()
            .filter(|r| r.region_type == "IMAGE")
            .collect();

        // Typical legitimate process should have at least one IMAGE region for the main executable
        if main_image_regions.is_empty() {
            return Some(HollowingIndicator::UnmappedMainImage);
        }

        // Check if the main image base is suspicious
        // Most Windows executables load at predictable addresses
        for region in &main_image_regions {
            if region.base_address < 0x400000 || region.base_address > 0x80000000 {
                return Some(HollowingIndicator::SuspiciousImageBase);
            }
        }

        None
    }

    fn check_memory_layout_anomalies(
        &self,
        regions: &[MemoryRegion],
    ) -> Option<HollowingIndicator> {
        // Calculate total executable memory size
        let total_executable: usize = regions
            .iter()
            .filter(|r| {
                matches!(
                    r.protection,
                    crate::MemoryProtection::ReadExecute
                        | crate::MemoryProtection::ReadWriteExecute
                )
            })
            .map(|r| r.size)
            .sum();

        // Check for unusually large or small executable regions
        if total_executable > 0x10000000 {
            // More than 256MB of executable memory is very suspicious
            return Some(HollowingIndicator::MemoryLayoutAnomaly {
                expected_size: 0x1000000, // 16MB expected
                actual_size: total_executable,
            });
        }

        // Check for too many small executable regions (potential shellcode injection)
        let small_exec_regions = regions
            .iter()
            .filter(|r| {
                matches!(r.protection, crate::MemoryProtection::ReadExecute | crate::MemoryProtection::ReadWriteExecute)
                    && r.size < 0x10000 // Less than 64KB
                    && r.region_type == "PRIVATE"
            })
            .count();

        if small_exec_regions > 10 {
            return Some(HollowingIndicator::MemoryLayoutAnomaly {
                expected_size: 3, // 3 or fewer small executable regions expected
                actual_size: small_exec_regions,
            });
        }

        None
    }

    fn check_memory_gaps(&self, regions: &[MemoryRegion]) -> Option<HollowingIndicator> {
        // Sort regions by base address
        let mut sorted_regions: Vec<_> = regions.iter().collect();
        sorted_regions.sort_by_key(|r| r.base_address);

        let mut gaps = Vec::new();

        // Find gaps between consecutive regions
        for window in sorted_regions.windows(2) {
            let current_end = window[0].base_address + window[0].size;
            let next_start = window[1].base_address;

            if next_start > current_end {
                let gap_size = next_start - current_end;
                // Only consider significant gaps (> 64KB)
                if gap_size > 0x10000 {
                    gaps.push(gap_size);
                }
            }
        }

        // Look for suspicious gap patterns
        let large_gaps = gaps.iter().filter(|&&gap| gap > 0x1000000).count(); // 16MB+
        let total_gaps = gaps.len();

        if large_gaps > 0 || total_gaps > 20 {
            let largest_gap = gaps.iter().max().copied().unwrap_or(0);
            return Some(HollowingIndicator::SuspiciousMemoryGaps {
                gap_count: total_gaps,
                largest_gap,
            });
        }

        None
    }

    fn check_pe_header_anomalies(&self, regions: &[MemoryRegion]) -> Option<HollowingIndicator> {
        // Look for IMAGE regions that might have mismatched PE headers
        let image_regions: Vec<_> = regions
            .iter()
            .filter(|r| r.region_type == "IMAGE")
            .collect();

        // Check for unusual number of IMAGE regions
        if image_regions.len() > 50 {
            // Too many loaded modules might indicate DLL injection
            return Some(HollowingIndicator::MismatchedPEHeader);
        }

        // Check for IMAGE regions at unusual addresses
        for region in &image_regions {
            // PE images should typically be aligned to 64KB boundaries
            if region.base_address % 0x10000 != 0 {
                return Some(HollowingIndicator::MismatchedPEHeader);
            }
        }

        None
    }

    #[cfg(windows)]
    fn validate_pe_headers(
        &self,
        pid: u32,
        regions: &[MemoryRegion],
    ) -> Option<HollowingIndicator> {
        // Focus on main executable IMAGE regions
        let image_regions: Vec<_> = regions
            .iter()
            .filter(|r| r.region_type == "IMAGE")
            .take(5) // Check first 5 IMAGE regions (main exe + critical DLLs)
            .collect();

        for region in image_regions {
            match validate_pe_header(pid, region.base_address) {
                Ok(validation) => match validation {
                    PEHeaderValidation::Valid => continue,
                    PEHeaderValidation::InvalidDosSignature => {
                        return Some(HollowingIndicator::InvalidPEHeader {
                            validation: "Invalid DOS signature (not MZ)".to_string(),
                        });
                    }
                    PEHeaderValidation::InvalidNtSignature => {
                        return Some(HollowingIndicator::InvalidPEHeader {
                            validation: "Invalid NT signature (not PE)".to_string(),
                        });
                    }
                    PEHeaderValidation::InvalidHeaderOffset => {
                        return Some(HollowingIndicator::InvalidPEHeader {
                            validation: "Invalid PE header offset".to_string(),
                        });
                    }
                    PEHeaderValidation::MismatchedImageBase => {
                        return Some(HollowingIndicator::CorruptedPEStructure {
                            address: region.base_address,
                            reason: "Image base mismatch - possible hollowing".to_string(),
                        });
                    }
                    PEHeaderValidation::SuspiciousEntryPoint => {
                        return Some(HollowingIndicator::InvalidPEHeader {
                            validation: "Suspicious entry point location".to_string(),
                        });
                    }
                    PEHeaderValidation::CorruptedHeader => {
                        return Some(HollowingIndicator::CorruptedPEStructure {
                            address: region.base_address,
                            reason: "Corrupted PE header structure".to_string(),
                        });
                    }
                    PEHeaderValidation::NotPE => continue,
                },
                Err(_) => {
                    // Could not read memory - might be suspicious but don't report
                    continue;
                }
            }
        }

        None
    }

    #[cfg(not(windows))]
    fn validate_pe_headers(
        &self,
        _pid: u32,
        _regions: &[MemoryRegion],
    ) -> Option<HollowingIndicator> {
        // PE validation is Windows-specific
        None
    }

    fn check_entry_point_anomalies(
        &self,
        _process: &ProcessInfo,
        regions: &[MemoryRegion],
    ) -> Option<HollowingIndicator> {
        // In a real implementation, we would read the PE header to get the actual entry point
        // For now, we'll use heuristics based on memory layout

        // Look for executable regions that might contain the entry point
        let executable_regions: Vec<_> = regions
            .iter()
            .filter(|r| {
                matches!(
                    r.protection,
                    crate::MemoryProtection::ReadExecute
                        | crate::MemoryProtection::ReadWriteExecute
                ) && r.region_type == "PRIVATE"
            })
            .collect();

        // If there are many small private executable regions, the entry point might have been moved
        if executable_regions.len() > 5 {
            // Pick the first region as a potential suspicious entry point
            if let Some(region) = executable_regions.first() {
                return Some(HollowingIndicator::UnusualEntryPoint {
                    address: region.base_address,
                });
            }
        }

        None
    }

    /// Deep PE comparison with section hashing
    #[cfg(windows)]
    fn deep_pe_comparison(&self, process: &ProcessInfo) -> Option<Vec<HollowingIndicator>> {
        use sha2::{Digest, Sha256};
        use std::fs::File;
        use std::io::Read;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};

        let mut indicators = Vec::new();

        // Get the path to the executable on disk
        let disk_path = match &process.path {
            Some(path) => path,
            None => return None,
        };

        // Read PE from disk
        let mut disk_file = match File::open(disk_path) {
            Ok(f) => f,
            Err(_) => return None,
        };

        let mut disk_data = Vec::new();
        if disk_file.read_to_end(&mut disk_data).is_err() {
            return None;
        }

        // Parse PE sections from disk
        let disk_sections = match parse_pe_sections(&disk_data) {
            Ok(sections) => sections,
            Err(_) => return None,
        };

        // Read process memory
        unsafe {
            let handle = match OpenProcess(PROCESS_VM_READ, false, process.pid) {
                Ok(h) => h,
                Err(_) => return None,
            };

            // Assume base address (in real implementation, would enumerate modules)
            let base_address = 0x400000usize;

            // Read PE header from memory to get actual base
            let mut header_buf = vec![0u8; 0x1000];
            let mut bytes_read = 0usize;

            if ReadProcessMemory(
                handle,
                base_address as *const _,
                header_buf.as_mut_ptr() as *mut _,
                header_buf.len(),
                Some(&mut bytes_read),
            )
            .is_err()
            {
                let _ = CloseHandle(handle);
                return None;
            }

            // Parse sections from memory
            let memory_sections = match parse_pe_sections(&header_buf) {
                Ok(sections) => sections,
                Err(_) => {
                    let _ = CloseHandle(handle);
                    return None;
                }
            };

            // Compare each section
            for disk_section in &disk_sections {
                // Find corresponding section in memory
                if let Some(mem_section) =
                    memory_sections.iter().find(|s| s.name == disk_section.name)
                {
                    // Read section data from memory
                    let section_addr = base_address + mem_section.virtual_address;
                    let mut section_data = vec![0u8; mem_section.size];
                    let mut section_bytes_read = 0usize;

                    if ReadProcessMemory(
                        handle,
                        section_addr as *const _,
                        section_data.as_mut_ptr() as *mut _,
                        section_data.len(),
                        Some(&mut section_bytes_read),
                    )
                    .is_ok()
                        && section_bytes_read > 0
                    {
                        section_data.truncate(section_bytes_read);

                        // Compare hashes for code sections
                        if disk_section.is_code {
                            let disk_hash = Sha256::digest(&disk_section.data);
                            let memory_hash = Sha256::digest(&section_data);

                            if disk_hash != memory_hash {
                                // Calculate percentage difference
                                let different_bytes = disk_section
                                    .data
                                    .iter()
                                    .zip(section_data.iter())
                                    .filter(|(a, b)| a != b)
                                    .count();
                                let total_bytes = disk_section.data.len().min(section_data.len());
                                let modification_percentage =
                                    (different_bytes as f32 / total_bytes as f32) * 100.0;

                                if modification_percentage > 5.0 {
                                    // More than 5% modified
                                    indicators.push(HollowingIndicator::ModifiedCodeSection {
                                        section_name: disk_section.name.clone(),
                                        modification_percentage,
                                    });
                                }
                            }
                        }
                    }
                } else {
                    // Section exists in disk but not in memory - suspicious
                    if disk_section.is_code {
                        indicators.push(HollowingIndicator::CorruptedPEStructure {
                            address: base_address,
                            reason: format!("Missing section: {}", disk_section.name),
                        });
                    }
                }
            }

            let _ = CloseHandle(handle);
        }

        if indicators.is_empty() {
            None
        } else {
            Some(indicators)
        }
    }

    #[cfg(not(windows))]
    fn deep_pe_comparison(&self, _process: &ProcessInfo) -> Option<Vec<HollowingIndicator>> {
        None
    }
}

/// PE section information for comparison
#[derive(Debug, Clone)]
struct PESection {
    name: String,
    virtual_address: usize,
    size: usize,
    is_code: bool,
    data: Vec<u8>,
}

/// Parse PE sections from a buffer
fn parse_pe_sections(data: &[u8]) -> Result<Vec<PESection>> {
    use crate::GhostError;

    if data.len() < 0x40 {
        return Err(GhostError::ParseError("Buffer too small".to_string()));
    }

    // Check DOS signature
    if &data[0..2] != b"MZ" {
        return Err(GhostError::ParseError("Invalid DOS signature".to_string()));
    }

    // Get PE offset
    let pe_offset = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;

    if pe_offset + 0x18 >= data.len() {
        return Err(GhostError::ParseError("Invalid PE offset".to_string()));
    }

    // Check PE signature
    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err(GhostError::ParseError("Invalid PE signature".to_string()));
    }

    // Parse COFF header
    let number_of_sections =
        u16::from_le_bytes([data[pe_offset + 6], data[pe_offset + 7]]) as usize;
    let size_of_optional_header =
        u16::from_le_bytes([data[pe_offset + 20], data[pe_offset + 21]]) as usize;

    // Section headers start after optional header
    let section_table_offset = pe_offset + 24 + size_of_optional_header;

    let mut sections = Vec::new();

    for i in 0..number_of_sections {
        let section_offset = section_table_offset + (i * 40); // Each section header is 40 bytes

        if section_offset + 40 > data.len() {
            break;
        }

        // Section name (8 bytes)
        let name_bytes = &data[section_offset..section_offset + 8];
        let name = String::from_utf8_lossy(name_bytes)
            .trim_end_matches('\0')
            .to_string();

        // Virtual size and address
        let virtual_size = u32::from_le_bytes([
            data[section_offset + 8],
            data[section_offset + 9],
            data[section_offset + 10],
            data[section_offset + 11],
        ]) as usize;

        let virtual_address = u32::from_le_bytes([
            data[section_offset + 12],
            data[section_offset + 13],
            data[section_offset + 14],
            data[section_offset + 15],
        ]) as usize;

        // Size of raw data and pointer to raw data
        let size_of_raw_data = u32::from_le_bytes([
            data[section_offset + 16],
            data[section_offset + 17],
            data[section_offset + 18],
            data[section_offset + 19],
        ]) as usize;

        let pointer_to_raw_data = u32::from_le_bytes([
            data[section_offset + 20],
            data[section_offset + 21],
            data[section_offset + 22],
            data[section_offset + 23],
        ]) as usize;

        // Characteristics
        let characteristics = u32::from_le_bytes([
            data[section_offset + 36],
            data[section_offset + 37],
            data[section_offset + 38],
            data[section_offset + 39],
        ]);

        // Check if section contains code (IMAGE_SCN_CNT_CODE = 0x00000020)
        let is_code = (characteristics & 0x20) != 0;

        // Read section data
        let section_data =
            if pointer_to_raw_data > 0 && pointer_to_raw_data + size_of_raw_data <= data.len() {
                data[pointer_to_raw_data..pointer_to_raw_data + size_of_raw_data].to_vec()
            } else {
                Vec::new()
            };

        sections.push(PESection {
            name,
            virtual_address,
            size: virtual_size,
            is_code,
            data: section_data,
        });
    }

    Ok(sections)
}

impl Default for HollowingDetector {
    fn default() -> Self {
        Self::new()
    }
}

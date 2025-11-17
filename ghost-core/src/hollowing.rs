use crate::{GhostError, MemoryRegion, ProcessInfo, Result};

#[cfg(windows)]
use crate::memory::{validate_pe_header, read_pe_header_info, PEHeaderValidation};

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
    MemoryLayoutAnomaly { expected_size: usize, actual_size: usize },
    MismatchedPEHeader,
    InvalidPEHeader { validation: String },
    CorruptedPEStructure { address: usize, reason: String },
    UnusualEntryPoint { address: usize },
    SuspiciousMemoryGaps { gap_count: usize, largest_gap: usize },
}

impl std::fmt::Display for HollowingIndicator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnmappedMainImage => write!(f, "Main executable image appears unmapped"),
            Self::SuspiciousImageBase => write!(f, "Image base address is suspicious"),
            Self::MemoryLayoutAnomaly { expected_size, actual_size } => {
                write!(f, "Memory layout anomaly: expected {:#x}, found {:#x}", expected_size, actual_size)
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
            Self::SuspiciousMemoryGaps { gap_count, largest_gap } => {
                write!(f, "{} memory gaps detected, largest: {:#x} bytes", gap_count, largest_gap)
            }
        }
    }
}

/// Process hollowing detection engine
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
        process: &ProcessInfo,
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
            .filter(|r| matches!(r.protection, crate::MemoryProtection::ReadExecute | crate::MemoryProtection::ReadWriteExecute))
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
    fn validate_pe_headers(&self, pid: u32, regions: &[MemoryRegion]) -> Option<HollowingIndicator> {
        // Focus on main executable IMAGE regions
        let image_regions: Vec<_> = regions
            .iter()
            .filter(|r| r.region_type == "IMAGE")
            .take(5) // Check first 5 IMAGE regions (main exe + critical DLLs)
            .collect();

        for region in image_regions {
            match validate_pe_header(pid, region.base_address) {
                Ok(validation) => {
                    match validation {
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
                    }
                }
                Err(_) => {
                    // Could not read memory - might be suspicious but don't report
                    continue;
                }
            }
        }

        None
    }

    #[cfg(not(windows))]
    fn validate_pe_headers(&self, _pid: u32, _regions: &[MemoryRegion]) -> Option<HollowingIndicator> {
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
                matches!(r.protection, crate::MemoryProtection::ReadExecute | crate::MemoryProtection::ReadWriteExecute)
                    && r.region_type == "PRIVATE"
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
}

impl Default for HollowingDetector {
    fn default() -> Self {
        Self::new()
    }
}
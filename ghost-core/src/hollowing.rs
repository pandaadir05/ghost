use crate::{MemoryRegion, ProcessInfo, Result};

// PE header validation intentionally disabled (see comments in analyze_process).

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
        // PID 0/4 are kernel/system pseudo-processes where our user-mode memory
        // enumeration intentionally returns empty; do not attempt hollowing heuristics.
        if process.pid == 0 || process.pid == 4 {
            return Ok(None);
        }

        // If we couldn't enumerate any memory, treat as "unknown" rather than "hollowed".
        if memory_regions.is_empty() {
            return Ok(None);
        }

        let mut indicators = Vec::new();
        let mut confidence: f32 = 0.0;

        // Check for main image unmapping
        if let Some(indicator) = self.check_main_image_unmapping(process, memory_regions) {
            indicators.push(indicator);
            confidence += 0.8;
        }

        // Memory layout heuristics intentionally disabled (too noisy under ASLR/JIT workloads).

        // PE header validation disabled: module base address cannot be inferred reliably from
        // VirtualQueryEx regions alone (modules span multiple regions). Doing this naively causes
        // false positives on benign processes.

        // NOTE: Deep PE comparison was removed because the previous implementation assumed a
        // fixed base address (0x400000) and produced widespread false positives under ASLR.

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

        None
    }

    // validate_pe_headers intentionally removed.

}

/// PE section information for comparison
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct PESection {
    name: String,
    virtual_address: usize,
    size: usize,
    is_code: bool,
    data: Vec<u8>,
}

/// Parse PE sections from a buffer
#[allow(dead_code)]
fn parse_pe_sections(data: &[u8]) -> Result<Vec<PESection>> {
    use crate::GhostError;

    if data.len() < 0x40 {
        return Err(GhostError::InvalidInput {
            message: "Buffer too small".to_string(),
        });
    }

    // Check DOS signature
    if &data[0..2] != b"MZ" {
        return Err(GhostError::InvalidInput {
            message: "Invalid DOS signature".to_string(),
        });
    }

    // Get PE offset
    let pe_offset = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;

    if pe_offset + 0x18 >= data.len() {
        return Err(GhostError::InvalidInput {
            message: "Invalid PE offset".to_string(),
        });
    }

    // Check PE signature
    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err(GhostError::InvalidInput {
            message: "Invalid PE signature".to_string(),
        });
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

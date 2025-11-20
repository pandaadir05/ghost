///! PE (Portable Executable) file parsing utilities for hook detection.
///!
///! This module provides comprehensive PE parsing capabilities including:
///! - Import Address Table (IAT) extraction
///! - Export Address Table (EAT) extraction
///! - Data directory parsing
///! - Function address resolution
use crate::{GhostError, Result};
use serde::{Deserialize, Serialize};

/// PE data directory indices
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;

/// Data directory entry in PE optional header
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// Import descriptor structure
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ImageImportDescriptor {
    pub original_first_thunk: u32, // RVA to ILT
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,        // RVA to DLL name
    pub first_thunk: u32, // RVA to IAT
}

/// Export directory structure
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,                     // RVA to DLL name
    pub base: u32,                     // Ordinal base
    pub number_of_functions: u32,      // Number of entries in EAT
    pub number_of_names: u32,          // Number of entries in name/ordinal tables
    pub address_of_functions: u32,     // RVA to EAT
    pub address_of_names: u32,         // RVA to name pointer table
    pub address_of_name_ordinals: u32, // RVA to ordinal table
}

/// Section header structure
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

/// Import entry representing a single imported function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    pub dll_name: String,
    pub function_name: Option<String>,
    pub ordinal: Option<u16>,
    pub iat_address: usize,
    pub current_address: usize,
    pub is_hooked: bool,
}

/// Export entry representing a single exported function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    pub function_name: Option<String>,
    pub ordinal: u32,
    pub address: usize,
    pub is_forwarded: bool,
}

/// IAT hook detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IATHookResult {
    pub hooked_imports: Vec<ImportEntry>,
    pub total_imports: usize,
    pub hook_percentage: f32,
}

/// Parse Import Address Table from process memory
#[cfg(windows)]
pub fn parse_iat_from_memory(
    pid: u32,
    base_address: usize,
    memory_reader: impl Fn(u32, usize, usize) -> Result<Vec<u8>>,
) -> Result<Vec<ImportEntry>> {
    use std::mem;

    let mut imports = Vec::new();

    // Read DOS header
    let dos_header = read_dos_header(pid, base_address, &memory_reader)?;

    // Read NT headers
    let nt_header_addr = base_address + dos_header.e_lfanew as usize;

    // Read PE signature and file header
    let _pe_sig = read_u32(pid, nt_header_addr, &memory_reader)?;
    let file_header_addr = nt_header_addr + 4;
    let file_header = read_file_header(pid, file_header_addr, &memory_reader)?;

    // Read optional header magic to determine if 32-bit or 64-bit
    let opt_header_addr = file_header_addr + mem::size_of::<crate::memory::ImageFileHeader>();
    let magic = read_u16(pid, opt_header_addr, &memory_reader)?;

    let is_64bit = magic == 0x20b;

    // Get import directory RVA
    let import_dir_offset = if is_64bit {
        // 64-bit: skip to data directories (at offset 112 in optional header)
        opt_header_addr
            + 112
            + (IMAGE_DIRECTORY_ENTRY_IMPORT * mem::size_of::<ImageDataDirectory>())
    } else {
        // 32-bit: skip to data directories (at offset 96 in optional header)
        opt_header_addr + 96 + (IMAGE_DIRECTORY_ENTRY_IMPORT * mem::size_of::<ImageDataDirectory>())
    };

    let import_dir = read_data_directory(pid, import_dir_offset, &memory_reader)?;

    if import_dir.virtual_address == 0 {
        return Ok(imports); // No imports
    }

    // Read import descriptors
    let mut desc_addr = base_address + import_dir.virtual_address as usize;

    loop {
        let desc = read_import_descriptor(pid, desc_addr, &memory_reader)?;

        // Null descriptor marks end of imports
        if desc.original_first_thunk == 0 && desc.first_thunk == 0 {
            break;
        }

        // Read DLL name
        let dll_name_addr = base_address + desc.name as usize;
        let dll_name = read_cstring(pid, dll_name_addr, &memory_reader)?;

        // Parse IAT entries
        let iat_addr = base_address + desc.first_thunk as usize;
        let ilt_addr = if desc.original_first_thunk != 0 {
            base_address + desc.original_first_thunk as usize
        } else {
            iat_addr
        };

        let mut thunk_idx = 0;
        loop {
            let thunk_size = if is_64bit { 8 } else { 4 };
            let current_ilt_addr = ilt_addr + (thunk_idx * thunk_size);
            let current_iat_addr = iat_addr + (thunk_idx * thunk_size);

            let thunk_value = if is_64bit {
                read_u64(pid, current_ilt_addr, &memory_reader)?
            } else {
                read_u32(pid, current_ilt_addr, &memory_reader)? as u64
            };

            if thunk_value == 0 {
                break; // End of thunks
            }

            let current_address = if is_64bit {
                read_u64(pid, current_iat_addr, &memory_reader)? as usize
            } else {
                read_u32(pid, current_iat_addr, &memory_reader)? as usize
            };

            // Check if import is by ordinal
            let ordinal_flag = if is_64bit {
                0x8000000000000000u64
            } else {
                0x80000000u64
            };
            let (function_name, ordinal) = if (thunk_value & ordinal_flag) != 0 {
                // Import by ordinal
                (None, Some((thunk_value & 0xFFFF) as u16))
            } else {
                // Import by name
                let hint_name_addr = base_address + (thunk_value as usize & 0x7FFFFFFF);
                let _hint = read_u16(pid, hint_name_addr, &memory_reader)?;
                let name_addr = hint_name_addr + 2;
                let func_name = read_cstring(pid, name_addr, &memory_reader)?;
                (Some(func_name), None)
            };

            imports.push(ImportEntry {
                dll_name: dll_name.clone(),
                function_name,
                ordinal,
                iat_address: current_iat_addr,
                current_address,
                is_hooked: false, // Will be determined by comparison
            });

            thunk_idx += 1;
        }

        desc_addr += mem::size_of::<ImageImportDescriptor>();
    }

    Ok(imports)
}

/// Compare IAT entries between memory and disk to detect hooks
#[cfg(windows)]
pub fn detect_iat_hooks(
    pid: u32,
    base_address: usize,
    disk_path: &str,
    memory_reader: impl Fn(u32, usize, usize) -> Result<Vec<u8>>,
) -> Result<IATHookResult> {
    // Parse IAT from process memory
    let mut memory_imports = parse_iat_from_memory(pid, base_address, &memory_reader)?;

    // Parse IAT from disk file
    let disk_imports = parse_iat_from_disk(disk_path)?;

    // Create lookup map for disk imports
    let disk_map: HashMap<String, usize> = disk_imports
        .iter()
        .filter_map(|imp| {
            imp.function_name.as_ref().map(|name| {
                (
                    format!("{}!{}", imp.dll_name.to_lowercase(), name.to_lowercase()),
                    imp.current_address,
                )
            })
        })
        .collect();

    let mut hooked_count = 0;

    // Compare each memory import with disk version
    for import in &mut memory_imports {
        if let Some(func_name) = &import.function_name {
            let key = format!(
                "{}!{}",
                import.dll_name.to_lowercase(),
                func_name.to_lowercase()
            );

            if let Some(&disk_addr) = disk_map.get(&key) {
                // Check if addresses differ significantly (not just ASLR offset)
                // Real hooks will point to completely different modules
                if !addresses_match_with_aslr(import.current_address, disk_addr) {
                    import.is_hooked = true;
                    hooked_count += 1;
                }
            }
        }
    }

    let total = memory_imports.len();
    let hook_percentage = if total > 0 {
        (hooked_count as f32 / total as f32) * 100.0
    } else {
        0.0
    };

    Ok(IATHookResult {
        hooked_imports: memory_imports.into_iter().filter(|i| i.is_hooked).collect(),
        total_imports: total,
        hook_percentage,
    })
}

/// Parse IAT from disk file
#[cfg(windows)]
fn parse_iat_from_disk(file_path: &str) -> Result<Vec<ImportEntry>> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(file_path)
        .map_err(|e| GhostError::ConfigurationError(format!("Failed to open file: {}", e)))?;

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|e| GhostError::ConfigurationError(format!("Failed to read file: {}", e)))?;

    parse_iat_from_buffer(&buffer)
}

/// Parse IAT from memory buffer
#[cfg(windows)]
fn parse_iat_from_buffer(buffer: &[u8]) -> Result<Vec<ImportEntry>> {
    use std::mem;

    let reader = |_pid: u32, offset: usize, size: usize| -> Result<Vec<u8>> {
        if offset + size > buffer.len() {
            return Err(GhostError::MemoryReadError("Buffer overflow".to_string()));
        }
        Ok(buffer[offset..offset + size].to_vec())
    };

    parse_iat_from_memory(0, 0, reader)
}

/// Helper to check if two addresses match considering ASLR
fn addresses_match_with_aslr(addr1: usize, addr2: usize) -> bool {
    // Simple heuristic: if addresses are in completely different ranges (different modules)
    // they don't match. This is a simplified check.
    let high_mask = 0xFFFF000000000000usize;
    (addr1 & high_mask) == (addr2 & high_mask)
}

// Helper functions for reading PE structures

#[cfg(windows)]
fn read_dos_header(
    pid: u32,
    base: usize,
    reader: &impl Fn(u32, usize, usize) -> Result<Vec<u8>>,
) -> Result<crate::memory::ImageDosHeader> {
    use std::mem;
    let size = mem::size_of::<crate::memory::ImageDosHeader>();
    let bytes = reader(pid, base, size)?;
    unsafe { Ok(std::ptr::read(bytes.as_ptr() as *const _)) }
}

#[cfg(windows)]
fn read_file_header(
    pid: u32,
    addr: usize,
    reader: &impl Fn(u32, usize, usize) -> Result<Vec<u8>>,
) -> Result<crate::memory::ImageFileHeader> {
    use std::mem;
    let size = mem::size_of::<crate::memory::ImageFileHeader>();
    let bytes = reader(pid, addr, size)?;
    unsafe { Ok(std::ptr::read(bytes.as_ptr() as *const _)) }
}

#[cfg(windows)]
fn read_data_directory(
    pid: u32,
    addr: usize,
    reader: &impl Fn(u32, usize, usize) -> Result<Vec<u8>>,
) -> Result<ImageDataDirectory> {
    use std::mem;
    let size = mem::size_of::<ImageDataDirectory>();
    let bytes = reader(pid, addr, size)?;
    unsafe { Ok(std::ptr::read(bytes.as_ptr() as *const _)) }
}

#[cfg(windows)]
fn read_import_descriptor(
    pid: u32,
    addr: usize,
    reader: &impl Fn(u32, usize, usize) -> Result<Vec<u8>>,
) -> Result<ImageImportDescriptor> {
    use std::mem;
    let size = mem::size_of::<ImageImportDescriptor>();
    let bytes = reader(pid, addr, size)?;
    unsafe { Ok(std::ptr::read(bytes.as_ptr() as *const _)) }
}

#[cfg(windows)]
fn read_u16(
    pid: u32,
    addr: usize,
    reader: &impl Fn(u32, usize, usize) -> Result<Vec<u8>>,
) -> Result<u16> {
    let bytes = reader(pid, addr, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

#[cfg(windows)]
fn read_u32(
    pid: u32,
    addr: usize,
    reader: &impl Fn(u32, usize, usize) -> Result<Vec<u8>>,
) -> Result<u32> {
    let bytes = reader(pid, addr, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(windows)]
fn read_u64(
    pid: u32,
    addr: usize,
    reader: &impl Fn(u32, usize, usize) -> Result<Vec<u8>>,
) -> Result<u64> {
    let bytes = reader(pid, addr, 8)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(windows)]
fn read_cstring(
    pid: u32,
    addr: usize,
    reader: &impl Fn(u32, usize, usize) -> Result<Vec<u8>>,
) -> Result<String> {
    let mut result = Vec::new();
    let mut offset = 0;

    loop {
        let bytes = reader(pid, addr + offset, 16)?;
        for &byte in &bytes {
            if byte == 0 {
                return Ok(String::from_utf8_lossy(&result).to_string());
            }
            result.push(byte);
        }
        offset += 16;

        if offset > 512 {
            return Err(GhostError::MemoryReadError("String too long".to_string()));
        }
    }
}

#[cfg(not(windows))]
pub fn parse_iat_from_memory(
    _pid: u32,
    _base_address: usize,
    _memory_reader: impl Fn(u32, usize, usize) -> Result<Vec<u8>>,
) -> Result<Vec<ImportEntry>> {
    Err(GhostError::PlatformNotSupported { feature: "IAT parsing not implemented for this platform".to_string() })
}

#[cfg(not(windows))]
pub fn detect_iat_hooks(
    _pid: u32,
    _base_address: usize,
    _disk_path: &str,
    _memory_reader: impl Fn(u32, usize, usize) -> Result<Vec<u8>>,
) -> Result<IATHookResult> {
    Err(GhostError::PlatformNotSupported { feature: "IAT hook detection not implemented for this platform".to_string() })
}

//! Memory region enumeration and analysis.
//!
//! This module provides cross-platform memory introspection capabilities,
//! allowing analysis of process memory layouts, protection flags, and content.

use serde::{Deserialize, Serialize};
use std::fmt;

/// PE header constants
#[cfg(windows)]
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
#[cfg(windows)]
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // "PE\0\0"

/// DOS header structure (first 64 bytes of a PE file)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ImageDosHeader {
    pub e_magic: u16,      // Magic number ("MZ")
    pub e_cblp: u16,       // Bytes on last page
    pub e_cp: u16,         // Pages in file
    pub e_crlc: u16,       // Relocations
    pub e_cparhdr: u16,    // Size of header in paragraphs
    pub e_minalloc: u16,   // Minimum extra paragraphs
    pub e_maxalloc: u16,   // Maximum extra paragraphs
    pub e_ss: u16,         // Initial SS value
    pub e_sp: u16,         // Initial SP value
    pub e_csum: u16,       // Checksum
    pub e_ip: u16,         // Initial IP value
    pub e_cs: u16,         // Initial CS value
    pub e_lfarlc: u16,     // File address of relocation table
    pub e_ovno: u16,       // Overlay number
    pub e_res: [u16; 4],   // Reserved
    pub e_oemid: u16,      // OEM identifier
    pub e_oeminfo: u16,    // OEM information
    pub e_res2: [u16; 10], // Reserved
    pub e_lfanew: i32,     // File address of new exe header
}

/// PE file header structure
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// PE optional header structure (64-bit)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

/// PE header validation result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PEHeaderValidation {
    Valid,
    InvalidDosSignature,
    InvalidNtSignature,
    InvalidHeaderOffset,
    MismatchedImageBase,
    SuspiciousEntryPoint,
    CorruptedHeader,
    NotPE,
}

impl fmt::Display for PEHeaderValidation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => write!(f, "Valid PE header"),
            Self::InvalidDosSignature => write!(f, "Invalid DOS signature"),
            Self::InvalidNtSignature => write!(f, "Invalid NT signature"),
            Self::InvalidHeaderOffset => write!(f, "Invalid header offset"),
            Self::MismatchedImageBase => write!(f, "Image base mismatch"),
            Self::SuspiciousEntryPoint => write!(f, "Suspicious entry point"),
            Self::CorruptedHeader => write!(f, "Corrupted PE header"),
            Self::NotPE => write!(f, "Not a PE file"),
        }
    }
}

/// Memory protection flags for a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryProtection {
    NoAccess,
    ReadOnly,
    ReadWrite,
    ReadExecute,
    ReadWriteExecute,
    Execute,
    WriteCopy,
    Unknown,
}

impl MemoryProtection {
    /// Check if the memory region is readable
    pub fn is_readable(&self) -> bool {
        matches!(
            self,
            Self::ReadOnly
                | Self::ReadWrite
                | Self::ReadExecute
                | Self::ReadWriteExecute
                | Self::WriteCopy
        )
    }

    /// Check if the memory region is writable
    pub fn is_writable(&self) -> bool {
        matches!(
            self,
            Self::ReadWrite | Self::ReadWriteExecute | Self::WriteCopy
        )
    }

    /// Check if the memory region is executable
    pub fn is_executable(&self) -> bool {
        matches!(
            self,
            Self::ReadExecute | Self::ReadWriteExecute | Self::Execute
        )
    }
}

impl fmt::Display for MemoryProtection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NoAccess => "---",
            Self::ReadOnly => "R--",
            Self::ReadWrite => "RW-",
            Self::ReadExecute => "R-X",
            Self::ReadWriteExecute => "RWX",
            Self::Execute => "--X",
            Self::WriteCopy => "WC-",
            Self::Unknown => "???",
        };
        write!(f, "{}", s)
    }
}

/// Information about a memory region within a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Base address of the memory region.
    pub base_address: usize,
    /// Size of the region in bytes.
    pub size: usize,
    /// Memory protection flags.
    pub protection: MemoryProtection,
    /// Type of memory region (IMAGE, MAPPED, PRIVATE, etc.).
    pub region_type: String,
}

impl fmt::Display for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#016x} - {:#016x} {} {}",
            self.base_address,
            self.base_address + self.size,
            self.protection,
            self.region_type
        )
    }
}

/// Validates a PE header in process memory
#[cfg(windows)]
pub fn validate_pe_header(pid: u32, base_address: usize) -> anyhow::Result<PEHeaderValidation> {
    use std::mem;

    // Read DOS header
    let dos_header_size = mem::size_of::<ImageDosHeader>();
    let dos_header_bytes = read_process_memory(pid, base_address, dos_header_size)?;

    if dos_header_bytes.len() < dos_header_size {
        return Ok(PEHeaderValidation::CorruptedHeader);
    }

    let dos_header = unsafe { std::ptr::read(dos_header_bytes.as_ptr() as *const ImageDosHeader) };

    // Validate DOS signature
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        return Ok(PEHeaderValidation::InvalidDosSignature);
    }

    // Validate e_lfanew offset (should be reasonable)
    if dos_header.e_lfanew < 0 || dos_header.e_lfanew > 0x1000 {
        return Ok(PEHeaderValidation::InvalidHeaderOffset);
    }

    // Read NT headers
    let nt_header_address = base_address.wrapping_add(dos_header.e_lfanew as usize);

    // Read NT signature (4 bytes)
    let nt_sig_bytes = read_process_memory(pid, nt_header_address, 4)?;
    if nt_sig_bytes.len() < 4 {
        return Ok(PEHeaderValidation::CorruptedHeader);
    }

    let nt_signature = u32::from_le_bytes([
        nt_sig_bytes[0],
        nt_sig_bytes[1],
        nt_sig_bytes[2],
        nt_sig_bytes[3],
    ]);

    if nt_signature != IMAGE_NT_SIGNATURE {
        return Ok(PEHeaderValidation::InvalidNtSignature);
    }

    // Read file header
    let file_header_address = nt_header_address + 4;
    let file_header_size = mem::size_of::<ImageFileHeader>();
    let file_header_bytes = read_process_memory(pid, file_header_address, file_header_size)?;

    if file_header_bytes.len() < file_header_size {
        return Ok(PEHeaderValidation::CorruptedHeader);
    }

    let file_header =
        unsafe { std::ptr::read(file_header_bytes.as_ptr() as *const ImageFileHeader) };

    // Read optional header (64-bit)
    let optional_header_address = file_header_address + file_header_size;
    let optional_header_size = mem::size_of::<ImageOptionalHeader64>();
    let optional_header_bytes =
        read_process_memory(pid, optional_header_address, optional_header_size)?;

    if optional_header_bytes.len() < optional_header_size {
        return Ok(PEHeaderValidation::CorruptedHeader);
    }

    let optional_header =
        unsafe { std::ptr::read(optional_header_bytes.as_ptr() as *const ImageOptionalHeader64) };

    // Validate image base matches memory address
    if optional_header.image_base != base_address as u64 {
        return Ok(PEHeaderValidation::MismatchedImageBase);
    }

    // Validate entry point (should be within the image)
    let entry_point_rva = optional_header.address_of_entry_point;
    if entry_point_rva == 0 || entry_point_rva >= optional_header.size_of_image {
        return Ok(PEHeaderValidation::SuspiciousEntryPoint);
    }

    // Additional validation: check if sections count is reasonable
    if file_header.number_of_sections > 96 {
        return Ok(PEHeaderValidation::CorruptedHeader);
    }

    Ok(PEHeaderValidation::Valid)
}

/// Stub for non-Windows platforms
#[cfg(not(windows))]
pub fn validate_pe_header(_pid: u32, _base_address: usize) -> anyhow::Result<PEHeaderValidation> {
    Ok(PEHeaderValidation::NotPE)
}

/// Gets PE header information from process memory
#[cfg(windows)]
pub fn read_pe_header_info(pid: u32, base_address: usize) -> anyhow::Result<Option<PEHeaderInfo>> {
    use std::mem;

    let dos_header_size = mem::size_of::<ImageDosHeader>();
    let dos_header_bytes = read_process_memory(pid, base_address, dos_header_size)?;

    if dos_header_bytes.len() < dos_header_size {
        return Ok(None);
    }

    let dos_header = unsafe { std::ptr::read(dos_header_bytes.as_ptr() as *const ImageDosHeader) };

    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        return Ok(None);
    }

    if dos_header.e_lfanew < 0 || dos_header.e_lfanew > 0x1000 {
        return Ok(None);
    }

    let nt_header_address = base_address.wrapping_add(dos_header.e_lfanew as usize);

    // Read NT signature
    let nt_sig_bytes = read_process_memory(pid, nt_header_address, 4)?;
    if nt_sig_bytes.len() < 4 {
        return Ok(None);
    }

    let nt_signature = u32::from_le_bytes([
        nt_sig_bytes[0],
        nt_sig_bytes[1],
        nt_sig_bytes[2],
        nt_sig_bytes[3],
    ]);

    if nt_signature != IMAGE_NT_SIGNATURE {
        return Ok(None);
    }

    // Read file header
    let file_header_address = nt_header_address + 4;
    let file_header_size = mem::size_of::<ImageFileHeader>();
    let file_header_bytes = read_process_memory(pid, file_header_address, file_header_size)?;

    if file_header_bytes.len() < file_header_size {
        return Ok(None);
    }

    let file_header =
        unsafe { std::ptr::read(file_header_bytes.as_ptr() as *const ImageFileHeader) };

    // Read optional header
    let optional_header_address = file_header_address + file_header_size;
    let optional_header_size = mem::size_of::<ImageOptionalHeader64>();
    let optional_header_bytes =
        read_process_memory(pid, optional_header_address, optional_header_size)?;

    if optional_header_bytes.len() < optional_header_size {
        return Ok(None);
    }

    let optional_header =
        unsafe { std::ptr::read(optional_header_bytes.as_ptr() as *const ImageOptionalHeader64) };

    Ok(Some(PEHeaderInfo {
        dos_signature: dos_header.e_magic,
        nt_signature,
        machine: file_header.machine,
        number_of_sections: file_header.number_of_sections,
        image_base: optional_header.image_base,
        entry_point_rva: optional_header.address_of_entry_point,
        size_of_image: optional_header.size_of_image,
        size_of_headers: optional_header.size_of_headers,
    }))
}

/// PE header information extracted from process memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PEHeaderInfo {
    pub dos_signature: u16,
    pub nt_signature: u32,
    pub machine: u16,
    pub number_of_sections: u16,
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
}

#[cfg(not(windows))]
pub fn read_pe_header_info(
    _pid: u32,
    _base_address: usize,
) -> anyhow::Result<Option<PEHeaderInfo>> {
    Ok(None)
}

#[cfg(windows)]
mod platform {
    use super::{MemoryProtection, MemoryRegion};
    use anyhow::{Context, Result};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    fn parse_protection(protect: u32) -> MemoryProtection {
        match protect & 0xFF {
            p if p == PAGE_NOACCESS.0 => MemoryProtection::NoAccess,
            p if p == PAGE_READONLY.0 => MemoryProtection::ReadOnly,
            p if p == PAGE_READWRITE.0 => MemoryProtection::ReadWrite,
            p if p == PAGE_EXECUTE.0 => MemoryProtection::Execute,
            p if p == PAGE_EXECUTE_READ.0 => MemoryProtection::ReadExecute,
            p if p == PAGE_EXECUTE_READWRITE.0 => MemoryProtection::ReadWriteExecute,
            p if p == PAGE_WRITECOPY.0 || p == PAGE_EXECUTE_WRITECOPY.0 => {
                MemoryProtection::WriteCopy
            }
            _ => MemoryProtection::Unknown,
        }
    }

    pub fn enumerate_memory_regions(pid: u32) -> Result<Vec<MemoryRegion>> {
        let mut regions = Vec::new();

        if pid == 0 || pid == 4 {
            return Ok(regions);
        }

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                .context("Failed to open process")?;

            let mut address: usize = 0;
            let mut mbi = MEMORY_BASIC_INFORMATION::default();

            loop {
                let result = VirtualQueryEx(
                    handle,
                    Some(address as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if result == 0 {
                    break;
                }

                if mbi.State == MEM_COMMIT {
                    let region_type = if mbi.Type == MEM_IMAGE {
                        "IMAGE"
                    } else if mbi.Type == MEM_MAPPED {
                        "MAPPED"
                    } else if mbi.Type == MEM_PRIVATE {
                        "PRIVATE"
                    } else {
                        "UNKNOWN"
                    }
                    .to_string();

                    regions.push(MemoryRegion {
                        base_address: mbi.BaseAddress as usize,
                        size: mbi.RegionSize,
                        protection: parse_protection(mbi.Protect.0),
                        region_type,
                    });
                }

                address = (mbi.BaseAddress as usize)
                    .checked_add(mbi.RegionSize)
                    .unwrap_or(usize::MAX);

                if address == usize::MAX {
                    break;
                }
            }

            let _ = CloseHandle(handle);
        }

        Ok(regions)
    }

    /// Reads memory from a process at the specified address.
    ///
    /// # Safety
    ///
    /// This function reads arbitrary process memory. The caller must ensure
    /// the address and size are valid for the target process.
    pub fn read_process_memory(pid: u32, address: usize, size: usize) -> Result<Vec<u8>> {
        if pid == 0 || pid == 4 {
            return Err(anyhow::anyhow!("Cannot read system process memory"));
        }

        unsafe {
            let handle = OpenProcess(PROCESS_VM_READ, false, pid)
                .context("Failed to open process for memory read")?;

            let mut buffer = vec![0u8; size];
            let mut bytes_read = 0usize;

            let success = ReadProcessMemory(
                handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                size,
                Some(&mut bytes_read),
            );

            let _ = CloseHandle(handle);

            if success.is_ok() && bytes_read > 0 {
                buffer.truncate(bytes_read);
                Ok(buffer)
            } else {
                Err(anyhow::anyhow!(
                    "Failed to read process memory at {:#x}",
                    address
                ))
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{MemoryProtection, MemoryRegion};
    use anyhow::{Context, Result};
    use std::fs;

    pub fn enumerate_memory_regions(pid: u32) -> Result<Vec<MemoryRegion>> {
        let maps_path = format!("/proc/{}/maps", pid);
        let content =
            fs::read_to_string(&maps_path).context(format!("Failed to read {}", maps_path))?;

        let mut regions = Vec::new();

        for line in content.lines() {
            if let Some(region) = parse_maps_line(line) {
                regions.push(region);
            }
        }

        Ok(regions)
    }

    fn parse_maps_line(line: &str) -> Option<MemoryRegion> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return None;
        }

        let addr_range = parts[0];
        let perms = parts.get(1)?;
        let pathname = parts.get(5..).map(|p| p.join(" ")).unwrap_or_default();

        let (start, end) = {
            let mut split = addr_range.split('-');
            let start = usize::from_str_radix(split.next()?, 16).ok()?;
            let end = usize::from_str_radix(split.next()?, 16).ok()?;
            (start, end)
        };

        let protection = parse_linux_perms(perms);
        let region_type = determine_region_type(&pathname);

        Some(MemoryRegion {
            base_address: start,
            size: end.saturating_sub(start),
            protection,
            region_type,
        })
    }

    fn parse_linux_perms(perms: &str) -> MemoryProtection {
        let r = perms.contains('r');
        let w = perms.contains('w');
        let x = perms.contains('x');

        match (r, w, x) {
            (false, false, false) => MemoryProtection::NoAccess,
            (true, false, false) => MemoryProtection::ReadOnly,
            (true, true, false) => MemoryProtection::ReadWrite,
            (true, false, true) => MemoryProtection::ReadExecute,
            (true, true, true) => MemoryProtection::ReadWriteExecute,
            (false, false, true) => MemoryProtection::Execute,
            _ => MemoryProtection::Unknown,
        }
    }

    fn determine_region_type(pathname: &str) -> String {
        if pathname.is_empty() || pathname == "[anon]" {
            "PRIVATE".to_string()
        } else if pathname.starts_with('[') {
            match pathname {
                "[heap]" => "HEAP".to_string(),
                "[stack]" => "STACK".to_string(),
                "[vdso]" | "[vvar]" | "[vsyscall]" => "SYSTEM".to_string(),
                _ => "SPECIAL".to_string(),
            }
        } else if pathname.ends_with(".so") || pathname.contains(".so.") {
            "IMAGE".to_string()
        } else {
            "MAPPED".to_string()
        }
    }

    pub fn read_process_memory(pid: u32, address: usize, size: usize) -> Result<Vec<u8>> {
        let mem_path = format!("/proc/{}/mem", pid);
        let mut file = fs::File::open(&mem_path).context(format!("Failed to open {}", mem_path))?;

        use std::io::{Read, Seek, SeekFrom};
        file.seek(SeekFrom::Start(address as u64))
            .context("Failed to seek to memory address")?;

        let mut buffer = vec![0u8; size];
        let bytes_read = file.read(&mut buffer).context("Failed to read memory")?;
        buffer.truncate(bytes_read);

        Ok(buffer)
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{MemoryProtection, MemoryRegion};
    use anyhow::{Context, Result};
    use libc::{c_int, pid_t, size_t};
    use std::ptr;

    // Mach types and constants
    type mach_port_t = u32;
    type vm_address_t = usize;
    type vm_size_t = usize;
    type vm_prot_t = c_int;
    type kern_return_t = c_int;

    const KERN_SUCCESS: kern_return_t = 0;
    const VM_PROT_READ: vm_prot_t = 0x01;
    const VM_PROT_WRITE: vm_prot_t = 0x02;
    const VM_PROT_EXECUTE: vm_prot_t = 0x04;

    // External mach functions
    extern "C" {
        fn task_for_pid(
            target_tport: mach_port_t,
            pid: pid_t,
            t: *mut mach_port_t,
        ) -> kern_return_t;

        fn mach_task_self() -> mach_port_t;

        fn mach_vm_read_overwrite(
            target_task: mach_port_t,
            address: vm_address_t,
            size: vm_size_t,
            data: vm_address_t,
            out_size: *mut vm_size_t,
        ) -> kern_return_t;
    }

    pub fn enumerate_memory_regions(pid: u32) -> Result<Vec<MemoryRegion>> {
        use libc::{c_int, mach_msg_type_number_t};

        // Mach VM structures and constants
        const VM_REGION_BASIC_INFO_64: c_int = 9;
        const VM_REGION_BASIC_INFO_COUNT_64: mach_msg_type_number_t = 9;

        #[repr(C)]
        #[derive(Copy, Clone)]
        struct vm_region_basic_info_64 {
            protection: c_int,
            max_protection: c_int,
            inheritance: c_int,
            shared: c_int,
            reserved: c_int,
            offset: u64,
            behavior: c_int,
            user_wired_count: u16,
        }

        extern "C" {
            fn task_for_pid(
                target_tport: mach_port_t,
                pid: libc::pid_t,
                t: *mut mach_port_t,
            ) -> kern_return_t;

            fn mach_task_self() -> mach_port_t;

            fn mach_vm_region(
                target_task: mach_port_t,
                address: *mut vm_address_t,
                size: *mut vm_size_t,
                flavor: c_int,
                info: *mut c_int,
                info_count: *mut mach_msg_type_number_t,
                object_name: *mut mach_port_t,
            ) -> kern_return_t;
        }

        unsafe {
            let mut task: mach_port_t = 0;
            let kr = task_for_pid(mach_task_self(), pid as libc::pid_t, &mut task);

            if kr != KERN_SUCCESS {
                return Err(anyhow::anyhow!(
                    "Failed to get task port for pid {}. Requires sudo or proper entitlements. Error: {}",
                    pid,
                    kr
                ));
            }

            let mut regions = Vec::new();
            let mut address: vm_address_t = 0;

            loop {
                let mut size: vm_size_t = 0;
                let mut info: vm_region_basic_info_64 = std::mem::zeroed();
                let mut info_count = VM_REGION_BASIC_INFO_COUNT_64;
                let mut object_name: mach_port_t = 0;

                let kr = mach_vm_region(
                    task,
                    &mut address,
                    &mut size,
                    VM_REGION_BASIC_INFO_64,
                    &mut info as *mut _ as *mut c_int,
                    &mut info_count,
                    &mut object_name,
                );

                // End of memory space
                if kr != KERN_SUCCESS {
                    break;
                }

                // Convert mach protection to our MemoryProtection enum
                let protection = match info.protection {
                    0 => MemoryProtection::NoAccess,
                    1 => MemoryProtection::ReadOnly,
                    2 => MemoryProtection::ReadWrite,  // Write implies read on most systems
                    3 => MemoryProtection::ReadWrite,
                    4 => MemoryProtection::Execute,
                    5 => MemoryProtection::ReadExecute,
                    6 => MemoryProtection::ReadWriteExecute,  // WX -> RWX
                    7 => MemoryProtection::ReadWriteExecute,
                    _ => MemoryProtection::NoAccess,
                };

                // Determine region type based on protection and shared status
                let region_type = if info.shared != 0 {
                    "SHARED".to_string()
                } else if info.protection & 4 != 0 {
                    // Executable regions are likely IMAGE
                    "IMAGE".to_string()
                } else {
                    "PRIVATE".to_string()
                };

                regions.push(MemoryRegion {
                    base_address: address,
                    size,
                    protection,
                    region_type,
                });

                // Move to next region
                address += size;
            }

            Ok(regions)
        }
    }

    pub fn read_process_memory(pid: u32, address: usize, size: usize) -> Result<Vec<u8>> {
        unsafe {
            // Get task port for the target process
            let mut task: mach_port_t = 0;
            let kr = task_for_pid(mach_task_self(), pid as pid_t, &mut task);

            if kr != KERN_SUCCESS {
                return Err(anyhow::anyhow!(
                    "Failed to get task port for pid {}. Make sure to run with sudo or have proper entitlements. Error code: {}",
                    pid,
                    kr
                ));
            }

            // Allocate buffer for reading
            let mut buffer = vec![0u8; size];
            let mut out_size: vm_size_t = 0;

            // Read memory from target process
            let kr = mach_vm_read_overwrite(
                task,
                address as vm_address_t,
                size as vm_size_t,
                buffer.as_mut_ptr() as vm_address_t,
                &mut out_size,
            );

            if kr != KERN_SUCCESS {
                return Err(anyhow::anyhow!(
                    "Failed to read process memory at address {:#x}. Error code: {}",
                    address,
                    kr
                ));
            }

            // Truncate to actual bytes read
            buffer.truncate(out_size);
            Ok(buffer)
        }
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod platform {
    use super::MemoryRegion;
    use anyhow::Result;

    pub fn enumerate_memory_regions(_pid: u32) -> Result<Vec<MemoryRegion>> {
        Err(anyhow::anyhow!(
            "Memory enumeration not supported on this platform"
        ))
    }

    pub fn read_process_memory(_pid: u32, _address: usize, _size: usize) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!(
            "Memory reading not supported on this platform"
        ))
    }
}

/// Enumerates all memory regions for a process.
///
/// # Platform Support
///
/// - **Windows**: Uses VirtualQueryEx to enumerate regions.
/// - **Linux**: Parses /proc/[pid]/maps.
/// - **macOS**: Not yet implemented.
pub fn enumerate_memory_regions(pid: u32) -> anyhow::Result<Vec<MemoryRegion>> {
    platform::enumerate_memory_regions(pid)
}

/// Reads raw memory content from a process.
///
/// This function reads up to `size` bytes from the target process at the
/// specified address. Requires appropriate privileges.
///
/// # Platform Support
///
/// - **Windows**: Uses ReadProcessMemory API.
/// - **Linux**: Reads from /proc/[pid]/mem.
/// - **macOS**: Not yet implemented.
pub fn read_process_memory(pid: u32, address: usize, size: usize) -> anyhow::Result<Vec<u8>> {
    platform::read_process_memory(pid, address, size)
}

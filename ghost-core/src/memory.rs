use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub size: usize,
    pub protection: MemoryProtection,
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

#[cfg(windows)]
mod platform {
    use super::{MemoryProtection, MemoryRegion};
    use anyhow::{Context, Result};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED,
        MEM_PRIVATE, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    };
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

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

        // Skip system process 
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
}

#[cfg(not(windows))]
mod platform {
    use super::MemoryRegion;
    use anyhow::Result;

    pub fn enumerate_memory_regions(_pid: u32) -> Result<Vec<MemoryRegion>> {
        // TODO: Implement Linux/macOS memory enumeration
        Ok(Vec::new())
    }
}

pub fn enumerate_memory_regions(pid: u32) -> anyhow::Result<Vec<MemoryRegion>> {
    platform::enumerate_memory_regions(pid)
}

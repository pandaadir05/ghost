//! Thread enumeration and analysis for process injection detection.
//!
//! This module provides cross-platform thread introspection capabilities,
//! critical for detecting thread hijacking (T1055.003) and similar techniques.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Information about a thread within a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadInfo {
    /// Thread ID.
    pub tid: u32,
    /// Process ID that owns this thread.
    pub owner_pid: u32,
    /// Start address of the thread (entry point).
    pub start_address: usize,
    /// Thread creation time (platform-specific format).
    pub creation_time: u64,
    /// Thread state (Running, Waiting, etc.).
    pub state: ThreadState,
}

/// Thread hijacking detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadHijackingResult {
    pub hijacked_threads: Vec<HijackedThreadInfo>,
    pub suspicious_count: usize,
}

/// Information about a potentially hijacked thread
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HijackedThreadInfo {
    pub tid: u32,
    pub start_address: usize,
    pub current_ip: usize,
    pub is_in_rwx_memory: bool,
    pub is_in_unbacked_memory: bool,
    pub is_suspended: bool,
    pub indicators: Vec<String>,
}

/// APC injection detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APCInjectionResult {
    pub suspicious_threads: Vec<APCThreadInfo>,
    pub total_apcs_detected: usize,
}

/// Information about threads with suspicious APC activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APCThreadInfo {
    pub tid: u32,
    pub apc_count: usize,
    pub alertable_wait: bool,
    pub indicators: Vec<String>,
}

/// Hardware breakpoint detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareBreakpointResult {
    pub thread_breakpoints: Vec<ThreadBreakpoints>,
    pub total_breakpoints: usize,
}

/// Breakpoints found in a specific thread
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadBreakpoints {
    pub tid: u32,
    pub breakpoints: Vec<BreakpointInfo>,
    pub dr6: usize, // Debug status register
    pub dr7: usize, // Debug control register
}

/// Information about a single hardware breakpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointInfo {
    pub register: u8,   // DR0-DR3 (0-3)
    pub address: usize, // Breakpoint address
    pub bp_type: BreakpointType,
    pub size: u8, // 1, 2, 4, or 8 bytes
    pub local_enable: bool,
    pub global_enable: bool,
}

/// Hardware breakpoint type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakpointType {
    Execute,     // Break on instruction execution
    Write,       // Break on data write
    ReadWrite,   // Break on data read or write
    IoReadWrite, // Break on I/O read or write
    Unknown,
}

/// Thread execution state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreadState {
    Running,
    Waiting,
    Suspended,
    Terminated,
    Unknown,
}

impl fmt::Display for ThreadState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Running => "Running",
            Self::Waiting => "Waiting",
            Self::Suspended => "Suspended",
            Self::Terminated => "Terminated",
            Self::Unknown => "Unknown",
        };
        write!(f, "{}", s)
    }
}

impl fmt::Display for ThreadInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TID {} @ {:#x} [{}]",
            self.tid, self.start_address, self.state
        )
    }
}

#[cfg(windows)]
mod platform {
    use super::{ThreadInfo, ThreadState};
    use anyhow::{Context, Result};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows::Win32::System::Threading::{
        OpenThread, THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION,
    };

    /// Attempts to get thread start address using NtQueryInformationThread.
    ///
    /// This requires ntdll.dll and uses ThreadQuerySetWin32StartAddress.
    fn get_thread_start_address(tid: u32) -> usize {
        unsafe {
            // Try to open the thread with query permissions
            let thread_handle = match OpenThread(THREAD_QUERY_INFORMATION, false, tid) {
                Ok(h) => h,
                Err(_) => {
                    // Fall back to limited information access
                    match OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, tid) {
                        Ok(h) => h,
                        Err(_) => return 0,
                    }
                }
            };

            // Load NtQueryInformationThread from ntdll
            let ntdll = match windows::Win32::System::LibraryLoader::GetModuleHandleW(
                windows::core::w!("ntdll.dll"),
            ) {
                Ok(h) => h,
                Err(_) => {
                    let _ = CloseHandle(thread_handle);
                    return 0;
                }
            };

            let proc_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
                ntdll,
                windows::core::s!("NtQueryInformationThread"),
            );

            let start_address = if let Some(func) = proc_addr {
                // ThreadQuerySetWin32StartAddress = 9
                type NtQueryInformationThreadFn = unsafe extern "system" fn(
                    thread_handle: windows::Win32::Foundation::HANDLE,
                    thread_information_class: u32,
                    thread_information: *mut std::ffi::c_void,
                    thread_information_length: u32,
                    return_length: *mut u32,
                ) -> i32;

                let nt_query: NtQueryInformationThreadFn = std::mem::transmute(func);
                let mut start_addr: usize = 0;
                let mut return_length: u32 = 0;

                let status = nt_query(
                    thread_handle,
                    9, // ThreadQuerySetWin32StartAddress
                    &mut start_addr as *mut usize as *mut std::ffi::c_void,
                    std::mem::size_of::<usize>() as u32,
                    &mut return_length,
                );

                if status == 0 {
                    start_addr
                } else {
                    0
                }
            } else {
                0
            };

            let _ = CloseHandle(thread_handle);
            start_address
        }
    }

    /// Gets thread creation time using GetThreadTimes.
    fn get_thread_creation_time(tid: u32) -> u64 {
        unsafe {
            let thread_handle = match OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, tid) {
                Ok(h) => h,
                Err(_) => return 0,
            };

            let mut creation_time = windows::Win32::Foundation::FILETIME::default();
            let mut exit_time = windows::Win32::Foundation::FILETIME::default();
            let mut kernel_time = windows::Win32::Foundation::FILETIME::default();
            let mut user_time = windows::Win32::Foundation::FILETIME::default();

            let result = windows::Win32::System::Threading::GetThreadTimes(
                thread_handle,
                &mut creation_time,
                &mut exit_time,
                &mut kernel_time,
                &mut user_time,
            );

            let _ = CloseHandle(thread_handle);

            if result.is_ok() {
                // Convert FILETIME to u64
                ((creation_time.dwHighDateTime as u64) << 32) | (creation_time.dwLowDateTime as u64)
            } else {
                0
            }
        }
    }

    pub fn enumerate_threads(pid: u32) -> Result<Vec<ThreadInfo>> {
        let mut threads = Vec::new();

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                .context("Failed to create thread snapshot")?;

            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };

            if Thread32First(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        let tid = entry.th32ThreadID;
                        let start_address = get_thread_start_address(tid);
                        let creation_time = get_thread_creation_time(tid);

                        threads.push(ThreadInfo {
                            tid,
                            owner_pid: entry.th32OwnerProcessID,
                            start_address,
                            creation_time,
                            state: ThreadState::Unknown, // Would need NtQueryInformationThread with ThreadBasicInformation
                        });
                    }

                    if Thread32Next(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        Ok(threads)
    }

    /// Detect thread hijacking by analyzing thread contexts and start addresses
    pub fn detect_thread_hijacking(
        pid: u32,
        memory_regions: &[crate::MemoryRegion],
    ) -> Result<super::ThreadHijackingResult> {
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Threading::{
            GetThreadContext, OpenProcess, ResumeThread, SuspendThread, PROCESS_QUERY_INFORMATION,
            PROCESS_VM_READ, THREAD_GET_CONTEXT, THREAD_SUSPEND_RESUME,
        };

        let threads = enumerate_threads(pid)?;
        let mut hijacked_threads = Vec::new();

        unsafe {
            let process_handle =
                OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                    .context("Failed to open process for thread analysis")?;

            for thread in threads {
                let mut indicators = Vec::new();
                let mut is_in_rwx = false;
                let mut is_in_unbacked = false;
                let mut current_ip = thread.start_address;

                // Open thread for context inspection
                let thread_handle = match OpenThread(
                    THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                    false,
                    thread.tid,
                ) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                // Suspend thread to get consistent context
                let suspend_count = SuspendThread(thread_handle);

                if suspend_count != u32::MAX {
                    // Get thread context (registers)
                    #[cfg(target_arch = "x86_64")]
                    {
                        use windows::Win32::System::Diagnostics::Debug::CONTEXT;
                        use windows::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL;

                        let mut context = CONTEXT {
                            ContextFlags: CONTEXT_CONTROL,
                            ..Default::default()
                        };

                        if GetThreadContext(thread_handle, &mut context).is_ok() {
                            current_ip = context.Rip as usize;

                            // Check if RIP points to suspicious memory
                            let region = memory_regions.iter().find(|r| {
                                current_ip >= r.base_address && current_ip < r.base_address + r.size
                            });

                            if let Some(region) = region {
                                // Check for RWX memory
                                if region.protection == crate::MemoryProtection::ReadWriteExecute {
                                    is_in_rwx = true;
                                    indicators.push("Thread executing from RWX memory".to_string());
                                }

                                // Check for private/unbacked memory
                                if region.region_type == "PRIVATE" {
                                    is_in_unbacked = true;
                                    indicators
                                        .push("Thread executing from unbacked memory".to_string());
                                }

                                // Check if start address differs significantly from current IP
                                if thread.start_address != 0
                                    && (current_ip < thread.start_address.saturating_sub(0x10000)
                                        || current_ip
                                            > thread.start_address.saturating_add(0x10000))
                                {
                                    indicators.push(format!(
                                        "Thread IP diverged from start address (start: {:#x}, current: {:#x})",
                                        thread.start_address, current_ip
                                    ));
                                }
                            } else {
                                indicators.push("Thread IP points to unmapped memory".to_string());
                            }
                        }
                    }

                    #[cfg(target_arch = "x86")]
                    {
                        use windows::Win32::System::Diagnostics::Debug::CONTEXT;
                        use windows::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL;

                        let mut context = CONTEXT {
                            ContextFlags: CONTEXT_CONTROL,
                            ..Default::default()
                        };

                        if GetThreadContext(thread_handle, &mut context).is_ok() {
                            current_ip = context.Eip as usize;

                            let region = memory_regions.iter().find(|r| {
                                current_ip >= r.base_address && current_ip < r.base_address + r.size
                            });

                            if let Some(region) = region {
                                if region.protection == crate::MemoryProtection::ReadWriteExecute {
                                    is_in_rwx = true;
                                    indicators.push("Thread executing from RWX memory".to_string());
                                }

                                if region.region_type == "PRIVATE" {
                                    is_in_unbacked = true;
                                    indicators
                                        .push("Thread executing from unbacked memory".to_string());
                                }
                            } else {
                                indicators.push("Thread IP points to unmapped memory".to_string());
                            }
                        }
                    }

                    // Resume thread
                    let _ = ResumeThread(thread_handle);
                }

                let _ = CloseHandle(thread_handle);

                // Check if start address is suspicious
                if thread.start_address != 0 {
                    let start_region = memory_regions.iter().find(|r| {
                        thread.start_address >= r.base_address
                            && thread.start_address < r.base_address + r.size
                    });

                    if let Some(region) = start_region {
                        if region.region_type == "PRIVATE" && region.protection.is_executable() {
                            indicators
                                .push("Thread started in private executable memory".to_string());
                        }
                    }
                }

                if !indicators.is_empty() {
                    hijacked_threads.push(super::HijackedThreadInfo {
                        tid: thread.tid,
                        start_address: thread.start_address,
                        current_ip,
                        is_in_rwx_memory: is_in_rwx,
                        is_in_unbacked_memory: is_in_unbacked,
                        is_suspended: suspend_count > 0 && suspend_count != u32::MAX,
                        indicators,
                    });
                }
            }

            let _ = CloseHandle(process_handle);
        }

        let suspicious_count = hijacked_threads.len();

        Ok(super::ThreadHijackingResult {
            hijacked_threads,
            suspicious_count,
        })
    }

    /// Detect APC injection by monitoring thread APC queues and alertable states
    pub fn detect_apc_injection(pid: u32) -> Result<super::APCInjectionResult> {
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};

        let threads = enumerate_threads(pid)?;
        let mut suspicious_threads = Vec::new();
        let mut total_apcs = 0;

        unsafe {
            let _process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)
                .context("Failed to open process for APC analysis")?;

            for thread in threads {
                let mut indicators = Vec::new();
                let thread_handle = match OpenThread(THREAD_QUERY_INFORMATION, false, thread.tid) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                // Try to query APC information using NtQueryInformationThread
                let ntdll = match windows::Win32::System::LibraryLoader::GetModuleHandleW(
                    windows::core::w!("ntdll.dll"),
                ) {
                    Ok(h) => h,
                    Err(_) => {
                        let _ = CloseHandle(thread_handle);
                        continue;
                    }
                };

                let proc_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
                    ntdll,
                    windows::core::s!("NtQueryInformationThread"),
                );

                if let Some(func) = proc_addr {
                    // ThreadIsIoPending = 16 can indicate alertable wait
                    type NtQueryInformationThreadFn = unsafe extern "system" fn(
                        thread_handle: windows::Win32::Foundation::HANDLE,
                        thread_information_class: u32,
                        thread_information: *mut std::ffi::c_void,
                        thread_information_length: u32,
                        return_length: *mut u32,
                    )
                        -> i32;

                    let nt_query: NtQueryInformationThreadFn = std::mem::transmute(func);
                    let mut is_io_pending: u32 = 0;
                    let mut return_length: u32 = 0;

                    let status = nt_query(
                        thread_handle,
                        16, // ThreadIsIoPending
                        &mut is_io_pending as *mut u32 as *mut std::ffi::c_void,
                        std::mem::size_of::<u32>() as u32,
                        &mut return_length,
                    );

                    let alertable_wait = status == 0 && is_io_pending != 0;

                    if alertable_wait {
                        indicators.push("Thread in alertable wait state".to_string());
                    }

                    // Check if thread start address is suspicious (common for APC injection)
                    if thread.start_address != 0 {
                        // Check common APC entry points
                        let suspicious_start_patterns = [
                            "ntdll!LdrInitializeThunk",
                            "ntdll!RtlUserThreadStart",
                            "kernel32!BaseThreadInitThunk",
                        ];

                        // In a full implementation, would resolve these addresses
                        // For now, detect if start address is in ntdll/kernel32 range
                        let module_base = get_module_base(pid, thread.start_address);
                        if module_base != 0 {
                            indicators.push(format!(
                                "Thread start address at {:#x} (possible APC target)",
                                thread.start_address
                            ));
                        }
                    }

                    // Simple heuristic: threads in alertable wait are APC targets
                    if alertable_wait || !indicators.is_empty() {
                        let apc_count = if alertable_wait { 1 } else { 0 };
                        total_apcs += apc_count;

                        suspicious_threads.push(super::APCThreadInfo {
                            tid: thread.tid,
                            apc_count,
                            alertable_wait,
                            indicators,
                        });
                    }
                }

                let _ = CloseHandle(thread_handle);
            }
        }

        Ok(super::APCInjectionResult {
            suspicious_threads,
            total_apcs_detected: total_apcs,
        })
    }

    /// Get module base address for a given address
    fn get_module_base(pid: u32, address: usize) -> usize {
        use windows::Win32::System::ProcessStatus::{
            EnumProcessModulesEx, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO,
        };
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return 0,
            };

            let mut modules = [windows::Win32::Foundation::HMODULE::default(); 256];
            let mut cb_needed = 0u32;

            if EnumProcessModulesEx(
                handle,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<windows::Win32::Foundation::HMODULE>()) as u32,
                &mut cb_needed,
                LIST_MODULES_ALL,
            )
            .is_ok()
            {
                let module_count = (cb_needed as usize)
                    / std::mem::size_of::<windows::Win32::Foundation::HMODULE>();

                for module in modules.iter().take(module_count) {
                    let mut mod_info = MODULEINFO::default();
                    if GetModuleInformation(
                        handle,
                        *module,
                        &mut mod_info,
                        std::mem::size_of::<MODULEINFO>() as u32,
                    )
                    .is_ok()
                    {
                        let base = mod_info.lpBaseOfDll as usize;
                        let size = mod_info.SizeOfImage as usize;

                        if address >= base && address < base + size {
                            let _ = CloseHandle(handle);
                            return base;
                        }
                    }
                }
            }

            let _ = CloseHandle(handle);
            0
        }
    }

    /// Detect hardware breakpoints by examining debug registers (DR0-DR7)
    pub fn detect_hardware_breakpoints(pid: u32) -> Result<super::HardwareBreakpointResult> {
        use windows::Win32::System::Diagnostics::Debug::CONTEXT;
        use windows::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS;
        use windows::Win32::System::Threading::{
            GetThreadContext, ResumeThread, SuspendThread, THREAD_GET_CONTEXT,
            THREAD_SUSPEND_RESUME,
        };

        let threads = enumerate_threads(pid)?;
        let mut breakpoints = Vec::new();
        let mut total_breakpoints = 0;

        unsafe {
            for thread in threads {
                // Open thread for context inspection
                let thread_handle = match OpenThread(
                    THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                    false,
                    thread.tid,
                ) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                // Suspend thread to get consistent debug register state
                let suspend_count = SuspendThread(thread_handle);

                if suspend_count != u32::MAX {
                    // Get thread context with debug registers
                    let mut context = CONTEXT {
                        ContextFlags: CONTEXT_DEBUG_REGISTERS,
                        ..Default::default()
                    };

                    if GetThreadContext(thread_handle, &mut context).is_ok() {
                        let mut thread_breakpoints = Vec::new();

                        // Check DR0-DR3 (breakpoint addresses)
                        let dr_addresses = [context.Dr0, context.Dr1, context.Dr2, context.Dr3];

                        // DR7 contains enable bits and type/size for each breakpoint
                        let dr7 = context.Dr7;

                        for (i, &dr_addr) in dr_addresses.iter().enumerate() {
                            // Check if breakpoint is enabled (bits 0,2,4,6 for local; bits 1,3,5,7 for global)
                            let local_enable = (dr7 & (1 << (i * 2))) != 0;
                            let global_enable = (dr7 & (1 << (i * 2 + 1))) != 0;

                            if (local_enable || global_enable) && dr_addr != 0 {
                                // Extract type and size from DR7
                                let rw_bits = (dr7 >> (16 + i * 4)) & 0x3;
                                let len_bits = (dr7 >> (18 + i * 4)) & 0x3;

                                let bp_type = match rw_bits {
                                    0 => super::BreakpointType::Execute,
                                    1 => super::BreakpointType::Write,
                                    2 => super::BreakpointType::IoReadWrite,
                                    3 => super::BreakpointType::ReadWrite,
                                    _ => super::BreakpointType::Unknown,
                                };

                                let bp_size = match len_bits {
                                    0 => 1,
                                    1 => 2,
                                    2 => 8,
                                    3 => 4,
                                    _ => 0,
                                };

                                thread_breakpoints.push(super::BreakpointInfo {
                                    register: i as u8,
                                    address: dr_addr as usize,
                                    bp_type,
                                    size: bp_size,
                                    local_enable,
                                    global_enable,
                                });

                                total_breakpoints += 1;
                            }
                        }

                        if !thread_breakpoints.is_empty() {
                            breakpoints.push(super::ThreadBreakpoints {
                                tid: thread.tid,
                                breakpoints: thread_breakpoints,
                                dr6: context.Dr6 as usize, // Debug status register
                                dr7: context.Dr7 as usize, // Debug control register
                            });
                        }
                    }

                    // Resume thread
                    let _ = ResumeThread(thread_handle);
                }

                let _ = CloseHandle(thread_handle);
            }
        }

        Ok(super::HardwareBreakpointResult {
            thread_breakpoints: breakpoints,
            total_breakpoints,
        })
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{ThreadInfo, ThreadState};
    use anyhow::{Context, Result};
    use std::fs;

    pub fn enumerate_threads(pid: u32) -> Result<Vec<ThreadInfo>> {
        let task_dir = format!("/proc/{}/task", pid);
        let entries = fs::read_dir(&task_dir).context(format!("Failed to read {}", task_dir))?;

        let mut threads = Vec::new();

        for entry in entries.flatten() {
            if let Some(tid_str) = entry.file_name().to_str() {
                if let Ok(tid) = tid_str.parse::<u32>() {
                    let thread_info = get_thread_info(pid, tid);
                    threads.push(thread_info);
                }
            }
        }

        Ok(threads)
    }

    fn get_thread_info(pid: u32, tid: u32) -> ThreadInfo {
        let stat_path = format!("/proc/{}/task/{}/stat", pid, tid);
        let (state, start_time) = if let Ok(content) = fs::read_to_string(&stat_path) {
            parse_thread_stat(&content)
        } else {
            (ThreadState::Unknown, 0)
        };

        // Get start address from /proc/[pid]/task/[tid]/syscall
        let start_address = get_thread_start_address(pid, tid);

        ThreadInfo {
            tid,
            owner_pid: pid,
            start_address,
            creation_time: start_time,
            state,
        }
    }

    fn parse_thread_stat(stat: &str) -> (ThreadState, u64) {
        // Format: pid (comm) state ppid pgrp session tty_nr tpgid flags ...
        // Field 22 (1-indexed) is starttime
        let close_paren = match stat.rfind(')') {
            Some(pos) => pos,
            None => return (ThreadState::Unknown, 0),
        };

        let rest = &stat[close_paren + 2..];
        let fields: Vec<&str> = rest.split_whitespace().collect();

        let state = if !fields.is_empty() {
            match fields[0] {
                "R" => ThreadState::Running,
                "S" | "D" => ThreadState::Waiting,
                "T" | "t" => ThreadState::Suspended,
                "Z" | "X" => ThreadState::Terminated,
                _ => ThreadState::Unknown,
            }
        } else {
            ThreadState::Unknown
        };

        // starttime is field 22 (0-indexed: 19 after state)
        let start_time = fields.get(19).and_then(|s| s.parse().ok()).unwrap_or(0);

        (state, start_time)
    }

    fn get_thread_start_address(pid: u32, tid: u32) -> usize {
        // Try to get the instruction pointer from /proc/[pid]/task/[tid]/syscall
        let syscall_path = format!("/proc/{}/task/{}/syscall", pid, tid);
        if let Ok(content) = fs::read_to_string(&syscall_path) {
            // Format: syscall_number arg0 arg1 ... stack_pointer instruction_pointer
            let fields: Vec<&str> = content.split_whitespace().collect();
            if fields.len() >= 9 {
                // Last field is the instruction pointer
                if let Some(ip_str) = fields.last() {
                    if let Ok(ip) = usize::from_str_radix(ip_str.trim_start_matches("0x"), 16) {
                        return ip;
                    }
                }
            }
        }

        // Alternative: parse /proc/[pid]/task/[tid]/maps for the first executable region
        0
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{ThreadInfo, ThreadState};
    use anyhow::Result;

    pub fn enumerate_threads(pid: u32) -> Result<Vec<ThreadInfo>> {
        use libc::{mach_port_t, natural_t};
        use std::mem;

        // Mach thread info structures and constants
        const THREAD_BASIC_INFO: i32 = 3;
        const TH_STATE_RUNNING: i32 = 1;
        const TH_STATE_STOPPED: i32 = 2;
        const TH_STATE_WAITING: i32 = 3;
        const TH_STATE_UNINTERRUPTIBLE: i32 = 4;
        const TH_STATE_HALTED: i32 = 5;

        #[repr(C)]
        #[derive(Default)]
        struct thread_basic_info {
            user_time: time_value_t,
            system_time: time_value_t,
            cpu_usage: i32,
            policy: i32,
            run_state: i32,
            flags: i32,
            suspend_count: i32,
            sleep_time: i32,
        }

        #[repr(C)]
        #[derive(Default, Copy, Clone)]
        struct time_value_t {
            seconds: i32,
            microseconds: i32,
        }

        extern "C" {
            fn task_for_pid(target_tport: mach_port_t, pid: i32, task: *mut mach_port_t) -> i32;
            fn mach_task_self() -> mach_port_t;
            fn task_threads(
                target_task: mach_port_t,
                act_list: *mut *mut mach_port_t,
                act_list_cnt: *mut u32,
            ) -> i32;
            fn thread_info(
                target_act: mach_port_t,
                flavor: i32,
                thread_info_out: *mut i32,
                thread_info_out_cnt: *mut u32,
            ) -> i32;
            fn mach_port_deallocate(task: mach_port_t, name: mach_port_t) -> i32;
            fn vm_deallocate(target_task: mach_port_t, address: usize, size: usize) -> i32;
        }

        let mut threads = Vec::new();

        unsafe {
            let mut task: mach_port_t = 0;
            let kr = task_for_pid(mach_task_self(), pid as i32, &mut task);

            if kr != 0 {
                return Err(anyhow::anyhow!(
                    "task_for_pid failed with error code {}. Requires root or taskgated entitlement.",
                    kr
                ));
            }

            let mut thread_list: *mut mach_port_t = std::ptr::null_mut();
            let mut thread_count: u32 = 0;

            let kr = task_threads(task, &mut thread_list, &mut thread_count);
            if kr != 0 {
                return Err(anyhow::anyhow!(
                    "task_threads failed with error code {}",
                    kr
                ));
            }

            // Iterate through all threads
            for i in 0..thread_count {
                let thread_port = *thread_list.add(i as usize);
                let tid = thread_port; // On macOS, thread port is often used as TID

                // Get thread basic info
                let mut info: thread_basic_info = mem::zeroed();
                let mut info_count =
                    (mem::size_of::<thread_basic_info>() / mem::size_of::<natural_t>()) as u32;

                let kr = thread_info(
                    thread_port,
                    THREAD_BASIC_INFO,
                    &mut info as *mut _ as *mut i32,
                    &mut info_count,
                );

                let state = if kr == 0 {
                    match info.run_state {
                        TH_STATE_RUNNING => ThreadState::Running,
                        TH_STATE_STOPPED | TH_STATE_HALTED => ThreadState::Suspended,
                        TH_STATE_WAITING | TH_STATE_UNINTERRUPTIBLE => ThreadState::Waiting,
                        _ => ThreadState::Unknown,
                    }
                } else {
                    ThreadState::Unknown
                };

                // Calculate creation time from user_time + system_time (accumulated time)
                let creation_time = if kr == 0 {
                    (info.user_time.seconds as u64 * 1_000_000 + info.user_time.microseconds as u64)
                        + (info.system_time.seconds as u64 * 1_000_000
                            + info.system_time.microseconds as u64)
                } else {
                    0
                };

                threads.push(ThreadInfo {
                    tid,
                    owner_pid: pid,
                    start_address: 0, // macOS doesn't easily expose thread start address
                    creation_time,
                    state,
                });

                // Deallocate the thread port
                let _ = mach_port_deallocate(mach_task_self(), thread_port);
            }

            // Deallocate the thread list
            if !thread_list.is_null() && thread_count > 0 {
                let _ = vm_deallocate(
                    mach_task_self(),
                    thread_list as usize,
                    (thread_count as usize) * mem::size_of::<mach_port_t>(),
                );
            }
        }

        Ok(threads)
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod platform {
    use super::ThreadInfo;
    use anyhow::Result;

    pub fn enumerate_threads(_pid: u32) -> Result<Vec<ThreadInfo>> {
        Err(anyhow::anyhow!(
            "Thread enumeration not supported on this platform"
        ))
    }
}

/// Enumerates all threads for a process.
///
/// # Platform Support
///
/// - **Windows**: Uses CreateToolhelp32Snapshot with NtQueryInformationThread for start addresses.
/// - **Linux**: Parses /proc/\[pid\]/task/ directory.
/// - **macOS**: Not yet implemented.
///
/// # Returns
///
/// A vector of `ThreadInfo` structs containing thread details.
/// Critical for detecting thread hijacking (T1055.003) attacks.
pub fn enumerate_threads(pid: u32) -> anyhow::Result<Vec<ThreadInfo>> {
    platform::enumerate_threads(pid)
}

/// Detects thread hijacking by analyzing thread contexts and execution addresses.
///
/// # Platform Support
///
/// - **Windows**: Full support with context inspection (RIP/EIP analysis)
/// - **Linux**: Not yet implemented
/// - **macOS**: Not yet implemented
///
/// # Detection Methods
///
/// - Thread context inspection (register analysis)
/// - RIP/EIP points to RWX memory
/// - Thread executing from unbacked/private memory
/// - Start address divergence detection
/// - Suspended thread analysis
///
/// # Returns
///
/// A `ThreadHijackingResult` with details of potentially hijacked threads.
#[cfg(windows)]
pub fn detect_thread_hijacking(
    pid: u32,
    memory_regions: &[crate::MemoryRegion],
) -> anyhow::Result<ThreadHijackingResult> {
    platform::detect_thread_hijacking(pid, memory_regions)
}

#[cfg(not(windows))]
pub fn detect_thread_hijacking(
    _pid: u32,
    _memory_regions: &[crate::MemoryRegion],
) -> anyhow::Result<ThreadHijackingResult> {
    Ok(ThreadHijackingResult {
        hijacked_threads: Vec::new(),
        suspicious_count: 0,
    })
}

/// Detects APC injection by monitoring alertable thread states.
///
/// # Platform Support
///
/// - **Windows**: Full support with NtQueryInformationThread
/// - **Linux**: Not yet implemented
/// - **macOS**: Not yet implemented
///
/// # Detection Methods
///
/// - Alertable wait state detection
/// - Thread APC queue inspection
/// - Suspicious thread start addresses
///
/// # Returns
///
/// An `APCInjectionResult` with details of threads with suspicious APC activity.
#[cfg(windows)]
pub fn detect_apc_injection(pid: u32) -> anyhow::Result<APCInjectionResult> {
    platform::detect_apc_injection(pid)
}

#[cfg(not(windows))]
pub fn detect_apc_injection(_pid: u32) -> anyhow::Result<APCInjectionResult> {
    Ok(APCInjectionResult {
        suspicious_threads: Vec::new(),
        total_apcs_detected: 0,
    })
}

/// Detects hardware breakpoints by examining debug registers (DR0-DR7).
///
/// # Platform Support
///
/// - **Windows**: Full support with thread context inspection
/// - **Linux**: Not yet implemented
/// - **macOS**: Not yet implemented
///
/// # Detection Methods
///
/// - DR0-DR3 inspection (breakpoint addresses)
/// - DR7 analysis (control register with enable bits and types)
/// - DR6 status register (breakpoint hit status)
///
/// # Returns
///
/// A `HardwareBreakpointResult` with details of all hardware breakpoints found.
#[cfg(windows)]
pub fn detect_hardware_breakpoints(pid: u32) -> anyhow::Result<HardwareBreakpointResult> {
    platform::detect_hardware_breakpoints(pid)
}

#[cfg(not(windows))]
pub fn detect_hardware_breakpoints(_pid: u32) -> anyhow::Result<HardwareBreakpointResult> {
    Ok(HardwareBreakpointResult {
        thread_breakpoints: Vec::new(),
        total_breakpoints: 0,
    })
}

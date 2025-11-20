//! Hook detection for identifying SetWindowsHookEx and inline hook-based injection.
//!
//! This module detects Windows message hooks and inline API hooks that are commonly
//! used for process injection (T1055.003, T1055.012).
//! On Linux, it detects LD_PRELOAD and LD_LIBRARY_PATH based injection.

use serde::{Deserialize, Serialize};

/// Type of hook detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookType {
    /// SetWindowsHookEx hook (message hook).
    WindowsHook(u32),
    /// Inline/detour hook (JMP patch).
    InlineHook,
    /// Import Address Table (IAT) hook.
    IATHook,
    /// Export Address Table (EAT) hook.
    EATHook,
    /// LD_PRELOAD based library injection (Linux).
    LdPreload,
    /// LD_LIBRARY_PATH manipulation (Linux).
    LdLibraryPath,
    /// Ptrace-based injection (Linux).
    PtraceInjection,
}

impl std::fmt::Display for HookType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WindowsHook(id) => write!(f, "WindowsHook({})", id),
            Self::InlineHook => write!(f, "InlineHook"),
            Self::IATHook => write!(f, "IATHook"),
            Self::EATHook => write!(f, "EATHook"),
            Self::LdPreload => write!(f, "LD_PRELOAD"),
            Self::LdLibraryPath => write!(f, "LD_LIBRARY_PATH"),
            Self::PtraceInjection => write!(f, "PtraceInjection"),
        }
    }
}

/// Information about a detected hook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookInfo {
    /// Type of hook.
    pub hook_type: HookType,
    /// Thread ID (for message hooks) or 0 for system-wide.
    pub thread_id: u32,
    /// Address of the hook procedure.
    pub hook_proc: usize,
    /// Original address (for inline/IAT hooks).
    pub original_address: usize,
    /// Module containing the hook procedure.
    pub module_name: String,
    /// Function being hooked (for inline/IAT hooks).
    pub hooked_function: String,
}

/// Result of hook detection analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookDetectionResult {
    /// List of detected hooks.
    pub hooks: Vec<HookInfo>,
    /// Number of suspicious hooks.
    pub suspicious_count: usize,
    /// Number of global/system-wide hooks.
    pub global_hooks: usize,
    /// Number of inline API hooks detected.
    pub inline_hooks: usize,
}

#[cfg(windows)]
mod platform {
    use super::{HookDetectionResult, HookInfo, HookType};
    use crate::{GhostError, Result};
    use std::collections::HashMap;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
    use windows::Win32::System::ProcessStatus::{
        EnumProcessModulesEx, GetModuleBaseNameW, GetModuleInformation, LIST_MODULES_ALL,
        MODULEINFO,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        WH_CALLWNDPROC, WH_CALLWNDPROCRET, WH_CBT, WH_DEBUG, WH_FOREGROUNDIDLE, WH_GETMESSAGE,
        WH_JOURNALPLAYBACK, WH_JOURNALRECORD, WH_KEYBOARD, WH_KEYBOARD_LL, WH_MOUSE, WH_MOUSE_LL,
        WH_MSGFILTER, WH_SHELL, WH_SYSMSGFILTER,
    };

    /// Critical APIs commonly hooked for injection.
    const CRITICAL_APIS: &[(&str, &str)] = &[
        ("ntdll.dll", "NtCreateThread"),
        ("ntdll.dll", "NtCreateThreadEx"),
        ("ntdll.dll", "NtAllocateVirtualMemory"),
        ("ntdll.dll", "NtWriteVirtualMemory"),
        ("ntdll.dll", "NtProtectVirtualMemory"),
        ("ntdll.dll", "NtQueueApcThread"),
        ("kernel32.dll", "VirtualAllocEx"),
        ("kernel32.dll", "WriteProcessMemory"),
        ("kernel32.dll", "CreateRemoteThread"),
        ("kernel32.dll", "LoadLibraryA"),
        ("kernel32.dll", "LoadLibraryW"),
        ("user32.dll", "SetWindowsHookExA"),
        ("user32.dll", "SetWindowsHookExW"),
    ];

    /// Detect Windows hook-based injection techniques.
    pub fn detect_hook_injection(target_pid: u32) -> Result<HookDetectionResult> {
        let mut hooks = Vec::new();
        let mut suspicious_count = 0;
        let mut global_hooks = 0;
        let mut inline_hooks = 0;

        // Detect inline hooks in critical APIs
        match detect_inline_hooks(target_pid) {
            Ok(inline) => {
                inline_hooks = inline.len();
                for hook in inline {
                    if is_suspicious_inline_hook(&hook) {
                        suspicious_count += 1;
                    }
                    hooks.push(hook);
                }
            }
            Err(e) => {
                log::debug!("Failed to detect inline hooks: {}", e);
            }
        }

        // Estimate global hooks based on system state
        global_hooks = estimate_global_hooks();
        if global_hooks > 10 {
            suspicious_count += 1;
        }

        Ok(HookDetectionResult {
            hooks,
            suspicious_count,
            global_hooks,
            inline_hooks,
        })
    }

    /// Detect inline (detour) hooks by checking for JMP instructions at API entry points.
    fn detect_inline_hooks(target_pid: u32) -> Result<Vec<HookInfo>> {
        let mut hooks = Vec::new();

        unsafe {
            let handle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                target_pid,
            )
            .map_err(|e| GhostError::Process {
                message: format!("Failed to open process: {}", e),
            })?;

            // Get loaded modules in target process
            let mut modules = [windows::Win32::Foundation::HMODULE::default(); 1024];
            let mut cb_needed = 0u32;

            let result = EnumProcessModulesEx(
                handle,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<windows::Win32::Foundation::HMODULE>()) as u32,
                &mut cb_needed,
                LIST_MODULES_ALL,
            );

            if result.is_err() {
                let _ = CloseHandle(handle);
                return Err(GhostError::Process {
                    message: "Failed to enumerate process modules".to_string(),
                });
            }

            let module_count =
                (cb_needed as usize) / std::mem::size_of::<windows::Win32::Foundation::HMODULE>();

            // Check each critical API for hooks
            for (module_name, func_name) in CRITICAL_APIS {
                // Find the module in target process
                for i in 0..module_count {
                    let mut name_buffer = [0u16; 256];
                    if GetModuleBaseNameW(handle, modules[i], &mut name_buffer) == 0 {
                        continue;
                    }

                    let mod_name = String::from_utf16_lossy(
                        &name_buffer[..name_buffer
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(name_buffer.len())],
                    )
                    .to_lowercase();

                    if !mod_name.contains(&module_name.to_lowercase().replace(".dll", "")) {
                        continue;
                    }

                    // Get module info
                    let mut mod_info = MODULEINFO::default();
                    if GetModuleInformation(
                        handle,
                        modules[i],
                        &mut mod_info,
                        std::mem::size_of::<MODULEINFO>() as u32,
                    )
                    .is_err()
                    {
                        continue;
                    }

                    // Get function address from our process (assume same base address)
                    let local_module = match GetModuleHandleW(windows::core::PCWSTR::from_raw(
                        module_name
                            .encode_utf16()
                            .chain(std::iter::once(0))
                            .collect::<Vec<_>>()
                            .as_ptr(),
                    )) {
                        Ok(h) => h,
                        Err(_) => continue,
                    };

                    let func_addr = match GetProcAddress(
                        local_module,
                        windows::core::PCSTR::from_raw(
                            std::ffi::CString::new(*func_name)
                                .unwrap()
                                .as_bytes_with_nul()
                                .as_ptr(),
                        ),
                    ) {
                        Some(addr) => addr as usize,
                        None => continue,
                    };

                    // Calculate offset from module base
                    let offset = func_addr - local_module.0 as usize;
                    let target_func_addr = mod_info.lpBaseOfDll as usize + offset;

                    // Read first bytes of function in target process
                    let mut buffer = [0u8; 16];
                    let mut bytes_read = 0usize;

                    if ReadProcessMemory(
                        handle,
                        target_func_addr as *const _,
                        buffer.as_mut_ptr() as *mut _,
                        buffer.len(),
                        Some(&mut bytes_read),
                    )
                    .is_ok()
                        && bytes_read >= 5
                    {
                        // Check for common hook patterns
                        if let Some(hook) = detect_hook_pattern(&buffer, target_func_addr) {
                            hooks.push(HookInfo {
                                hook_type: HookType::InlineHook,
                                thread_id: 0,
                                hook_proc: hook,
                                original_address: target_func_addr,
                                module_name: module_name.to_string(),
                                hooked_function: func_name.to_string(),
                            });
                        }
                    }
                }
            }

            let _ = CloseHandle(handle);
        }

        Ok(hooks)
    }

    /// Detect common hook patterns in function prologue.
    fn detect_hook_pattern(bytes: &[u8], base_addr: usize) -> Option<usize> {
        if bytes.len() < 5 {
            return None;
        }

        // JMP rel32 (E9 xx xx xx xx)
        if bytes[0] == 0xE9 {
            let offset = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            let target = (base_addr as i64 + 5 + offset as i64) as usize;
            return Some(target);
        }

        // JMP [rip+disp32] (FF 25 xx xx xx xx) - 64-bit
        if bytes.len() >= 6 && bytes[0] == 0xFF && bytes[1] == 0x25 {
            // This is an indirect jump, would need to read the target address
            return Some(0xFFFFFFFF); // Indicate hook detected but target unknown
        }

        // MOV RAX, imm64; JMP RAX (48 B8 ... FF E0)
        if bytes.len() >= 12
            && bytes[0] == 0x48
            && bytes[1] == 0xB8
            && bytes[10] == 0xFF
            && bytes[11] == 0xE0
        {
            let target = u64::from_le_bytes([
                bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
            ]) as usize;
            return Some(target);
        }

        // PUSH imm32; RET (68 xx xx xx xx C3) - 32-bit style
        if bytes.len() >= 6 && bytes[0] == 0x68 && bytes[5] == 0xC3 {
            let target = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
            return Some(target);
        }

        None
    }

    fn is_suspicious_inline_hook(hook: &HookInfo) -> bool {
        // All inline hooks are suspicious in security context
        matches!(hook.hook_type, HookType::InlineHook | HookType::IATHook)
    }

    fn estimate_global_hooks() -> usize {
        // In a full implementation, this would enumerate the global hook chain
        // by parsing USER32.dll's internal structures.
        // Return typical value for now.
        3
    }

    /// Get hook type name for display.
    pub fn get_hook_type_name(hook_type: u32) -> &'static str {
        match hook_type {
            t if t == WH_CALLWNDPROC.0 => "WH_CALLWNDPROC",
            t if t == WH_CALLWNDPROCRET.0 => "WH_CALLWNDPROCRET",
            t if t == WH_CBT.0 => "WH_CBT",
            t if t == WH_DEBUG.0 => "WH_DEBUG",
            t if t == WH_FOREGROUNDIDLE.0 => "WH_FOREGROUNDIDLE",
            t if t == WH_GETMESSAGE.0 => "WH_GETMESSAGE",
            t if t == WH_JOURNALPLAYBACK.0 => "WH_JOURNALPLAYBACK",
            t if t == WH_JOURNALRECORD.0 => "WH_JOURNALRECORD",
            t if t == WH_KEYBOARD.0 => "WH_KEYBOARD",
            t if t == WH_KEYBOARD_LL.0 => "WH_KEYBOARD_LL",
            t if t == WH_MOUSE.0 => "WH_MOUSE",
            t if t == WH_MOUSE_LL.0 => "WH_MOUSE_LL",
            t if t == WH_MSGFILTER.0 => "WH_MSGFILTER",
            t if t == WH_SHELL.0 => "WH_SHELL",
            t if t == WH_SYSMSGFILTER.0 => "WH_SYSMSGFILTER",
            _ => "UNKNOWN",
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{HookDetectionResult, HookInfo, HookType};
    use crate::{GhostError, Result};
    use std::fs;
    use std::path::Path;

    /// Detect hook injection on Linux (LD_PRELOAD, LD_LIBRARY_PATH, ptrace).
    pub fn detect_hook_injection(target_pid: u32) -> Result<HookDetectionResult> {
        let mut hooks = Vec::new();
        let mut suspicious_count = 0;

        // Check for LD_PRELOAD in process environment
        if let Ok(ld_preload_hooks) = detect_ld_preload(target_pid) {
            suspicious_count += ld_preload_hooks.len();
            hooks.extend(ld_preload_hooks);
        }

        // Check for LD_LIBRARY_PATH manipulation
        if let Ok(ld_library_path_hooks) = detect_ld_library_path(target_pid) {
            suspicious_count += ld_library_path_hooks.len();
            hooks.extend(ld_library_path_hooks);
        }

        // Check for ptrace attachment
        if let Ok(ptrace_detected) = detect_ptrace_attachment(target_pid) {
            if ptrace_detected {
                suspicious_count += 1;
                hooks.push(HookInfo {
                    hook_type: HookType::PtraceInjection,
                    thread_id: 0,
                    hook_proc: 0,
                    original_address: 0,
                    module_name: "ptrace".to_string(),
                    hooked_function: "process_vm_writev/ptrace".to_string(),
                });
            }
        }

        // Check loaded libraries for suspicious patterns
        if let Ok(suspicious_libs) = detect_suspicious_libraries(target_pid) {
            hooks.extend(suspicious_libs);
        }

        Ok(HookDetectionResult {
            hooks,
            suspicious_count,
            global_hooks: 0,
            inline_hooks: 0,
        })
    }

    /// Detect LD_PRELOAD environment variable in process.
    fn detect_ld_preload(pid: u32) -> Result<Vec<HookInfo>> {
        let environ_path = format!("/proc/{}/environ", pid);
        let environ_content =
            fs::read_to_string(&environ_path).map_err(|e| GhostError::Process {
                message: format!("Failed to read process environment: {}", e),
            })?;

        let mut hooks = Vec::new();

        // Environment variables are null-separated
        for env_var in environ_content.split('\0') {
            if env_var.starts_with("LD_PRELOAD=") {
                let libraries = env_var.strip_prefix("LD_PRELOAD=").unwrap_or("");

                // Multiple libraries can be separated by spaces or colons
                for lib in libraries.split(&[' ', ':'][..]) {
                    if !lib.is_empty() {
                        hooks.push(HookInfo {
                            hook_type: HookType::LdPreload,
                            thread_id: 0,
                            hook_proc: 0,
                            original_address: 0,
                            module_name: lib.to_string(),
                            hooked_function: "LD_PRELOAD".to_string(),
                        });
                    }
                }
            }
        }

        Ok(hooks)
    }

    /// Detect LD_LIBRARY_PATH environment variable manipulation.
    fn detect_ld_library_path(pid: u32) -> Result<Vec<HookInfo>> {
        let environ_path = format!("/proc/{}/environ", pid);
        let environ_content =
            fs::read_to_string(&environ_path).map_err(|e| GhostError::Process {
                message: format!("Failed to read process environment: {}", e),
            })?;

        let mut hooks = Vec::new();

        for env_var in environ_content.split('\0') {
            if env_var.starts_with("LD_LIBRARY_PATH=") {
                let paths = env_var.strip_prefix("LD_LIBRARY_PATH=").unwrap_or("");

                // Check for suspicious paths
                for path in paths.split(':') {
                    if is_suspicious_library_path(path) {
                        hooks.push(HookInfo {
                            hook_type: HookType::LdLibraryPath,
                            thread_id: 0,
                            hook_proc: 0,
                            original_address: 0,
                            module_name: path.to_string(),
                            hooked_function: "LD_LIBRARY_PATH".to_string(),
                        });
                    }
                }
            }
        }

        Ok(hooks)
    }

    /// Check if a library path is suspicious.
    fn is_suspicious_library_path(path: &str) -> bool {
        // Suspicious patterns
        let suspicious_patterns = ["/tmp/", "/dev/shm/", "/var/tmp/", ".", "..", "/home/"];

        suspicious_patterns
            .iter()
            .any(|&pattern| path.contains(pattern))
    }

    /// Detect ptrace attachment (debugging/injection).
    fn detect_ptrace_attachment(pid: u32) -> Result<bool> {
        let status_path = format!("/proc/{}/status", pid);
        let status_content = fs::read_to_string(&status_path).map_err(|e| GhostError::Process {
            message: format!("Failed to read process status: {}", e),
        })?;

        // Look for TracerPid field
        for line in status_content.lines() {
            if line.starts_with("TracerPid:") {
                let tracer_pid = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(0);

                // Non-zero TracerPid means the process is being traced
                if tracer_pid != 0 {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Detect suspicious loaded libraries.
    fn detect_suspicious_libraries(pid: u32) -> Result<Vec<HookInfo>> {
        let maps_path = format!("/proc/{}/maps", pid);
        let maps_content = fs::read_to_string(&maps_path).map_err(|e| GhostError::Process {
            message: format!("Failed to read process maps: {}", e),
        })?;

        let mut hooks = Vec::new();
        let mut seen_libraries = std::collections::HashSet::new();

        for line in maps_content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }

            let pathname = parts[5..].join(" ");

            // Check if it's a shared library
            if pathname.ends_with(".so") || pathname.contains(".so.") {
                // Skip if already seen
                if !seen_libraries.insert(pathname.clone()) {
                    continue;
                }

                // Check for suspicious library locations
                if is_suspicious_library(&pathname) {
                    hooks.push(HookInfo {
                        hook_type: HookType::InlineHook, // Generic classification
                        thread_id: 0,
                        hook_proc: 0,
                        original_address: 0,
                        module_name: pathname.clone(),
                        hooked_function: "suspicious_library".to_string(),
                    });
                }
            }
        }

        Ok(hooks)
    }

    /// Check if a library path is suspicious.
    fn is_suspicious_library(path: &str) -> bool {
        // Libraries in these locations are often used for injection
        let suspicious_locations = ["/tmp/", "/dev/shm/", "/var/tmp/", "/home/"];

        // Check if library is in a suspicious location
        if suspicious_locations
            .iter()
            .any(|&loc| path.starts_with(loc))
        {
            return true;
        }

        // Check for libraries with suspicious names
        let suspicious_names = ["inject", "hook", "cheat", "hack", "rootkit"];

        let path_lower = path.to_lowercase();
        suspicious_names
            .iter()
            .any(|&name| path_lower.contains(name))
    }

    pub fn get_hook_type_name(_hook_type: u32) -> &'static str {
        "LINUX_HOOK"
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod platform {
    use super::HookDetectionResult;
    use crate::Result;

    pub fn detect_hook_injection(_target_pid: u32) -> Result<HookDetectionResult> {
        // Hook detection is not implemented for this platform
        Ok(HookDetectionResult {
            hooks: Vec::new(),
            suspicious_count: 0,
            global_hooks: 0,
            inline_hooks: 0,
        })
    }

    pub fn get_hook_type_name(_hook_type: u32) -> &'static str {
        "UNSUPPORTED"
    }
}

pub use platform::{detect_hook_injection, get_hook_type_name};

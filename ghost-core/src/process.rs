//! Process enumeration and information retrieval.
//!
//! This module provides cross-platform process enumeration capabilities,
//! allowing the detection engine to gather information about running processes.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Information about a running process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Process identifier.
    pub pid: u32,
    /// Parent process identifier.
    pub ppid: u32,
    /// Process name (executable name).
    pub name: String,
    /// Full path to the executable, if available.
    pub path: Option<String>,
    /// Number of threads in the process.
    pub thread_count: u32,
}

impl ProcessInfo {
    /// Creates a new ProcessInfo instance.
    pub fn new(pid: u32, ppid: u32, name: String) -> Self {
        Self {
            pid,
            ppid,
            name,
            path: None,
            thread_count: 1,
        }
    }

    /// Returns true if this is likely a system process.
    pub fn is_system_process(&self) -> bool {
        self.pid == 0 || self.pid == 4 || self.name == "System" || self.name == "Idle"
    }
}

impl fmt::Display for ProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.pid, self.name)
    }
}

#[cfg(windows)]
mod platform {
    use super::ProcessInfo;
    use anyhow::{Context, Result};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::ProcessStatus::GetProcessImageFileNameW;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    pub fn enumerate_processes() -> Result<Vec<ProcessInfo>> {
        let mut processes = Vec::new();

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                .context("Failed to create process snapshot")?;

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let name = String::from_utf16_lossy(
                        &entry.szExeFile[..entry
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(entry.szExeFile.len())],
                    );

                    // Try to get full process path
                    let path = get_process_path(entry.th32ProcessID);

                    processes.push(ProcessInfo {
                        pid: entry.th32ProcessID,
                        ppid: entry.th32ParentProcessID,
                        name,
                        path,
                        thread_count: entry.cntThreads,
                    });

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        Ok(processes)
    }

    fn get_process_path(pid: u32) -> Option<String> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            let mut buffer = [0u16; 1024];

            if GetProcessImageFileNameW(handle, &mut buffer) > 0 {
                let _ = CloseHandle(handle);
                let path = String::from_utf16_lossy(
                    &buffer[..buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len())],
                );
                Some(path)
            } else {
                let _ = CloseHandle(handle);
                None
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::ProcessInfo;
    use anyhow::{Context, Result};
    use std::fs;
    use std::path::Path;

    pub fn enumerate_processes() -> Result<Vec<ProcessInfo>> {
        let mut processes = Vec::new();

        let proc_dir = Path::new("/proc");
        if !proc_dir.exists() {
            return Err(anyhow::anyhow!("procfs not available"));
        }

        for entry in fs::read_dir(proc_dir).context("Failed to read /proc directory")? {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let file_name = entry.file_name();
            let pid_str = match file_name.to_str() {
                Some(s) => s,
                None => continue,
            };

            let pid: u32 = match pid_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            if let Ok(info) = get_process_info(pid) {
                processes.push(info);
            }
        }

        Ok(processes)
    }

    fn get_process_info(pid: u32) -> Result<ProcessInfo> {
        let stat_path = format!("/proc/{}/stat", pid);
        let stat_content = fs::read_to_string(&stat_path).context("Failed to read process stat")?;

        let (name, ppid, thread_count) = parse_stat(&stat_content)?;

        let exe_path = format!("/proc/{}/exe", pid);
        let path = fs::read_link(&exe_path)
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        Ok(ProcessInfo {
            pid,
            ppid,
            name,
            path,
            thread_count,
        })
    }

    fn parse_stat(stat: &str) -> Result<(String, u32, u32)> {
        let open_paren = stat.find('(').context("Invalid stat format")?;
        let close_paren = stat.rfind(')').context("Invalid stat format")?;

        let name = stat[open_paren + 1..close_paren].to_string();
        let rest = &stat[close_paren + 2..];
        let fields: Vec<&str> = rest.split_whitespace().collect();

        if fields.len() < 18 {
            return Err(anyhow::anyhow!("Insufficient fields in stat"));
        }

        let ppid: u32 = fields[1].parse().context("Failed to parse PPID")?;
        let thread_count: u32 = fields[17].parse().unwrap_or(1);

        Ok((name, ppid, thread_count))
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::ProcessInfo;
    use anyhow::Result;
    use libc::{c_int, c_void, pid_t, size_t};
    use std::mem;
    use std::ptr;

    const CTL_KERN: c_int = 1;
    const KERN_PROC: c_int = 14;
    const KERN_PROC_ALL: c_int = 0;

    #[repr(C)]
    struct kinfo_proc {
        kp_proc: extern_proc,
        kp_eproc: eproc,
    }

    #[repr(C)]
    struct extern_proc {
        p_un: [u8; 16],
        p_pid: pid_t,
        p_ppid: pid_t,
        p_pgid: pid_t,
        p_stat: u16,
        p_pad1: [u8; 2],
        p_xstat: u16,
        p_pad2: [u8; 2],
        p_ru: [u8; 144],
    }

    #[repr(C)]
    struct eproc {
        e_paddr: u64,
        e_sess: u64,
        e_pcred: pcred,
        e_ucred: ucred,
        e_vm: vmspace,
        e_ppid: pid_t,
        e_pgid: pid_t,
        e_jobc: i16,
        e_tdev: u32,
        e_tpgid: pid_t,
        e_tsess: u64,
        e_wmesg: [u8; 8],
        e_xsize: i32,
        e_xrssize: i16,
        e_xccount: i16,
        e_xswrss: i16,
        e_flag: i32,
        e_login: [u8; 12],
        e_spare: [i32; 4],
    }

    #[repr(C)]
    struct pcred {
        pc_lock: [u8; 72],
        pc_ucred: u64,
        p_ruid: u32,
        p_svuid: u32,
        p_rgid: u32,
        p_svgid: u32,
        p_refcnt: i32,
    }

    #[repr(C)]
    struct ucred {
        cr_ref: i32,
        cr_uid: u32,
        cr_ngroups: i16,
        cr_groups: [u32; 16],
    }

    #[repr(C)]
    struct vmspace {
        vm_refcnt: i32,
        vm_shm: u64,
        vm_rssize: i32,
        vm_tsize: i32,
        vm_dsize: i32,
        vm_ssize: i32,
        vm_pad: [u8; 8],
    }

    pub fn enumerate_processes() -> Result<Vec<ProcessInfo>> {
        unsafe {
            let mut mib = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0];
            let mut size: size_t = 0;

            if libc::sysctl(
                mib.as_mut_ptr(),
                3,
                ptr::null_mut(),
                &mut size,
                ptr::null_mut(),
                0,
            ) == -1
            {
                return Err(anyhow::anyhow!("sysctl failed to get process list size"));
            }

            let count = size / mem::size_of::<kinfo_proc>();
            let mut procs: Vec<kinfo_proc> = Vec::with_capacity(count);
            procs.resize_with(count, || mem::zeroed());

            if libc::sysctl(
                mib.as_mut_ptr(),
                3,
                procs.as_mut_ptr() as *mut c_void,
                &mut size,
                ptr::null_mut(),
                0,
            ) == -1
            {
                return Err(anyhow::anyhow!("sysctl failed to get process list"));
            }

            let actual_count = size / mem::size_of::<kinfo_proc>();
            procs.truncate(actual_count);

            let mut processes = Vec::with_capacity(actual_count);

            for proc in procs {
                let pid = proc.kp_proc.p_pid as u32;
                let ppid = proc.kp_proc.p_ppid as u32;

                let name = get_process_name(pid).unwrap_or_else(|_| format!("pid_{}", pid));
                let path = get_process_path(pid);

                processes.push(ProcessInfo {
                    pid,
                    ppid,
                    name,
                    path,
                    thread_count: 1,
                });
            }

            Ok(processes)
        }
    }

    fn get_process_name(pid: u32) -> Result<String> {
        let mut buffer = [0u8; 1024];
        let mut mib = [CTL_KERN, libc::KERN_PROCARGS2, pid as c_int];

        unsafe {
            let mut size = buffer.len();
            if libc::sysctl(
                mib.as_mut_ptr(),
                3,
                buffer.as_mut_ptr() as *mut c_void,
                &mut size,
                ptr::null_mut(),
                0,
            ) == 0
                && size >= 4
            {
                let _argc = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
                let args_start = 4;

                if let Some(null_pos) = buffer[args_start..size].iter().position(|&b| b == 0) {
                    let path_bytes = &buffer[args_start..args_start + null_pos];
                    let path = String::from_utf8_lossy(path_bytes);
                    if let Some(name) = path.rsplit('/').next() {
                        let name = name.trim();
                        if !name.is_empty() {
                            return Ok(name.to_string());
                        }
                    }
                }
            }
        }

        Err(anyhow::anyhow!("Failed to get process name"))
    }

    fn get_process_path(pid: u32) -> Option<String> {
        unsafe {
            let mut buffer = [0u8; 2048];
            let size = buffer.len() as u32;

            extern "C" {
                fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
            }

            let ret = proc_pidpath(pid as c_int, buffer.as_mut_ptr() as *mut c_void, size);

            if ret > 0 {
                let path_bytes = &buffer[..ret as usize];
                Some(String::from_utf8_lossy(path_bytes).to_string())
            } else {
                None
            }
        }
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod platform {
    use super::ProcessInfo;
    use anyhow::Result;

    pub fn enumerate_processes() -> Result<Vec<ProcessInfo>> {
        Err(anyhow::anyhow!(
            "Process enumeration not supported on this platform"
        ))
    }
}

/// Enumerates all running processes on the system.
///
/// # Platform Support
///
/// - **Windows**: Uses the ToolHelp API to enumerate processes.
/// - **Linux**: Reads from the /proc filesystem.
/// - **macOS**: Uses sysctl KERN_PROC_ALL and proc_pidpath for process enumeration.
///
/// # Errors
///
/// Returns an error if process enumeration fails due to insufficient
/// privileges or platform limitations.
pub fn enumerate_processes() -> anyhow::Result<Vec<ProcessInfo>> {
    platform::enumerate_processes()
}

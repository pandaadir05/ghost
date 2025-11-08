use std::fmt;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: Option<String>,
    pub thread_count: u32,
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
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows::Win32::System::ProcessStatus::GetProcessImageFileNameW;

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

#[cfg(not(windows))]
mod platform {
    use super::ProcessInfo;
    use anyhow::Result;

    pub fn enumerate_processes() -> Result<Vec<ProcessInfo>> {
        // TODO: Implement Linux/macOS enumeration
        Ok(Vec::new())
    }
}

pub fn enumerate_processes() -> anyhow::Result<Vec<ProcessInfo>> {
    platform::enumerate_processes()
}

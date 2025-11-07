use std::fmt;

#[derive(Debug, Clone)]
pub struct ThreadInfo {
    pub tid: u32,
    pub owner_pid: u32,
    pub start_address: usize,
}

impl fmt::Display for ThreadInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TID {} @ {:#x}",
            self.tid, self.start_address
        )
    }
}

#[cfg(windows)]
mod platform {
    use super::ThreadInfo;
    use anyhow::{Context, Result};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD,
    };

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
                        threads.push(ThreadInfo {
                            tid: entry.th32ThreadID,
                            owner_pid: entry.th32OwnerProcessID,
                            start_address: 0, // TODO: Get actual start address
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
}

#[cfg(not(windows))]
mod platform {
    use super::ThreadInfo;
    use anyhow::Result;

    pub fn enumerate_threads(_pid: u32) -> Result<Vec<ThreadInfo>> {
        Ok(Vec::new())
    }
}

pub fn enumerate_threads(pid: u32) -> anyhow::Result<Vec<ThreadInfo>> {
    platform::enumerate_threads(pid)
}

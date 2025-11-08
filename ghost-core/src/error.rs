use thiserror::Error;

#[derive(Error, Debug)]
pub enum GhostError {
    #[error("Process access denied (PID: {pid})")]
    AccessDenied { pid: u32 },
    
    #[error("Process not found (PID: {pid})")]
    ProcessNotFound { pid: u32 },
    
    #[error("Memory enumeration failed: {reason}")]
    MemoryEnumeration { reason: String },
    
    #[error("Thread enumeration failed: {reason}")]
    ThreadEnumeration { reason: String },
    
    #[error("Insufficient privileges for operation")]
    InsufficientPrivileges,
    
    #[error("Windows API error: {message}")]
    WindowsApi { message: String },
    
    #[error("Detection engine error: {message}")]
    Detection { message: String },
}

pub type Result<T> = std::result::Result<T, GhostError>;
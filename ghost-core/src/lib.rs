pub mod detection;
pub mod error;
pub mod hooks;
pub mod memory;
pub mod process;
pub mod shellcode;
pub mod thread;

pub use detection::{DetectionEngine, DetectionResult, ThreatLevel};
pub use error::{GhostError, Result};
pub use hooks::{detect_hook_injection, HookDetectionResult, HookInfo};
pub use memory::{MemoryProtection, MemoryRegion};
pub use process::ProcessInfo;
pub use shellcode::{ShellcodeDetection, ShellcodeDetector};
pub use thread::ThreadInfo;

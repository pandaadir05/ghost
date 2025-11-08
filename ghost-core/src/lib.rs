pub mod detection;
pub mod error;
pub mod memory;
pub mod process;
pub mod thread;

pub use detection::{DetectionEngine, DetectionResult, ThreatLevel};
pub use error::{GhostError, Result};
pub use memory::{MemoryProtection, MemoryRegion};
pub use process::ProcessInfo;
pub use thread::ThreadInfo;

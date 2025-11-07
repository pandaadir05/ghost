pub mod detection;
pub mod memory;
pub mod process;
pub mod thread;

pub use detection::{DetectionEngine, DetectionResult, ThreatLevel};
pub use memory::{MemoryProtection, MemoryRegion};
pub use process::ProcessInfo;
pub use thread::ThreadInfo;

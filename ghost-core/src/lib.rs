pub mod detection;
pub mod memory;
pub mod process;

pub use detection::{DetectionEngine, DetectionResult, ThreatLevel};
pub use memory::{MemoryProtection, MemoryRegion};
pub use process::ProcessInfo;

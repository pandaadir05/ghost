pub mod anomaly;
pub mod config;
pub mod detection;
pub mod ebpf;
pub mod testing;
pub mod error;
pub mod evasion;
pub mod hollowing;
pub mod hooks;
pub mod memory;
pub mod process;
pub mod shellcode;
pub mod streaming;
pub mod thread;
pub mod threat_intel;

pub use anomaly::{AnomalyDetector, AnomalyScore, ProcessFeatures};
pub use config::{DetectionConfig, ProcessFilter};
pub use detection::{DetectionEngine, DetectionResult, ThreatLevel};
#[cfg(target_os = "linux")]
pub use ebpf::{EbpfDetector, EbpfEvent, EbpfError, EbpfStatistics};
pub use error::{GhostError, Result};
pub use evasion::{
    EvasionDetector, EvasionResult, EvasionTechnique, EvasionSeverity,
    TimingAnalyzer, EnvironmentChecker, BehaviorAnalyzer, ObfuscationDetector
};
pub use hollowing::{HollowingDetection, HollowingDetector, HollowingIndicator};
pub use hooks::{detect_hook_injection, HookDetectionResult, HookInfo};
pub use memory::{MemoryProtection, MemoryRegion};
pub use process::ProcessInfo;
pub use shellcode::{ShellcodeDetection, ShellcodeDetector};
pub use streaming::{
    EventStreamingSystem, EventChannel, StreamingEvent, EventType, EventSeverity,
    AlertManager, Alert, AlertRule, CorrelationEngine, NotificationSystem
};
pub use thread::ThreadInfo;
pub use threat_intel::{
    ThreatIntelligence, ThreatContext, IndicatorOfCompromise,
    ThreatActor, Campaign, IocType, SophisticationLevel
};

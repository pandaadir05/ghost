//! # Ghost - Cross-Platform Process Injection Detection Framework
//!
//! Ghost is a comprehensive security framework for detecting process injection,
//! memory manipulation, and advanced evasion techniques in running processes.
//!
//! ## Features
//!
//! - **Multi-layer detection**: Combines memory analysis, behavioral patterns,
//!   and machine learning for accurate threat detection.
//! - **MITRE ATT&CK integration**: Maps detected behaviors to the MITRE ATT&CK
//!   framework for standardized threat classification.
//! - **Cross-platform support**: Works on Windows, Linux (with eBPF), and macOS.
//! - **Threat intelligence**: Integrates with threat feeds for IOC correlation.
//! - **Performance optimized**: Designed for low-overhead continuous monitoring.
//!
//! ## Quick Start
//!
//! ```no_run
//! use ghost_core::{DetectionEngine, process, memory, thread};
//!
//! // Create detection engine
//! let mut engine = DetectionEngine::new().expect("Failed to create engine");
//!
//! // Enumerate and analyze processes
//! let processes = process::enumerate_processes().expect("Failed to enumerate");
//!
//! for proc in &processes {
//!     if let Ok(regions) = memory::enumerate_memory_regions(proc.pid) {
//!         let threads = thread::enumerate_threads(proc.pid).ok();
//!         let result = engine.analyze_process(proc, &regions, threads.as_deref());
//!
//!         if result.threat_level != ghost_core::ThreatLevel::Clean {
//!             println!("Suspicious: {} (PID: {})", proc.name, proc.pid);
//!         }
//!     }
//! }
//! ```
//!
//! ## Module Overview
//!
//! - [`detection`]: Core detection engine orchestrating all analysis.
//! - [`process`]: Process enumeration and information gathering.
//! - [`memory`]: Memory region analysis and protection detection.
//! - [`thread`]: Thread enumeration and behavioral analysis.
//! - [`shellcode`]: Shellcode pattern detection and signature matching.
//! - [`hollowing`]: Process hollowing detection algorithms.
//! - [`evasion`]: Anti-analysis and evasion technique detection.
//! - [`anomaly`]: Statistical anomaly detection using ML.
//! - [`mitre_attack`]: MITRE ATT&CK framework mapping.
//! - [`threat_intel`]: Threat intelligence correlation.

pub mod anomaly;
pub mod behavioral_ml;
pub mod config;
pub mod detection;
pub mod ebpf;
pub mod error;
pub mod evasion;
pub mod hollowing;
pub mod hooks;
pub mod live_feeds;
pub mod memory;
pub mod mitre_attack;
pub mod ml_cloud;
pub mod neural_memory;
pub mod pe_parser;
pub mod process;
pub mod shellcode;
pub mod streaming;
pub mod testing;
pub mod thread;
pub mod threat_intel;
pub mod yara_engine;

pub use anomaly::{AnomalyDetector, AnomalyScore, ProcessFeatures};
pub use behavioral_ml::{
    AdvancedBehavioralML, BehavioralAnalysisResult, BehavioralAnomaly, ModelConsensus,
    PredictedTechnique, RiskLevel, TemporalAnalysis,
};
pub use config::{DetectionConfig, ProcessFilter};
pub use detection::{DetectionEngine, DetectionResult, ThreatLevel};
#[cfg(target_os = "linux")]
pub use ebpf::{EbpfDetector, EbpfError, EbpfEvent, EbpfStatistics};
pub use error::{GhostError, Result};
pub use evasion::{
    BehaviorAnalyzer, EnvironmentChecker, EvasionDetector, EvasionResult, EvasionSeverity,
    EvasionTechnique, ObfuscationDetector, TimingAnalyzer,
};
pub use hollowing::{HollowingDetection, HollowingDetector, HollowingIndicator};
pub use hooks::{detect_hook_injection, HookDetectionResult, HookInfo};
pub use live_feeds::{FeedType, LiveThreatFeeds, ThreatFeed};
pub use memory::{MemoryProtection, MemoryRegion};
pub use mitre_attack::{
    AttackTactic, AttackTechnique, DetectedTechnique, KillChainAnalysis, MitreAnalysisResult,
    MitreAttackEngine, RiskAssessment, TacticCoverage, ThreatActor, ThreatActorMatch,
};
pub use ml_cloud::{CloudMLEngine, InferenceResult, MLModel, ThreatPrediction, ThreatSeverity};
pub use neural_memory::{
    DetectedEvasion, DetectedPattern, EvasionCategory, MemoryAnomaly, NeuralAnalysisResult,
    NeuralInsights, NeuralMemoryAnalyzer, PatternType, PolymorphicIndicator,
};
pub use pe_parser::{ExportEntry, IATHookResult, ImportEntry};
pub use process::ProcessInfo;
pub use shellcode::{ShellcodeDetection, ShellcodeDetector};
pub use streaming::{
    Alert, AlertManager, AlertRule, CorrelationEngine, EventChannel, EventSeverity,
    EventStreamingSystem, EventType, NotificationSystem, StreamingEvent,
};
pub use thread::{
    detect_apc_injection, detect_hardware_breakpoints, detect_thread_hijacking, APCInjectionResult,
    APCThreadInfo, BreakpointInfo, BreakpointType, HardwareBreakpointResult, HijackedThreadInfo,
    ThreadBreakpoints, ThreadHijackingResult, ThreadInfo,
};
pub use threat_intel::{
    Campaign, IndicatorOfCompromise, IocType, SophisticationLevel, ThreatActor as ThreatIntelActor,
    ThreatContext, ThreatIntelligence,
};
pub use yara_engine::{
    DynamicYaraEngine, RuleMatch, ThreatLevel as YaraThreatLevel, YaraRuleMetadata, YaraScanResult,
};

pub mod anomaly;
pub mod behavioral_ml;
pub mod config;
pub mod detection;
pub mod ebpf;
pub mod testing;
pub mod error;
pub mod evasion;
pub mod hollowing;
pub mod hooks;
pub mod live_feeds;
pub mod memory;
pub mod mitre_attack;
pub mod ml_cloud;
pub mod neural_memory;
pub mod process;
pub mod shellcode;
pub mod streaming;
pub mod thread;
pub mod threat_intel;
pub mod yara_engine;

pub use anomaly::{AnomalyDetector, AnomalyScore, ProcessFeatures};
pub use behavioral_ml::{
    AdvancedBehavioralML, BehavioralAnalysisResult, PredictedTechnique, BehavioralAnomaly,
    ModelConsensus, TemporalAnalysis, RiskLevel
};
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
pub use live_feeds::{LiveThreatFeeds, ThreatFeed, FeedType};
pub use memory::{MemoryProtection, MemoryRegion};
pub use mitre_attack::{
    MitreAttackEngine, MitreAnalysisResult, AttackTechnique, AttackTactic, ThreatActor,
    DetectedTechnique, TacticCoverage, ThreatActorMatch, KillChainAnalysis, RiskAssessment
};
pub use ml_cloud::{CloudMLEngine, InferenceResult, MLModel, ThreatPrediction, ThreatSeverity};
pub use neural_memory::{
    NeuralMemoryAnalyzer, NeuralAnalysisResult, DetectedPattern, DetectedEvasion,
    PolymorphicIndicator, MemoryAnomaly, NeuralInsights, PatternType, EvasionCategory
};
pub use process::ProcessInfo;
pub use shellcode::{ShellcodeDetection, ShellcodeDetector};
pub use streaming::{
    EventStreamingSystem, EventChannel, StreamingEvent, EventType, EventSeverity,
    AlertManager, Alert, AlertRule, CorrelationEngine, NotificationSystem
};
pub use thread::ThreadInfo;
pub use threat_intel::{
    ThreatIntelligence, ThreatContext, IndicatorOfCompromise,
    ThreatActor as ThreatIntelActor, Campaign, IocType, SophisticationLevel
};
pub use yara_engine::{
    DynamicYaraEngine, YaraRuleSource, YaraScanResult, RuleMatch, ThreatLevel as YaraThreatLevel
};

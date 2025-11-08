use std::collections::HashMap;
use std::time::{SystemTime, Duration};
use serde::{Serialize, Deserialize};
use crate::{DetectionResult, ThreatLevel, ProcessInfo};

/// Threat Intelligence Integration Module
/// Provides real-time threat context and IOC matching
pub struct ThreatIntelligence {
    ioc_database: IocDatabase,
    threat_feeds: Vec<ThreatFeed>,
    attribution_engine: AttributionEngine,
    reputation_cache: ReputationCache,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorOfCompromise {
    pub id: String,
    pub ioc_type: IocType,
    pub value: String,
    pub threat_level: ThreatLevel,
    pub source: String,
    pub confidence: f32,
    pub created_date: SystemTime,
    pub expiry_date: Option<SystemTime>,
    pub tags: Vec<String>,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IocType {
    ProcessName,
    ProcessPath,
    FileHash,
    NetworkAddress,
    MemorySignature,
    BehaviorPattern,
    RegistryKey,
    Mutex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatContext {
    pub matched_iocs: Vec<IndicatorOfCompromise>,
    pub threat_actor: Option<ThreatActor>,
    pub campaign: Option<Campaign>,
    pub attribution_confidence: f32,
    pub risk_score: f32,
    pub recommended_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    pub name: String,
    pub aliases: Vec<String>,
    pub motivation: String,
    pub sophistication_level: SophisticationLevel,
    pub known_techniques: Vec<String>,
    pub geographical_focus: Vec<String>,
    pub first_seen: SystemTime,
    pub last_activity: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SophisticationLevel {
    ScriptKiddie,
    Opportunistic,
    Professional,
    AdvancedPersistent,
    NationState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Campaign {
    pub name: String,
    pub description: String,
    pub threat_actor: String,
    pub start_date: SystemTime,
    pub end_date: Option<SystemTime>,
    pub target_sectors: Vec<String>,
    pub attack_patterns: Vec<String>,
    pub iocs: Vec<String>,
}

pub struct IocDatabase {
    indicators: HashMap<String, IndicatorOfCompromise>,
    hash_index: HashMap<String, Vec<String>>,
    pattern_index: HashMap<String, Vec<String>>,
    behavior_signatures: Vec<BehaviorSignature>,
}

#[derive(Debug, Clone)]
pub struct BehaviorSignature {
    pub id: String,
    pub name: String,
    pub description: String,
    pub patterns: Vec<BehaviorPattern>,
    pub confidence_threshold: f32,
    pub severity: ThreatLevel,
}

#[derive(Debug, Clone)]
pub struct BehaviorPattern {
    pub sequence: Vec<ProcessAction>,
    pub timing_constraints: Vec<TimingConstraint>,
    pub frequency_requirements: FrequencyRequirement,
}

#[derive(Debug, Clone)]
pub enum ProcessAction {
    ProcessCreation { name: String, cmdline: String },
    MemoryAllocation { protection: String, size: usize },
    NetworkConnection { address: String, port: u16 },
    FileOperation { path: String, operation: String },
    RegistryOperation { key: String, operation: String },
    ProcessInjection { target_pid: u32, method: String },
}

#[derive(Debug, Clone)]
pub struct TimingConstraint {
    pub max_interval: Duration,
    pub sequence_window: Duration,
}

#[derive(Debug, Clone)]
pub struct FrequencyRequirement {
    pub min_occurrences: u32,
    pub time_window: Duration,
}

pub struct ThreatFeed {
    pub name: String,
    pub url: String,
    pub feed_type: FeedType,
    pub update_interval: Duration,
    pub last_update: SystemTime,
    pub credential: Option<FeedCredential>,
}

#[derive(Debug, Clone)]
pub enum FeedType {
    StixTaxii,
    JSON,
    CSV,
    XML,
    MISP,
    OpenIOC,
}

#[derive(Debug, Clone)]
pub struct FeedCredential {
    pub api_key: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

pub struct AttributionEngine {
    threat_actors: HashMap<String, ThreatActor>,
    campaigns: HashMap<String, Campaign>,
    attribution_rules: Vec<AttributionRule>,
    similarity_calculator: SimilarityCalculator,
}

#[derive(Debug, Clone)]
pub struct AttributionRule {
    pub rule_id: String,
    pub conditions: Vec<AttributionCondition>,
    pub confidence_weight: f32,
    pub threat_actor: String,
    pub campaign: Option<String>,
}

#[derive(Debug, Clone)]
pub enum AttributionCondition {
    IocMatch { ioc_types: Vec<IocType>, min_matches: u32 },
    TechniquePattern { techniques: Vec<String>, correlation: f32 },
    TemporalPattern { time_windows: Vec<Duration>, frequency: u32 },
    GeographicalIndicator { regions: Vec<String>, confidence: f32 },
}

pub struct SimilarityCalculator {
    technique_weights: HashMap<String, f32>,
    temporal_weights: HashMap<String, f32>,
    behavioral_weights: HashMap<String, f32>,
}

pub struct ReputationCache {
    process_reputations: HashMap<String, ProcessReputation>,
    ip_reputations: HashMap<String, IpReputation>,
    hash_reputations: HashMap<String, HashReputation>,
    cache_ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct ProcessReputation {
    pub process_name: String,
    pub reputation_score: f32,
    pub classification: ReputationClass,
    pub sources: Vec<String>,
    pub last_updated: SystemTime,
    pub occurrence_count: u32,
}

#[derive(Debug, Clone)]
pub enum ReputationClass {
    Trusted,
    Unknown,
    Suspicious,
    Malicious,
    PUA, // Potentially Unwanted Application
}

#[derive(Debug, Clone)]
pub struct IpReputation {
    pub ip_address: String,
    pub reputation_score: f32,
    pub categories: Vec<String>,
    pub threat_types: Vec<String>,
    pub geographical_info: GeographicalInfo,
}

#[derive(Debug, Clone)]
pub struct GeographicalInfo {
    pub country: String,
    pub region: String,
    pub city: String,
    pub isp: String,
    pub organization: String,
}

#[derive(Debug, Clone)]
pub struct HashReputation {
    pub file_hash: String,
    pub hash_type: HashType,
    pub reputation_score: f32,
    pub vendor_detections: Vec<VendorDetection>,
    pub file_info: Option<FileInfo>,
}

#[derive(Debug, Clone)]
pub enum HashType {
    MD5,
    SHA1,
    SHA256,
    SHA512,
}

#[derive(Debug, Clone)]
pub struct VendorDetection {
    pub vendor: String,
    pub detection_name: String,
    pub confidence: f32,
    pub scan_date: SystemTime,
}

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub file_name: String,
    pub file_size: u64,
    pub file_type: String,
    pub creation_date: SystemTime,
    pub signature_info: Option<SignatureInfo>,
}

#[derive(Debug, Clone)]
pub struct SignatureInfo {
    pub is_signed: bool,
    pub signer: Option<String>,
    pub signature_valid: bool,
    pub certificate_info: Option<CertificateInfo>,
}

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub issuer: String,
    pub subject: String,
    pub serial_number: String,
    pub valid_from: SystemTime,
    pub valid_to: SystemTime,
}

impl ThreatIntelligence {
    pub fn new() -> Self {
        Self {
            ioc_database: IocDatabase::new(),
            threat_feeds: Vec::new(),
            attribution_engine: AttributionEngine::new(),
            reputation_cache: ReputationCache::new(),
        }
    }

    /// Initialize threat intelligence with default threat feeds
    pub async fn initialize_default_feeds(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Add default threat feeds
        self.add_threat_feed(ThreatFeed {
            name: "MITRE ATT&CK".to_string(),
            url: "https://attack.mitre.org/stix/".to_string(),
            feed_type: FeedType::StixTaxii,
            update_interval: Duration::from_secs(86400), // Daily
            last_update: SystemTime::now(),
            credential: None,
        });

        self.add_threat_feed(ThreatFeed {
            name: "AlienVault OTX".to_string(),
            url: "https://otx.alienvault.com/api/v1/".to_string(),
            feed_type: FeedType::JSON,
            update_interval: Duration::from_secs(3600), // Hourly
            last_update: SystemTime::now(),
            credential: None,
        });

        // Initialize with basic IOCs
        self.load_default_iocs().await?;
        
        Ok(())
    }

    /// Enrich detection results with threat intelligence
    pub async fn enrich_detection(&self, detection: &DetectionResult) -> ThreatContext {
        let mut matched_iocs = Vec::new();
        let mut risk_score = 0.0f32;

        // Check process name against IOCs
        if let Some(iocs) = self.ioc_database.lookup_process_name(&detection.process.name) {
            matched_iocs.extend(iocs);
        }

        // Check process path against IOCs
        if let Some(path) = &detection.process.path {
            if let Some(iocs) = self.ioc_database.lookup_process_path(path) {
                matched_iocs.extend(iocs);
            }
        }

        // Check memory signatures
        for indicator in &detection.indicators {
            if let Some(iocs) = self.ioc_database.lookup_memory_signature(indicator) {
                matched_iocs.extend(iocs);
            }
        }

        // Calculate risk score based on matched IOCs
        for ioc in &matched_iocs {
            risk_score += match ioc.threat_level {
                ThreatLevel::Clean => 0.0,
                ThreatLevel::Suspicious => ioc.confidence * 0.5,
                ThreatLevel::Malicious => ioc.confidence * 1.0,
            };
        }

        // Perform attribution analysis
        let (threat_actor, campaign, attribution_confidence) = 
            self.attribution_engine.analyze_attribution(&matched_iocs, &detection.indicators);

        // Generate recommended actions
        let recommended_actions = self.generate_recommendations(&matched_iocs, risk_score);

        ThreatContext {
            matched_iocs,
            threat_actor,
            campaign,
            attribution_confidence,
            risk_score: risk_score.min(1.0),
            recommended_actions,
        }
    }

    /// Add a new threat feed
    pub fn add_threat_feed(&mut self, feed: ThreatFeed) {
        self.threat_feeds.push(feed);
    }

    /// Update all threat feeds
    pub async fn update_threat_feeds(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        for feed in &mut self.threat_feeds {
            if SystemTime::now().duration_since(feed.last_update).unwrap_or_default() 
                >= feed.update_interval {
                
                match self.fetch_feed_data(feed).await {
                    Ok(iocs) => {
                        self.ioc_database.update_indicators(iocs);
                        feed.last_update = SystemTime::now();
                    }
                    Err(e) => {
                        eprintln!("Failed to update feed {}: {}", feed.name, e);
                    }
                }
            }
        }
        Ok(())
    }

    /// Fetch data from a threat feed
    async fn fetch_feed_data(&self, feed: &ThreatFeed) -> Result<Vec<IndicatorOfCompromise>, Box<dyn std::error::Error>> {
        // Implementation would depend on feed type
        match feed.feed_type {
            FeedType::JSON => self.fetch_json_feed(feed).await,
            FeedType::StixTaxii => self.fetch_stix_feed(feed).await,
            FeedType::CSV => self.fetch_csv_feed(feed).await,
            _ => Err("Unsupported feed type".into()),
        }
    }

    async fn fetch_json_feed(&self, feed: &ThreatFeed) -> Result<Vec<IndicatorOfCompromise>, Box<dyn std::error::Error>> {
        // Placeholder implementation
        // In a real implementation, this would fetch from the feed URL
        Ok(Vec::new())
    }

    async fn fetch_stix_feed(&self, feed: &ThreatFeed) -> Result<Vec<IndicatorOfCompromise>, Box<dyn std::error::Error>> {
        // Placeholder implementation
        // In a real implementation, this would parse STIX/TAXII data
        Ok(Vec::new())
    }

    async fn fetch_csv_feed(&self, feed: &ThreatFeed) -> Result<Vec<IndicatorOfCompromise>, Box<dyn std::error::Error>> {
        // Placeholder implementation
        // In a real implementation, this would parse CSV threat data
        Ok(Vec::new())
    }

    /// Load default IOCs for common injection techniques
    async fn load_default_iocs(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let default_iocs = vec![
            IndicatorOfCompromise {
                id: "IOC-001".to_string(),
                ioc_type: IocType::ProcessName,
                value: "rundll32.exe".to_string(),
                threat_level: ThreatLevel::Suspicious,
                source: "Default".to_string(),
                confidence: 0.6,
                created_date: SystemTime::now(),
                expiry_date: None,
                tags: vec!["process-injection".to_string(), "living-off-the-land".to_string()],
                mitre_techniques: vec!["T1055".to_string()],
            },
            IndicatorOfCompromise {
                id: "IOC-002".to_string(),
                ioc_type: IocType::MemorySignature,
                value: "CreateRemoteThread".to_string(),
                threat_level: ThreatLevel::Suspicious,
                source: "Default".to_string(),
                confidence: 0.8,
                created_date: SystemTime::now(),
                expiry_date: None,
                tags: vec!["process-injection".to_string(), "dll-injection".to_string()],
                mitre_techniques: vec!["T1055.001".to_string()],
            },
            IndicatorOfCompromise {
                id: "IOC-003".to_string(),
                ioc_type: IocType::BehaviorPattern,
                value: "rwx_allocation_followed_by_execution".to_string(),
                threat_level: ThreatLevel::Malicious,
                source: "Default".to_string(),
                confidence: 0.9,
                created_date: SystemTime::now(),
                expiry_date: None,
                tags: vec!["shellcode".to_string(), "code-injection".to_string()],
                mitre_techniques: vec!["T1055.002".to_string()],
            },
        ];

        for ioc in default_iocs {
            self.ioc_database.add_indicator(ioc);
        }

        Ok(())
    }

    fn generate_recommendations(&self, iocs: &[IndicatorOfCompromise], risk_score: f32) -> Vec<String> {
        let mut recommendations = Vec::new();

        if risk_score > 0.8 {
            recommendations.push("CRITICAL: Immediate isolation recommended".to_string());
            recommendations.push("Initiate incident response procedures".to_string());
            recommendations.push("Collect forensic artifacts for analysis".to_string());
        } else if risk_score > 0.5 {
            recommendations.push("HIGH: Enhanced monitoring required".to_string());
            recommendations.push("Review process behavior and network connections".to_string());
            recommendations.push("Consider sandboxed analysis".to_string());
        } else if risk_score > 0.2 {
            recommendations.push("MEDIUM: Continued observation advised".to_string());
            recommendations.push("Log all activities for correlation".to_string());
        }

        // Add technique-specific recommendations
        for ioc in iocs {
            for technique in &ioc.mitre_techniques {
                match technique.as_str() {
                    "T1055" => recommendations.push("Deploy process injection countermeasures".to_string()),
                    "T1055.001" => recommendations.push("Monitor DLL loading activities".to_string()),
                    "T1055.002" => recommendations.push("Implement PE injection detection".to_string()),
                    _ => {}
                }
            }
        }

        recommendations.sort();
        recommendations.dedup();
        recommendations
    }
}

impl IocDatabase {
    pub fn new() -> Self {
        Self {
            indicators: HashMap::new(),
            hash_index: HashMap::new(),
            pattern_index: HashMap::new(),
            behavior_signatures: Vec::new(),
        }
    }

    pub fn add_indicator(&mut self, ioc: IndicatorOfCompromise) {
        // Add to main database
        self.indicators.insert(ioc.id.clone(), ioc.clone());

        // Update indexes for fast lookup
        match ioc.ioc_type {
            IocType::FileHash => {
                self.hash_index.entry(ioc.value.clone())
                    .or_insert_with(Vec::new)
                    .push(ioc.id.clone());
            }
            IocType::MemorySignature | IocType::BehaviorPattern => {
                self.pattern_index.entry(ioc.value.clone())
                    .or_insert_with(Vec::new)
                    .push(ioc.id.clone());
            }
            _ => {}
        }
    }

    pub fn lookup_process_name(&self, name: &str) -> Option<Vec<IndicatorOfCompromise>> {
        let matches: Vec<_> = self.indicators
            .values()
            .filter(|ioc| ioc.ioc_type == IocType::ProcessName && ioc.value == name)
            .cloned()
            .collect();
        
        if matches.is_empty() { None } else { Some(matches) }
    }

    pub fn lookup_process_path(&self, path: &str) -> Option<Vec<IndicatorOfCompromise>> {
        let matches: Vec<_> = self.indicators
            .values()
            .filter(|ioc| ioc.ioc_type == IocType::ProcessPath && path.contains(&ioc.value))
            .cloned()
            .collect();
        
        if matches.is_empty() { None } else { Some(matches) }
    }

    pub fn lookup_memory_signature(&self, signature: &str) -> Option<Vec<IndicatorOfCompromise>> {
        if let Some(ioc_ids) = self.pattern_index.get(signature) {
            let matches: Vec<_> = ioc_ids
                .iter()
                .filter_map(|id| self.indicators.get(id))
                .cloned()
                .collect();
            if matches.is_empty() { None } else { Some(matches) }
        } else {
            None
        }
    }

    pub fn update_indicators(&mut self, new_iocs: Vec<IndicatorOfCompromise>) {
        for ioc in new_iocs {
            self.add_indicator(ioc);
        }
    }
}

impl AttributionEngine {
    pub fn new() -> Self {
        Self {
            threat_actors: HashMap::new(),
            campaigns: HashMap::new(),
            attribution_rules: Vec::new(),
            similarity_calculator: SimilarityCalculator::new(),
        }
    }

    pub fn analyze_attribution(&self, iocs: &[IndicatorOfCompromise], indicators: &[String]) 
        -> (Option<ThreatActor>, Option<Campaign>, f32) {
        
        let mut best_actor: Option<ThreatActor> = None;
        let mut best_campaign: Option<Campaign> = None;
        let mut best_confidence = 0.0f32;

        // Analyze each attribution rule
        for rule in &self.attribution_rules {
            let confidence = self.evaluate_attribution_rule(rule, iocs, indicators);
            
            if confidence > best_confidence {
                best_confidence = confidence;
                if let Some(actor) = self.threat_actors.get(&rule.threat_actor) {
                    best_actor = Some(actor.clone());
                }
                if let Some(campaign_name) = &rule.campaign {
                    if let Some(campaign) = self.campaigns.get(campaign_name) {
                        best_campaign = Some(campaign.clone());
                    }
                }
            }
        }

        (best_actor, best_campaign, best_confidence)
    }

    fn evaluate_attribution_rule(&self, rule: &AttributionRule, 
                                 iocs: &[IndicatorOfCompromise], 
                                 indicators: &[String]) -> f32 {
        let mut total_confidence = 0.0f32;
        let mut condition_count = 0;

        for condition in &rule.conditions {
            match condition {
                AttributionCondition::IocMatch { ioc_types, min_matches } => {
                    let matches = iocs.iter()
                        .filter(|ioc| ioc_types.contains(&ioc.ioc_type))
                        .count() as u32;
                    
                    if matches >= *min_matches {
                        total_confidence += rule.confidence_weight;
                    }
                }
                AttributionCondition::TechniquePattern { techniques, correlation } => {
                    let technique_matches = iocs.iter()
                        .flat_map(|ioc| &ioc.mitre_techniques)
                        .filter(|tech| techniques.contains(tech))
                        .count();
                    
                    if technique_matches as f32 / techniques.len() as f32 >= *correlation {
                        total_confidence += rule.confidence_weight;
                    }
                }
                _ => {} // Implement other condition types as needed
            }
            condition_count += 1;
        }

        if condition_count > 0 {
            total_confidence / condition_count as f32
        } else {
            0.0
        }
    }
}

impl SimilarityCalculator {
    pub fn new() -> Self {
        Self {
            technique_weights: HashMap::new(),
            temporal_weights: HashMap::new(),
            behavioral_weights: HashMap::new(),
        }
    }
}

impl ReputationCache {
    pub fn new() -> Self {
        Self {
            process_reputations: HashMap::new(),
            ip_reputations: HashMap::new(),
            hash_reputations: HashMap::new(),
            cache_ttl: Duration::from_secs(3600), // 1 hour
        }
    }
}
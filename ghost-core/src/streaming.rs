use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, Duration};
use tokio::sync::{broadcast, mpsc};
use serde::{Serialize, Deserialize};
use crate::{DetectionResult, ThreatLevel, ProcessInfo, ThreatContext, EvasionResult};

/// Real-time Event Streaming and Alerting System
/// Provides configurable alerting, correlation, and notification capabilities
pub struct EventStreamingSystem {
    event_publisher: EventPublisher,
    alert_manager: AlertManager,
    correlation_engine: CorrelationEngine,
    notification_system: NotificationSystem,
    event_buffer: Arc<Mutex<EventBuffer>>,
}

/// Event publishing system for real-time streaming
pub struct EventPublisher {
    channels: HashMap<EventChannel, broadcast::Sender<StreamingEvent>>,
    subscribers: HashMap<EventChannel, usize>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum EventChannel {
    DetectionEvents,
    ThreatIntelligence,
    EvasionDetection,
    SystemEvents,
    AlertNotifications,
    PerformanceMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingEvent {
    pub event_id: String,
    pub timestamp: SystemTime,
    pub event_type: EventType,
    pub source: EventSource,
    pub severity: EventSeverity,
    pub data: EventData,
    pub correlation_id: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    ProcessInjectionDetected,
    ThreatActorIdentified,
    EvasionTechniqueDetected,
    SystemAnomalyDetected,
    AlertTriggered,
    PerformanceThresholdExceeded,
    CorrelatedIncident,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSource {
    pub component: String,
    pub version: String,
    pub host: String,
    pub process_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventData {
    Detection(DetectionEventData),
    ThreatIntel(ThreatIntelEventData),
    Evasion(EvasionEventData),
    System(SystemEventData),
    Alert(AlertEventData),
    Performance(PerformanceEventData),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEventData {
    pub detection_result: DetectionResult,
    pub analysis_duration: Duration,
    pub confidence_threshold: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelEventData {
    pub threat_context: ThreatContext,
    pub ioc_matches: u32,
    pub attribution_confidence: f32,
    pub risk_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionEventData {
    pub evasion_result: EvasionResult,
    pub techniques_detected: u32,
    pub sophistication_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemEventData {
    pub metric_name: String,
    pub metric_value: f64,
    pub threshold: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEventData {
    pub alert: Alert,
    pub triggering_events: Vec<String>,
    pub context: AlertContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceEventData {
    pub metric_name: String,
    pub current_value: f64,
    pub baseline_value: f64,
    pub deviation_percentage: f64,
}

/// Alert management and configuration system
pub struct AlertManager {
    alert_rules: Vec<AlertRule>,
    active_alerts: HashMap<String, ActiveAlert>,
    alert_history: Vec<Alert>,
    escalation_policies: HashMap<String, EscalationPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub conditions: Vec<AlertCondition>,
    pub severity: EventSeverity,
    pub enabled: bool,
    pub cooldown_period: Duration,
    pub escalation_policy: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCondition {
    ThreatLevelEquals(ThreatLevel),
    ConfidenceThreshold(f32),
    EvasionSophisticationAbove(f32),
    ProcessCount(ProcessCountCondition),
    TimeWindow(TimeWindowCondition),
    CorrelationMatch(CorrelationCondition),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessCountCondition {
    pub count: u32,
    pub time_window: Duration,
    pub process_filter: Option<ProcessFilter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessFilter {
    pub name_pattern: Option<String>,
    pub path_pattern: Option<String>,
    pub minimum_confidence: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindowCondition {
    pub event_count: u32,
    pub time_window: Duration,
    pub event_type_filter: Option<EventType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationCondition {
    pub correlation_rule: String,
    pub minimum_confidence: f32,
    pub required_events: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub alert_id: String,
    pub rule_id: String,
    pub timestamp: SystemTime,
    pub severity: EventSeverity,
    pub title: String,
    pub description: String,
    pub triggering_events: Vec<String>,
    pub status: AlertStatus,
    pub acknowledged_by: Option<String>,
    pub resolved_by: Option<String>,
    pub resolution_time: Option<SystemTime>,
    pub context: AlertContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertStatus {
    Active,
    Acknowledged,
    Resolved,
    Suppressed,
    Escalated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertContext {
    pub affected_processes: Vec<ProcessInfo>,
    pub threat_actors: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub recommended_actions: Vec<String>,
    pub correlation_data: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveAlert {
    pub alert: Alert,
    pub escalation_level: u32,
    pub last_escalation: SystemTime,
    pub notification_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPolicy {
    pub policy_id: String,
    pub name: String,
    pub escalation_steps: Vec<EscalationStep>,
    pub max_escalation_level: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationStep {
    pub level: u32,
    pub delay: Duration,
    pub notification_channels: Vec<NotificationChannel>,
    pub actions: Vec<EscalationAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EscalationAction {
    SendNotification,
    CreateTicket,
    ExecuteScript(String),
    IsolateProcess(u32),
    BlockNetwork(String),
    SendToSIEM,
}

/// Advanced event correlation engine
pub struct CorrelationEngine {
    correlation_rules: Vec<CorrelationRule>,
    event_window: Duration,
    correlation_cache: HashMap<String, CorrelationState>,
    incident_tracker: IncidentTracker,
}

#[derive(Debug, Clone)]
pub struct CorrelationRule {
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub conditions: Vec<CorrelationRuleCondition>,
    pub time_window: Duration,
    pub minimum_events: u32,
    pub confidence_threshold: f32,
    pub incident_title: String,
    pub incident_severity: EventSeverity,
}

#[derive(Debug, Clone)]
pub enum CorrelationRuleCondition {
    EventSequence(Vec<EventType>),
    SameProcess(bool),
    ThreatActorMatch(bool),
    TechniqueChain(Vec<String>),
    GeographicalCorrelation(bool),
    TemporalPattern(TemporalPatternType),
}

#[derive(Debug, Clone)]
pub enum TemporalPatternType {
    BurstActivity,
    PeriodicActivity,
    EscalatingActivity,
    CoordinatedActivity,
}

#[derive(Debug, Clone)]
pub struct CorrelationState {
    pub rule_id: String,
    pub events: Vec<String>,
    pub first_event_time: SystemTime,
    pub last_event_time: SystemTime,
    pub confidence: f32,
}

#[derive(Debug, Clone)]
pub struct IncidentTracker {
    pub incidents: HashMap<String, CorrelatedIncident>,
    pub incident_counter: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedIncident {
    pub incident_id: String,
    pub timestamp: SystemTime,
    pub severity: EventSeverity,
    pub title: String,
    pub description: String,
    pub correlation_rule: String,
    pub confidence: f32,
    pub related_events: Vec<String>,
    pub affected_entities: Vec<String>,
    pub timeline: Vec<IncidentTimelineEntry>,
    pub status: IncidentStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentTimelineEntry {
    pub timestamp: SystemTime,
    pub event_type: EventType,
    pub description: String,
    pub severity: EventSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IncidentStatus {
    Open,
    InProgress,
    Resolved,
    Closed,
}

/// Multi-channel notification system
pub struct NotificationSystem {
    channels: HashMap<String, Box<dyn NotificationChannel>>,
    templates: HashMap<String, NotificationTemplate>,
    delivery_queue: mpsc::Sender<NotificationRequest>,
}

pub trait NotificationChannel: Send + Sync {
    fn send_notification(&self, notification: &Notification) -> Result<(), NotificationError>;
    fn validate_config(&self) -> Result<(), NotificationError>;
    fn get_channel_type(&self) -> String;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub notification_id: String,
    pub timestamp: SystemTime,
    pub severity: EventSeverity,
    pub title: String,
    pub message: String,
    pub channel: String,
    pub recipient: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct NotificationRequest {
    pub notification: Notification,
    pub retry_count: u32,
    pub max_retries: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationTemplate {
    pub template_id: String,
    pub name: String,
    pub subject_template: String,
    pub body_template: String,
    pub channel_type: String,
    pub variables: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum NotificationError {
    #[error("Channel not found: {0}")]
    ChannelNotFound(String),
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    #[error("Delivery failed: {0}")]
    DeliveryFailed(String),
    #[error("Template error: {0}")]
    TemplateError(String),
}

/// Email notification channel
pub struct EmailChannel {
    smtp_config: SmtpConfig,
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub use_tls: bool,
    pub from_address: String,
}

impl NotificationChannel for EmailChannel {
    fn send_notification(&self, notification: &Notification) -> Result<(), NotificationError> {
        // Email sending implementation would go here
        println!("Sending email notification: {}", notification.title);
        Ok(())
    }

    fn validate_config(&self) -> Result<(), NotificationError> {
        // Validate SMTP configuration
        Ok(())
    }

    fn get_channel_type(&self) -> String {
        "email".to_string()
    }
}

/// Slack notification channel
pub struct SlackChannel {
    webhook_url: String,
    default_channel: String,
}

impl NotificationChannel for SlackChannel {
    fn send_notification(&self, notification: &Notification) -> Result<(), NotificationError> {
        // Slack webhook implementation would go here
        println!("Sending Slack notification: {}", notification.title);
        Ok(())
    }

    fn validate_config(&self) -> Result<(), NotificationError> {
        // Validate Slack configuration
        Ok(())
    }

    fn get_channel_type(&self) -> String {
        "slack".to_string()
    }
}

/// Webhook notification channel
pub struct WebhookChannel {
    endpoint_url: String,
    headers: HashMap<String, String>,
    auth_token: Option<String>,
}

impl NotificationChannel for WebhookChannel {
    fn send_notification(&self, notification: &Notification) -> Result<(), NotificationError> {
        // HTTP webhook implementation would go here
        println!("Sending webhook notification: {}", notification.title);
        Ok(())
    }

    fn validate_config(&self) -> Result<(), NotificationError> {
        // Validate webhook configuration
        Ok(())
    }

    fn get_channel_type(&self) -> String {
        "webhook".to_string()
    }
}

/// SIEM integration channel
pub struct SiemChannel {
    siem_type: SiemType,
    endpoint: String,
    credentials: SiemCredentials,
}

#[derive(Debug, Clone)]
pub enum SiemType {
    Splunk,
    QRadar,
    ArcSight,
    Sentinel,
    ElasticSiem,
}

#[derive(Debug, Clone)]
pub struct SiemCredentials {
    pub api_key: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
}

impl NotificationChannel for SiemChannel {
    fn send_notification(&self, notification: &Notification) -> Result<(), NotificationError> {
        // SIEM integration implementation would go here
        println!("Sending SIEM notification: {}", notification.title);
        Ok(())
    }

    fn validate_config(&self) -> Result<(), NotificationError> {
        // Validate SIEM configuration
        Ok(())
    }

    fn get_channel_type(&self) -> String {
        format!("siem_{:?}", self.siem_type).to_lowercase()
    }
}

/// Event buffer for correlation and analysis
pub struct EventBuffer {
    events: Vec<StreamingEvent>,
    max_size: usize,
    retention_period: Duration,
}

impl EventStreamingSystem {
    pub fn new() -> Self {
        Self {
            event_publisher: EventPublisher::new(),
            alert_manager: AlertManager::new(),
            correlation_engine: CorrelationEngine::new(),
            notification_system: NotificationSystem::new(),
            event_buffer: Arc::new(Mutex::new(EventBuffer::new(10000, Duration::from_secs(3600)))),
        }
    }

    /// Publish a detection event
    pub async fn publish_detection_event(&mut self, detection: DetectionResult) -> Result<(), Box<dyn std::error::Error>> {
        let event = StreamingEvent {
            event_id: format!("det_{}", uuid::Uuid::new_v4()),
            timestamp: SystemTime::now(),
            event_type: EventType::ProcessInjectionDetected,
            source: EventSource {
                component: "ghost-detection-engine".to_string(),
                version: "1.0.0".to_string(),
                host: "localhost".to_string(), // Would be actual hostname
                process_id: std::process::id(),
            },
            severity: match detection.threat_level {
                ThreatLevel::Clean => EventSeverity::Info,
                ThreatLevel::Suspicious => EventSeverity::Medium,
                ThreatLevel::Malicious => EventSeverity::High,
            },
            data: EventData::Detection(DetectionEventData {
                detection_result: detection,
                analysis_duration: Duration::from_millis(100), // Would be actual duration
                confidence_threshold: 0.7,
            }),
            correlation_id: None,
            tags: vec!["process-injection".to_string(), "detection".to_string()],
        };

        self.publish_event(EventChannel::DetectionEvents, event).await
    }

    /// Publish an evasion detection event
    pub async fn publish_evasion_event(&mut self, evasion: EvasionResult, process: &ProcessInfo) -> Result<(), Box<dyn std::error::Error>> {
        let severity = if evasion.sophistication_score > 0.8 {
            EventSeverity::Critical
        } else if evasion.sophistication_score > 0.6 {
            EventSeverity::High
        } else {
            EventSeverity::Medium
        };

        let event = StreamingEvent {
            event_id: format!("eva_{}", uuid::Uuid::new_v4()),
            timestamp: SystemTime::now(),
            event_type: EventType::EvasionTechniqueDetected,
            source: EventSource {
                component: "ghost-evasion-detector".to_string(),
                version: "1.0.0".to_string(),
                host: "localhost".to_string(),
                process_id: std::process::id(),
            },
            severity,
            data: EventData::Evasion(EvasionEventData {
                evasion_result: evasion.clone(),
                techniques_detected: evasion.evasion_techniques.len() as u32,
                sophistication_level: format!("{:.1}%", evasion.sophistication_score * 100.0),
            }),
            correlation_id: None,
            tags: vec!["evasion".to_string(), "anti-analysis".to_string()],
        };

        self.publish_event(EventChannel::EvasionDetection, event).await
    }

    /// Publish a generic event to specified channel
    async fn publish_event(&mut self, channel: EventChannel, event: StreamingEvent) -> Result<(), Box<dyn std::error::Error>> {
        // Add to event buffer for correlation
        {
            let mut buffer = self.event_buffer.lock().unwrap();
            buffer.add_event(event.clone());
        }

        // Publish to subscribers
        self.event_publisher.publish(channel, event.clone()).await?;

        // Check for alert conditions
        self.alert_manager.evaluate_alerts(&event).await?;

        // Perform correlation analysis
        if let Some(incident) = self.correlation_engine.correlate_event(&event).await? {
            self.handle_correlated_incident(incident).await?;
        }

        Ok(())
    }

    async fn handle_correlated_incident(&mut self, incident: CorrelatedIncident) -> Result<(), Box<dyn std::error::Error>> {
        println!("Correlated incident detected: {}", incident.title);
        
        // Create alert for correlated incident
        let alert = Alert {
            alert_id: format!("inc_{}", uuid::Uuid::new_v4()),
            rule_id: incident.correlation_rule.clone(),
            timestamp: SystemTime::now(),
            severity: incident.severity.clone(),
            title: format!("Correlated Incident: {}", incident.title),
            description: incident.description.clone(),
            triggering_events: incident.related_events.clone(),
            status: AlertStatus::Active,
            acknowledged_by: None,
            resolved_by: None,
            resolution_time: None,
            context: AlertContext {
                affected_processes: Vec::new(),
                threat_actors: Vec::new(),
                mitre_techniques: Vec::new(),
                recommended_actions: vec![
                    "Investigate correlated events".to_string(),
                    "Review incident timeline".to_string(),
                    "Escalate to security team".to_string(),
                ],
                correlation_data: HashMap::new(),
            },
        };

        self.alert_manager.create_alert(alert).await?;
        Ok(())
    }

    /// Subscribe to event channel
    pub fn subscribe(&mut self, channel: EventChannel) -> broadcast::Receiver<StreamingEvent> {
        self.event_publisher.subscribe(channel)
    }
}

impl EventPublisher {
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
            subscribers: HashMap::new(),
        }
    }

    pub async fn publish(&mut self, channel: EventChannel, event: StreamingEvent) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(sender) = self.channels.get(&channel) {
            sender.send(event)?;
        }
        Ok(())
    }

    pub fn subscribe(&mut self, channel: EventChannel) -> broadcast::Receiver<StreamingEvent> {
        let sender = self.channels.entry(channel.clone())
            .or_insert_with(|| {
                let (tx, _) = broadcast::channel(1000);
                tx
            });
        
        let receiver = sender.subscribe();
        *self.subscribers.entry(channel).or_insert(0) += 1;
        receiver
    }
}

impl AlertManager {
    pub fn new() -> Self {
        Self {
            alert_rules: Vec::new(),
            active_alerts: HashMap::new(),
            alert_history: Vec::new(),
            escalation_policies: HashMap::new(),
        }
    }

    pub async fn evaluate_alerts(&mut self, event: &StreamingEvent) -> Result<(), Box<dyn std::error::Error>> {
        for rule in &self.alert_rules {
            if rule.enabled && self.evaluate_rule_conditions(rule, event) {
                self.trigger_alert(rule, event).await?;
            }
        }
        Ok(())
    }

    fn evaluate_rule_conditions(&self, rule: &AlertRule, event: &StreamingEvent) -> bool {
        // Evaluate alert rule conditions against the event
        // This is a simplified implementation
        rule.conditions.iter().any(|condition| {
            match condition {
                AlertCondition::ThreatLevelEquals(level) => {
                    if let EventData::Detection(data) = &event.data {
                        &data.detection_result.threat_level == level
                    } else {
                        false
                    }
                }
                AlertCondition::ConfidenceThreshold(threshold) => {
                    if let EventData::Detection(data) = &event.data {
                        data.detection_result.confidence >= *threshold
                    } else {
                        false
                    }
                }
                AlertCondition::EvasionSophisticationAbove(threshold) => {
                    if let EventData::Evasion(data) = &event.data {
                        data.evasion_result.sophistication_score >= *threshold
                    } else {
                        false
                    }
                }
                _ => false, // Implement other conditions as needed
            }
        })
    }

    async fn trigger_alert(&mut self, rule: &AlertRule, event: &StreamingEvent) -> Result<(), Box<dyn std::error::Error>> {
        let alert = Alert {
            alert_id: format!("alert_{}", uuid::Uuid::new_v4()),
            rule_id: rule.rule_id.clone(),
            timestamp: SystemTime::now(),
            severity: rule.severity.clone(),
            title: rule.name.clone(),
            description: rule.description.clone(),
            triggering_events: vec![event.event_id.clone()],
            status: AlertStatus::Active,
            acknowledged_by: None,
            resolved_by: None,
            resolution_time: None,
            context: AlertContext {
                affected_processes: Vec::new(),
                threat_actors: Vec::new(),
                mitre_techniques: Vec::new(),
                recommended_actions: Vec::new(),
                correlation_data: HashMap::new(),
            },
        };

        self.create_alert(alert).await
    }

    pub async fn create_alert(&mut self, alert: Alert) -> Result<(), Box<dyn std::error::Error>> {
        println!("Alert created: {} - {}", alert.alert_id, alert.title);
        
        let active_alert = ActiveAlert {
            alert: alert.clone(),
            escalation_level: 0,
            last_escalation: SystemTime::now(),
            notification_count: 0,
        };

        self.active_alerts.insert(alert.alert_id.clone(), active_alert);
        self.alert_history.push(alert);
        
        Ok(())
    }
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            correlation_rules: Vec::new(),
            event_window: Duration::from_secs(300), // 5 minutes
            correlation_cache: HashMap::new(),
            incident_tracker: IncidentTracker {
                incidents: HashMap::new(),
                incident_counter: 0,
            },
        }
    }

    pub async fn correlate_event(&mut self, event: &StreamingEvent) -> Result<Option<CorrelatedIncident>, Box<dyn std::error::Error>> {
        // Simplified correlation logic
        for rule in &self.correlation_rules {
            if let Some(incident) = self.evaluate_correlation_rule(rule, event) {
                self.incident_tracker.incident_counter += 1;
                let incident_id = format!("incident_{}", self.incident_tracker.incident_counter);
                
                let correlated_incident = CorrelatedIncident {
                    incident_id: incident_id.clone(),
                    timestamp: SystemTime::now(),
                    severity: rule.incident_severity.clone(),
                    title: rule.incident_title.clone(),
                    description: format!("Correlated incident based on rule: {}", rule.name),
                    correlation_rule: rule.rule_id.clone(),
                    confidence: rule.confidence_threshold,
                    related_events: vec![event.event_id.clone()],
                    affected_entities: Vec::new(),
                    timeline: Vec::new(),
                    status: IncidentStatus::Open,
                };

                self.incident_tracker.incidents.insert(incident_id, correlated_incident.clone());
                return Ok(Some(correlated_incident));
            }
        }
        
        Ok(None)
    }

    fn evaluate_correlation_rule(&self, rule: &CorrelationRule, event: &StreamingEvent) -> Option<()> {
        // Simplified correlation rule evaluation
        // In a real implementation, this would be much more sophisticated
        Some(())
    }
}

impl NotificationSystem {
    pub fn new() -> Self {
        let (tx, _) = mpsc::channel(1000);
        Self {
            channels: HashMap::new(),
            templates: HashMap::new(),
            delivery_queue: tx,
        }
    }

    pub fn add_email_channel(&mut self, name: String, config: SmtpConfig) {
        let channel = EmailChannel { smtp_config: config };
        self.channels.insert(name, Box::new(channel));
    }

    pub fn add_slack_channel(&mut self, name: String, webhook_url: String, default_channel: String) {
        let channel = SlackChannel { webhook_url, default_channel };
        self.channels.insert(name, Box::new(channel));
    }

    pub fn add_webhook_channel(&mut self, name: String, endpoint_url: String, headers: HashMap<String, String>) {
        let channel = WebhookChannel { 
            endpoint_url, 
            headers, 
            auth_token: None 
        };
        self.channels.insert(name, Box::new(channel));
    }
}

impl EventBuffer {
    pub fn new(max_size: usize, retention_period: Duration) -> Self {
        Self {
            events: Vec::new(),
            max_size,
            retention_period,
        }
    }

    pub fn add_event(&mut self, event: StreamingEvent) {
        self.events.push(event);
        
        // Remove old events
        let cutoff_time = SystemTime::now() - self.retention_period;
        self.events.retain(|e| e.timestamp >= cutoff_time);
        
        // Limit buffer size
        if self.events.len() > self.max_size {
            self.events.drain(0..self.events.len() - self.max_size);
        }
    }

    pub fn get_events_in_window(&self, window: Duration) -> Vec<&StreamingEvent> {
        let cutoff_time = SystemTime::now() - window;
        self.events.iter()
            .filter(|e| e.timestamp >= cutoff_time)
            .collect()
    }
}
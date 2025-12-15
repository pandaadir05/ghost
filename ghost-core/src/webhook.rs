//! Webhook notifications for alert delivery.
//!
//! Supports Slack, Discord, and generic HTTP POST endpoints.

use crate::{DetectionResult, ThreatLevel};
use serde::Serialize;
use std::time::Duration;

/// Webhook configuration
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    /// Webhook URL
    pub url: String,
    /// Webhook type (auto-detected from URL if not specified)
    pub webhook_type: WebhookType,
    /// Timeout for HTTP requests
    pub timeout: Duration,
    /// Minimum threat level to trigger alerts
    pub min_level: ThreatLevel,
}

/// Type of webhook endpoint
#[derive(Debug, Clone, PartialEq)]
pub enum WebhookType {
    Slack,
    Discord,
    Generic,
}

impl WebhookConfig {
    /// Creates a new webhook config with explicit type
    pub fn new(url: String, webhook_type: WebhookType) -> Self {
        Self {
            url,
            webhook_type,
            timeout: Duration::from_secs(10),
            min_level: ThreatLevel::Suspicious,
        }
    }

    /// Creates a new webhook config, auto-detecting the type from URL
    pub fn from_url(url: &str) -> Self {
        let webhook_type = if url.contains("hooks.slack.com") {
            WebhookType::Slack
        } else if url.contains("discord.com/api/webhooks") {
            WebhookType::Discord
        } else {
            WebhookType::Generic
        };

        Self {
            url: url.to_string(),
            webhook_type,
            timeout: Duration::from_secs(10),
            min_level: ThreatLevel::Suspicious,
        }
    }

    /// Sets minimum threat level for alerts
    pub fn with_min_level(mut self, level: ThreatLevel) -> Self {
        self.min_level = level;
        self
    }
}

/// Slack message format
#[derive(Debug, Serialize)]
struct SlackMessage {
    text: String,
    attachments: Vec<SlackAttachment>,
}

#[derive(Debug, Serialize)]
struct SlackAttachment {
    color: String,
    title: String,
    text: String,
    fields: Vec<SlackField>,
    footer: String,
    ts: i64,
}

#[derive(Debug, Serialize)]
struct SlackField {
    title: String,
    value: String,
    short: bool,
}

/// Discord message format
#[derive(Debug, Serialize)]
struct DiscordMessage {
    content: String,
    embeds: Vec<DiscordEmbed>,
}

#[derive(Debug, Serialize)]
struct DiscordEmbed {
    title: String,
    description: String,
    color: u32,
    fields: Vec<DiscordField>,
    footer: DiscordFooter,
    timestamp: String,
}

#[derive(Debug, Serialize)]
struct DiscordField {
    name: String,
    value: String,
    inline: bool,
}

#[derive(Debug, Serialize)]
struct DiscordFooter {
    text: String,
}

/// Generic webhook payload
#[derive(Debug, Serialize)]
pub struct AlertPayload {
    pub event: String,
    pub timestamp: String,
    pub hostname: String,
    pub process_name: String,
    pub pid: u32,
    pub threat_level: String,
    pub confidence: f32,
    pub indicators: Vec<String>,
}

/// Webhook notifier for sending alerts
pub struct WebhookNotifier {
    config: WebhookConfig,
    client: reqwest::Client,
}

impl WebhookNotifier {
    /// Creates a new webhook notifier
    pub fn new(config: WebhookConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self { config, client }
    }

    /// Sends alert for a single detection
    pub async fn send_detection(
        &self,
        detection: &DetectionResult,
        hostname: &str,
    ) -> Result<(), WebhookError> {
        // Check if meets threshold
        if !self.meets_threshold(&detection.threat_level) {
            return Ok(());
        }

        let payload = match self.config.webhook_type {
            WebhookType::Slack => self.build_slack_payload(detection, hostname),
            WebhookType::Discord => self.build_discord_payload(detection, hostname),
            WebhookType::Generic => self.build_generic_payload(detection, hostname),
        };

        let response = self
            .client
            .post(&self.config.url)
            .header("Content-Type", "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|e| WebhookError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(WebhookError::ResponseError(status, body));
        }

        Ok(())
    }

    /// Sends alerts for multiple detections
    pub async fn send_alerts(
        &self,
        detections: &[DetectionResult],
        hostname: &str,
    ) -> Result<(), WebhookError> {
        for detection in detections {
            self.send_detection(detection, hostname).await?;
        }
        Ok(())
    }

    fn meets_threshold(&self, level: &ThreatLevel) -> bool {
        matches!(
            (&self.config.min_level, level),
            (ThreatLevel::Clean, _)
                | (
                    ThreatLevel::Suspicious,
                    ThreatLevel::Suspicious | ThreatLevel::Malicious
                )
                | (ThreatLevel::Malicious, ThreatLevel::Malicious)
        )
    }

    fn build_slack_payload(&self, detection: &DetectionResult, hostname: &str) -> String {
        let color = match detection.threat_level {
            ThreatLevel::Malicious => "#ff0000",
            ThreatLevel::Suspicious => "#ffaa00",
            ThreatLevel::Clean => "#00ff00",
        };

        let indicators_text = detection
            .indicators
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");

        let attachment = SlackAttachment {
            color: color.to_string(),
            title: format!(
                "{} (PID: {})",
                detection.process.name, detection.process.pid
            ),
            text: indicators_text,
            fields: vec![
                SlackField {
                    title: "Threat Level".to_string(),
                    value: format!("{:?}", detection.threat_level),
                    short: true,
                },
                SlackField {
                    title: "Confidence".to_string(),
                    value: format!("{:.0}%", detection.confidence * 100.0),
                    short: true,
                },
            ],
            footer: format!("Ghost • {}", hostname),
            ts: chrono::Utc::now().timestamp(),
        };

        let message = SlackMessage {
            text: format!("Ghost detected suspicious activity on *{}*", hostname),
            attachments: vec![attachment],
        };

        serde_json::to_string(&message).unwrap_or_default()
    }

    fn build_discord_payload(&self, detection: &DetectionResult, hostname: &str) -> String {
        let color = match detection.threat_level {
            ThreatLevel::Malicious => 0xff0000,
            ThreatLevel::Suspicious => 0xffaa00,
            ThreatLevel::Clean => 0x00ff00,
        };

        let indicators_text = detection
            .indicators
            .iter()
            .take(3)
            .map(|i| format!("• {}", i))
            .collect::<Vec<_>>()
            .join("\n");

        let embed = DiscordEmbed {
            title: format!(
                "{} (PID: {})",
                detection.process.name, detection.process.pid
            ),
            description: indicators_text,
            color,
            fields: vec![
                DiscordField {
                    name: "Threat Level".to_string(),
                    value: format!("{:?}", detection.threat_level),
                    inline: true,
                },
                DiscordField {
                    name: "Confidence".to_string(),
                    value: format!("{:.0}%", detection.confidence * 100.0),
                    inline: true,
                },
            ],
            footer: DiscordFooter {
                text: format!("Ghost • {}", hostname),
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let message = DiscordMessage {
            content: format!(
                "**Ghost Alert**: Suspicious process detected on **{}**",
                hostname
            ),
            embeds: vec![embed],
        };

        serde_json::to_string(&message).unwrap_or_default()
    }

    fn build_generic_payload(&self, detection: &DetectionResult, hostname: &str) -> String {
        let payload = AlertPayload {
            event: "ghost.detection".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            hostname: hostname.to_string(),
            process_name: detection.process.name.clone(),
            pid: detection.process.pid,
            threat_level: format!("{:?}", detection.threat_level),
            confidence: detection.confidence,
            indicators: detection.indicators.clone(),
        };

        serde_json::to_string(&payload).unwrap_or_default()
    }
}

/// Webhook errors
#[derive(Debug)]
pub enum WebhookError {
    RequestFailed(String),
    ResponseError(u16, String),
}

impl std::fmt::Display for WebhookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebhookError::RequestFailed(e) => write!(f, "Request failed: {}", e),
            WebhookError::ResponseError(code, body) => {
                write!(f, "HTTP {}: {}", code, body)
            }
        }
    }
}

impl std::error::Error for WebhookError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_type_detection() {
        let slack = WebhookConfig::from_url("https://hooks.slack.com/services/xxx");
        assert_eq!(slack.webhook_type, WebhookType::Slack);

        let discord = WebhookConfig::from_url("https://discord.com/api/webhooks/xxx");
        assert_eq!(discord.webhook_type, WebhookType::Discord);

        let generic = WebhookConfig::from_url("https://example.com/webhook");
        assert_eq!(generic.webhook_type, WebhookType::Generic);
    }

    #[test]
    fn test_threshold_check() {
        let config =
            WebhookConfig::from_url("https://example.com").with_min_level(ThreatLevel::Suspicious);
        let notifier = WebhookNotifier::new(config);

        assert!(!notifier.meets_threshold(&ThreatLevel::Clean));
        assert!(notifier.meets_threshold(&ThreatLevel::Suspicious));
        assert!(notifier.meets_threshold(&ThreatLevel::Malicious));
    }
}

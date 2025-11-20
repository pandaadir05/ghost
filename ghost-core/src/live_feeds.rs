use crate::GhostError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveThreatFeeds {
    feeds: Vec<ThreatFeed>,
    ioc_cache: HashMap<String, CachedIOC>,
    update_interval: Duration,
    last_update: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeed {
    pub name: String,
    pub url: String,
    pub feed_type: FeedType,
    pub api_key: Option<String>,
    pub enabled: bool,
    pub last_updated: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeedType {
    VirusTotal,
    MISP,
    AlienVault,
    AbuseIPDB,
    MalwareBazaar,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedIOC {
    value: String,
    ioc_type: String,
    threat_level: u8,
    source: String,
    timestamp: SystemTime,
    ttl: Duration,
}

impl LiveThreatFeeds {
    pub fn new() -> Result<Self, GhostError> {
        let feeds = vec![
            ThreatFeed {
                name: "VirusTotal".to_string(),
                url: "https://www.virustotal.com/api/v3".to_string(),
                feed_type: FeedType::VirusTotal,
                api_key: None,
                enabled: true,
                last_updated: SystemTime::now(),
            },
            ThreatFeed {
                name: "AlienVault OTX".to_string(),
                url: "https://otx.alienvault.com/api/v1".to_string(),
                feed_type: FeedType::AlienVault,
                api_key: None,
                enabled: true,
                last_updated: SystemTime::now(),
            },
        ];

        Ok(LiveThreatFeeds {
            feeds,
            ioc_cache: HashMap::new(),
            update_interval: Duration::from_secs(1800), // 30 minutes
            last_update: SystemTime::now(),
        })
    }

    pub async fn update_feeds(&mut self) -> Result<usize, GhostError> {
        let mut updated_count = 0;

        for feed in &mut self.feeds {
            if !feed.enabled {
                continue;
            }

            match self.fetch_feed_data(feed).await {
                Ok(iocs) => {
                    log::info!("Updated {} with {} IOCs", feed.name, iocs.len());

                    // Add IOCs to cache
                    for ioc in iocs {
                        self.ioc_cache.insert(ioc.value.clone(), ioc);
                    }

                    feed.last_updated = SystemTime::now();
                    updated_count += 1;
                }
                Err(e) => {
                    log::warn!("Failed to update feed {}: {:?}", feed.name, e);
                }
            }
        }

        self.last_update = SystemTime::now();
        Ok(updated_count)
    }

    async fn fetch_feed_data(&self, feed: &ThreatFeed) -> Result<Vec<CachedIOC>, GhostError> {
        match feed.feed_type {
            FeedType::AbuseIPDB => self.fetch_abuseipdb(feed).await,
            FeedType::MalwareBazaar => self.fetch_malwarebazaar(feed).await,
            FeedType::AlienVault => self.fetch_alienvault(feed).await,
            _ => {
                log::debug!("Feed type {:?} not yet implemented", feed.feed_type);
                Ok(Vec::new())
            }
        }
    }

    async fn fetch_abuseipdb(&self, feed: &ThreatFeed) -> Result<Vec<CachedIOC>, GhostError> {
        let api_key = feed.api_key.as_ref().ok_or_else(|| {
            GhostError::ConfigurationError("AbuseIPDB requires API key".to_string())
        })?;

        let client = reqwest::Client::new();
        let url = format!("{}/blacklist", feed.url);

        let response = client
            .get(&url)
            .header("Key", api_key)
            .header("Accept", "application/json")
            .query(&[("confidenceMinimum", "90")])
            .send()
            .await
            .map_err(|e| GhostError::NetworkError(format!("AbuseIPDB request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(GhostError::NetworkError(format!(
                "AbuseIPDB API returned status: {}",
                response.status()
            )));
        }

        let data: serde_json::Value = response.json().await.map_err(|e| {
            GhostError::ParseError(format!("Failed to parse AbuseIPDB response: {}", e))
        })?;

        let mut iocs = Vec::new();

        if let Some(blacklist) = data.get("data").and_then(|d| d.as_array()) {
            for entry in blacklist {
                if let Some(ip) = entry.get("ipAddress").and_then(|v| v.as_str()) {
                    let confidence = entry
                        .get("abuseConfidenceScore")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);

                    let threat_level = if confidence >= 90 {
                        5
                    } else if confidence >= 75 {
                        4
                    } else if confidence >= 50 {
                        3
                    } else {
                        2
                    };

                    iocs.push(CachedIOC {
                        value: ip.to_string(),
                        ioc_type: "ip".to_string(),
                        threat_level,
                        source: "AbuseIPDB".to_string(),
                        timestamp: SystemTime::now(),
                        ttl: Duration::from_secs(3600), // 1 hour
                    });
                }
            }
        }

        Ok(iocs)
    }

    async fn fetch_malwarebazaar(&self, feed: &ThreatFeed) -> Result<Vec<CachedIOC>, GhostError> {
        let client = reqwest::Client::new();
        let url = format!("{}/recent", feed.url);

        let response = client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({ "query": "get_recent", "selector": "100" }))
            .send()
            .await
            .map_err(|e| {
                GhostError::NetworkError(format!("MalwareBazaar request failed: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(GhostError::NetworkError(format!(
                "MalwareBazaar API returned status: {}",
                response.status()
            )));
        }

        let data: serde_json::Value = response.json().await.map_err(|e| {
            GhostError::ParseError(format!("Failed to parse MalwareBazaar response: {}", e))
        })?;

        let mut iocs = Vec::new();

        if let Some(samples) = data.get("data").and_then(|d| d.as_array()) {
            for sample in samples.iter().take(100) {
                // Get SHA256 hash
                if let Some(sha256) = sample.get("sha256_hash").and_then(|v| v.as_str()) {
                    iocs.push(CachedIOC {
                        value: sha256.to_string(),
                        ioc_type: "sha256".to_string(),
                        threat_level: 5, // Malware samples are high threat
                        source: "MalwareBazaar".to_string(),
                        timestamp: SystemTime::now(),
                        ttl: Duration::from_secs(86400), // 24 hours
                    });
                }

                // Get file signatures/names
                if let Some(file_name) = sample.get("file_name").and_then(|v| v.as_str()) {
                    iocs.push(CachedIOC {
                        value: file_name.to_string(),
                        ioc_type: "filename".to_string(),
                        threat_level: 4,
                        source: "MalwareBazaar".to_string(),
                        timestamp: SystemTime::now(),
                        ttl: Duration::from_secs(86400),
                    });
                }
            }
        }

        Ok(iocs)
    }

    async fn fetch_alienvault(&self, feed: &ThreatFeed) -> Result<Vec<CachedIOC>, GhostError> {
        let api_key = feed.api_key.as_ref().ok_or_else(|| {
            GhostError::ConfigurationError("AlienVault OTX requires API key".to_string())
        })?;

        let client = reqwest::Client::new();
        let url = format!("{}/pulses/subscribed", feed.url);

        let response = client
            .get(&url)
            .header("X-OTX-API-KEY", api_key)
            .header("Content-Type", "application/json")
            .query(&[("limit", "50")])
            .send()
            .await
            .map_err(|e| GhostError::NetworkError(format!("AlienVault request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(GhostError::NetworkError(format!(
                "AlienVault API returned status: {}",
                response.status()
            )));
        }

        let data: serde_json::Value = response.json().await.map_err(|e| {
            GhostError::ParseError(format!("Failed to parse AlienVault response: {}", e))
        })?;

        let mut iocs = Vec::new();

        if let Some(results) = data.get("results").and_then(|r| r.as_array()) {
            for pulse in results {
                if let Some(indicators) = pulse.get("indicators").and_then(|i| i.as_array()) {
                    for indicator in indicators {
                        if let (Some(value), Some(ioc_type)) = (
                            indicator.get("indicator").and_then(|v| v.as_str()),
                            indicator.get("type").and_then(|t| t.as_str()),
                        ) {
                            // Map OTX threat level to our scale
                            let threat_level = indicator
                                .get("expiration")
                                .and_then(|_| Some(4))
                                .unwrap_or(3);

                            iocs.push(CachedIOC {
                                value: value.to_string(),
                                ioc_type: ioc_type.to_lowercase(),
                                threat_level,
                                source: "AlienVault OTX".to_string(),
                                timestamp: SystemTime::now(),
                                ttl: Duration::from_secs(7200), // 2 hours
                            });
                        }
                    }
                }
            }
        }

        Ok(iocs)
    }

    pub fn check_ioc(&self, indicator: &str) -> Option<u8> {
        if let Some(cached) = self.ioc_cache.get(indicator) {
            if cached.timestamp.elapsed().unwrap_or_default() < cached.ttl {
                return Some(cached.threat_level);
            }
        }
        None
    }

    pub fn get_feed_status(&self) -> Vec<&ThreatFeed> {
        self.feeds.iter().collect()
    }
}

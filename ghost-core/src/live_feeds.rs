use crate::GhostError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, Duration};

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

            // Simulate feed update
            feed.last_updated = SystemTime::now();
            updated_count += 1;
        }

        self.last_update = SystemTime::now();
        Ok(updated_count)
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
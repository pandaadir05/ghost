use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    pub shellcode_detection: bool,
    pub hollowing_detection: bool,
    pub hook_detection: bool,
    pub confidence_threshold: f32,
    pub skip_system_processes: bool,
    pub max_memory_scan_size: usize,
    pub thread_analysis_enabled: bool,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            shellcode_detection: true,
            hollowing_detection: true,
            hook_detection: true,
            confidence_threshold: 0.7,
            skip_system_processes: true,
            max_memory_scan_size: 1024 * 1024 * 100, // 100MB
            thread_analysis_enabled: true,
        }
    }
}

impl DetectionConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: DetectionConfig = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn load_or_default<P: AsRef<Path>>(path: P) -> Self {
        Self::load_from_file(path).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessFilter {
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>,
    pub system_processes: Vec<String>,
}

impl Default for ProcessFilter {
    fn default() -> Self {
        Self {
            whitelist: vec![],
            blacklist: vec![],
            system_processes: vec![
                "csrss.exe".to_string(),
                "wininit.exe".to_string(),
                "winlogon.exe".to_string(),
                "dwm.exe".to_string(),
                "explorer.exe".to_string(),
            ],
        }
    }
}

impl ProcessFilter {
    pub fn should_scan(&self, process_name: &str) -> bool {
        // If whitelist is not empty, only scan whitelisted processes
        if !self.whitelist.is_empty() {
            return self.whitelist.iter().any(|name| process_name.contains(name));
        }

        // Skip blacklisted processes
        if self.blacklist.iter().any(|name| process_name.contains(name)) {
            return false;
        }

        // Skip system processes if configured
        if self.system_processes.iter().any(|name| process_name == name) {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DetectionConfig::default();
        assert!(config.shellcode_detection);
        assert_eq!(config.confidence_threshold, 0.7);
    }

    #[test]
    fn test_process_filter() {
        let filter = ProcessFilter::default();
        assert!(!filter.should_scan("csrss.exe"));
        assert!(filter.should_scan("notepad.exe"));
    }

    #[test]
    fn test_whitelist_filter() {
        let filter = ProcessFilter {
            whitelist: vec!["notepad.exe".to_string()],
            blacklist: vec![],
            system_processes: vec![],
        };
        assert!(filter.should_scan("notepad.exe"));
        assert!(!filter.should_scan("malware.exe"));
    }
}
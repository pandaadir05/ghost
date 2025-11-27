//! Python ML Bridge for Neural Memory Analysis
//!
//! This module provides integration with Python ML models via PyO3 or subprocess calls.

use crate::{GhostError, MemoryRegion};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::{Command, Stdio};


/// Result from ML model analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLAnalysisResult {
    pub threat_probability: f32,
    pub detected_patterns: Vec<DetectedPattern>,
    pub evasion_techniques: Vec<DetectedEvasion>,
    pub polymorphic_indicators: Vec<PolymorphicIndicator>,
    pub memory_anomalies: Vec<MemoryAnomaly>,
    pub confidence_score: f32,
    pub model_predictions: Vec<ModelPrediction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedPattern {
    pub pattern_name: String,
    pub pattern_type: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedEvasion {
    pub evasion_name: String,
    pub technique_category: String,
    pub sophistication_level: String,
    pub detection_confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolymorphicIndicator {
    pub mutation_family: String,
    pub mutation_generation: u32,
    pub mutation_confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAnomaly {
    pub anomaly_name: String,
    pub severity_score: f32,
    pub anomaly_description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPrediction {
    pub model_id: String,
    pub prediction: f32,
    pub confidence: f32,
    pub inference_time_ms: f32,
}

/// ML Bridge for calling Python ML models
#[derive(Debug)]
pub struct MLBridge {
    model_dir: PathBuf,
    use_python: bool,
    python_path: Option<PathBuf>,
}

impl MLBridge {
    /// Create a new ML bridge
    pub fn new(model_dir: Option<PathBuf>) -> Self {
        let model_dir = model_dir.unwrap_or_else(|| PathBuf::from("models"));

        // Try to find Python
        let python_path = find_python();
        let use_python = python_path.is_some();

        MLBridge {
            model_dir,
            use_python,
            python_path,
        }
    }
    
    /// Analyze memory regions using ML models
    pub async fn analyze_memory_regions(
        &self,
        memory_regions: &[MemoryRegion],
        memory_content: Option<&[Vec<u8>]>,
    ) -> Result<MLAnalysisResult, GhostError> {
        if self.use_python {
            self.analyze_with_subprocess(memory_regions, memory_content).await
        } else {
            // Fallback: return empty results
            log::warn!("Python not available, returning empty ML analysis");
            Ok(MLAnalysisResult {
                threat_probability: 0.0,
                detected_patterns: Vec::new(),
                evasion_techniques: Vec::new(),
                polymorphic_indicators: Vec::new(),
                memory_anomalies: Vec::new(),
                confidence_score: 0.0,
                model_predictions: Vec::new(),
            })
        }
    }

    async fn analyze_with_subprocess(
        &self,
        memory_regions: &[MemoryRegion],
        _memory_content: Option<&[Vec<u8>]>,
    ) -> Result<MLAnalysisResult, GhostError> {
        let python = self.python_path.as_ref()
            .ok_or_else(|| GhostError::Configuration {
                message: "Python interpreter not found for ML analysis".to_string()
            })?;

        let script = format!(
            r#"
import sys
import json
sys.path.insert(0, '.')
try:
    from ghost_ml.bridge.rust_bridge import GhostMLBridge
    bridge = GhostMLBridge('{}')
    regions_json = sys.stdin.read()
    result = bridge.analyze_memory_regions(regions_json)
    print(result)
except Exception as e:
    import traceback
    error_details = {{"error": str(e), "traceback": traceback.format_exc(), "threat_probability": 0.0, "detected_patterns": [], "evasion_techniques": [], "polymorphic_indicators": [], "memory_anomalies": [], "confidence_score": 0.0, "model_predictions": []}}
    print(json.dumps(error_details), file=sys.stderr)
    print(json.dumps({{"error": str(e), "threat_probability": 0.0, "detected_patterns": [], "evasion_techniques": [], "polymorphic_indicators": [], "memory_anomalies": [], "confidence_score": 0.0, "model_predictions": []}}))
    sys.exit(0)
"#,
            self.model_dir.to_string_lossy()
        );
        
        // Serialize memory regions
        let regions_json = serde_json::to_string(memory_regions)?;
        
        // Execute Python script in blocking task
        let python_path = python.clone();
        let script_clone = script.clone();
        let regions_json_clone = regions_json.clone();
        let output = tokio::task::spawn_blocking(move || {
            use std::io::Write;
            let mut child = Command::new(&python_path)
                .arg("-c")
                .arg(&script_clone)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            
            // Write input
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(regions_json_clone.as_bytes())?;
            }

            let output = child.wait_with_output()?;
            Ok::<_, std::io::Error>(output)
        })
        .await
        .map_err(|e| GhostError::Configuration {
            message: format!("Failed to execute ML analysis task: {}", e)
        })?
        .map_err(|e| GhostError::Configuration {
            message: format!("Python ML bridge execution failed: {}", e)
        })?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::warn!("Python ML script failed: {}", stderr);
        }
        
        let stdout = String::from_utf8(output.stdout)
            .map_err(|e| GhostError::Serialization {
                message: format!("Invalid UTF-8 in Python output: {}", e)
            })?;
        
        // Parse result
        let analysis: MLAnalysisResult = serde_json::from_str(&stdout.trim())
            .map_err(|e| GhostError::Serialization {
                message: format!("Failed to deserialize ML analysis result: {} (output: {})", e, stdout)
            })?;
        
        Ok(analysis)
    }
}

/// Find Python executable
fn find_python() -> Option<PathBuf> {
    // Try common Python names
    let candidates = ["python3", "python", "py"];
    
    for candidate in candidates.iter() {
        if let Ok(output) = Command::new(candidate).arg("--version").output() {
            if output.status.success() {
                return Some(PathBuf::from(candidate));
            }
        }
    }
    
    None
}

impl Default for MLBridge {
    fn default() -> Self {
        Self::new(None)
    }
}


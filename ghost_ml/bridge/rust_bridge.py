"""
Rust-Python Bridge for Ghost ML

This module provides the interface for Rust code to call Python ML models.
"""

import json
import logging
import time
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
import torch

from ..models import ShellcodeCNN, PolymorphicTransformer, EvasionGNN, load_model, save_model
from ..features import MemoryFeatureExtractor

logger = logging.getLogger(__name__)

class GhostMLBridge:
    """
    Bridge class for Rust-Python ML integration.
    
    This class loads ML models and provides inference methods that can be
    called from Rust via PyO3.
    """
    
    def __init__(self, model_dir: str = "models"):
        """
        Initialize the ML bridge.
        
        Args:
            model_dir: Directory containing trained model files
        """
        self.model_dir = model_dir
        self.feature_extractor = MemoryFeatureExtractor()
        
        # Model paths
        self.cnn_path = f"{model_dir}/shellcode_cnn_v4.pth"
        self.transformer_path = f"{model_dir}/polymorphic_transformer.pth"
        self.gnn_path = f"{model_dir}/evasion_gnn.pth"
        
        # Loaded models
        self.cnn_model: Optional[ShellcodeCNN] = None
        self.transformer_model: Optional[PolymorphicTransformer] = None
        self.gnn_model: Optional[EvasionGNN] = None
        
        # Load models if available
        self._load_models()
    
    def _load_models(self):
        """Load ML models from disk."""
        try:
            import os
            if os.path.exists(self.cnn_path):
                self.cnn_model = load_model(self.cnn_path, "cnn")
                logger.info(f"Loaded CNN model from {self.cnn_path}")
        except Exception as e:
            logger.warning(f"Failed to load CNN model: {e}")
        
        try:
            import os
            if os.path.exists(self.transformer_path):
                self.transformer_model = load_model(self.transformer_path, "transformer")
                logger.info(f"Loaded Transformer model from {self.transformer_path}")
        except Exception as e:
            logger.warning(f"Failed to load Transformer model: {e}")
        
        try:
            import os
            if os.path.exists(self.gnn_path):
                self.gnn_model = load_model(self.gnn_path, "gnn")
                logger.info(f"Loaded GNN model from {self.gnn_path}")
        except Exception as e:
            logger.warning(f"Failed to load GNN model: {e}")
    
    def analyze_memory_regions(
        self,
        memory_regions_json: str,
        memory_content: Optional[List[bytes]] = None,
    ) -> str:
        """
        Analyze memory regions using all ML models.
        
        Args:
            memory_regions_json: JSON string of memory regions
            memory_content: Optional list of byte content for each region
            
        Returns:
            JSON string with analysis results
        """
        try:
            # Parse input
            memory_regions = json.loads(memory_regions_json)
            
            # Extract features
            features = self.feature_extractor.extract_features(memory_regions, memory_content)
            
            # Run inference with all models
            results = {
                "threat_probability": 0.0,
                "detected_patterns": [],
                "evasion_techniques": [],
                "polymorphic_indicators": [],
                "memory_anomalies": [],
                "confidence_score": 0.0,
                "model_predictions": [],
            }
            
            # CNN for shellcode detection
            if self.cnn_model and memory_content:
                cnn_result = self._run_cnn_inference(memory_content)
                results["model_predictions"].append(cnn_result)
                
                if cnn_result["prediction"] > 0.5:
                    results["detected_patterns"].append({
                        "pattern_name": "Shellcode",
                        "pattern_type": "Shellcode",
                        "confidence": float(cnn_result["confidence"]),
                    })
                    results["threat_probability"] = max(
                        results["threat_probability"],
                        float(cnn_result["prediction"]),
                    )
            
            # Transformer for polymorphic analysis
            if self.transformer_model and memory_content:
                transformer_result = self._run_transformer_inference(memory_content)
                results["model_predictions"].append(transformer_result)
                
                if transformer_result["polymorphic_detected"]:
                    results["polymorphic_indicators"].append({
                        "mutation_family": transformer_result["mutation_family"],
                        "mutation_generation": int(transformer_result["mutation_generation"]),
                        "mutation_confidence": float(transformer_result["confidence"]),
                    })
            
            # GNN for evasion detection
            if self.gnn_model:
                gnn_result = self._run_gnn_inference(memory_regions)
                results["model_predictions"].append(gnn_result)
                
                if gnn_result["evasion_detected"]:
                    evasion_category_map = {
                        0: "AntiDebugging",
                        1: "AntiVirtualization",
                        2: "CodeObfuscation",
                        3: "BehavioralEvasion",
                    }
                    sophistication_map = {
                        0: "Basic",
                        1: "Intermediate",
                        2: "Advanced",
                        3: "Expert",
                    }
                    
                    results["evasion_techniques"].append({
                        "evasion_name": evasion_category_map.get(gnn_result["evasion_category"], "Unknown"),
                        "technique_category": evasion_category_map.get(gnn_result["evasion_category"], "Unknown"),
                        "sophistication_level": sophistication_map.get(gnn_result["sophistication_level"], "Basic"),
                        "detection_confidence": float(gnn_result["confidence"]),
                    })
            
            # Calculate overall confidence
            if results["model_predictions"]:
                confidences = [p["confidence"] for p in results["model_predictions"]]
                results["confidence_score"] = float(np.mean(confidences))
            
            # Detect anomalies based on features
            anomalies = self._detect_anomalies(features, memory_regions)
            results["memory_anomalies"] = anomalies
            
            return json.dumps(results)
        
        except Exception as e:
            logger.error(f"Error in analyze_memory_regions: {e}", exc_info=True)
            return json.dumps({
                "error": str(e),
                "threat_probability": 0.0,
                "detected_patterns": [],
                "evasion_techniques": [],
                "polymorphic_indicators": [],
                "memory_anomalies": [],
                "confidence_score": 0.0,
            })
    
    def _run_cnn_inference(self, memory_content: List[bytes]) -> Dict[str, Any]:
        """Run CNN inference for shellcode detection."""
        try:
            # Prepare input
            cnn_input = self.feature_extractor.prepare_cnn_input(memory_content)
            cnn_input_tensor = torch.from_numpy(cnn_input).long()
            
            # Run inference
            start_time = time.time()
            with torch.no_grad():
                probs = self.cnn_model.predict_proba(cnn_input_tensor)
                # Average across regions
                avg_prob = probs.mean(dim=0)
                shellcode_prob = float(avg_prob[1])  # Class 1 is shellcode
            
            inference_time = (time.time() - start_time) * 1000  # ms
            
            return {
                "model_id": "shellcode_cnn_v4",
                "prediction": shellcode_prob,
                "confidence": shellcode_prob,
                "inference_time_ms": inference_time,
            }
        except Exception as e:
            logger.error(f"CNN inference error: {e}")
            return {
                "model_id": "shellcode_cnn_v4",
                "prediction": 0.0,
                "confidence": 0.0,
                "inference_time_ms": 0.0,
                "error": str(e),
            }
    
    def _run_transformer_inference(self, memory_content: List[bytes]) -> Dict[str, Any]:
        """Run Transformer inference for polymorphic analysis."""
        try:
            # Prepare input (use first region or combine)
            if memory_content:
                # Combine all content
                combined = b"".join(memory_content[:10])  # Limit to first 10 regions
                # Truncate to max length
                max_len = 512
                if len(combined) > max_len:
                    combined = combined[:max_len]
                
                # Pad to max_len
                padded = combined + b"\x00" * (max_len - len(combined))
                input_tensor = torch.from_numpy(np.frombuffer(padded, dtype=np.uint8)).long().unsqueeze(0)
                
                # Run inference
                start_time = time.time()
                analysis = self.transformer_model.analyze_polymorphic(input_tensor)
                inference_time = (time.time() - start_time) * 1000  # ms
                
                mutation_family = int(analysis["mutation_family"][0])
                mutation_gen = float(analysis["mutation_generation"][0])
                confidence = float(analysis["confidence"][0])
                
                return {
                    "model_id": "polymorphic_transformer",
                    "prediction": confidence,
                    "confidence": confidence,
                    "inference_time_ms": inference_time,
                    "polymorphic_detected": confidence > 0.3,
                    "mutation_family": f"Family_{mutation_family}",
                    "mutation_generation": mutation_gen,
                }
            else:
                return {
                    "model_id": "polymorphic_transformer",
                    "prediction": 0.0,
                    "confidence": 0.0,
                    "inference_time_ms": 0.0,
                    "polymorphic_detected": False,
                }
        except Exception as e:
            logger.error(f"Transformer inference error: {e}")
            return {
                "model_id": "polymorphic_transformer",
                "prediction": 0.0,
                "confidence": 0.0,
                "inference_time_ms": 0.0,
                "polymorphic_detected": False,
                "error": str(e),
            }
    
    def _run_gnn_inference(self, memory_regions: List[Dict]) -> Dict[str, Any]:
        """Run GNN inference for evasion detection."""
        try:
            # Prepare graph input
            node_features, edge_index, edge_attr = self.feature_extractor.prepare_gnn_input(memory_regions)
            
            if len(node_features) == 0:
                return {
                    "model_id": "evasion_gnn",
                    "prediction": 0.0,
                    "confidence": 0.0,
                    "inference_time_ms": 0.0,
                    "evasion_detected": False,
                }
            
            # Convert to tensors
            node_features_tensor = torch.from_numpy(node_features).float()
            edge_index_tensor = torch.from_numpy(edge_index).long()
            batch_tensor = torch.zeros(len(node_features), dtype=torch.long)  # Single graph
            
            # Run inference
            start_time = time.time()
            analysis = self.gnn_model.analyze_evasion(
                node_features_tensor,
                edge_index_tensor,
                batch_tensor,
            )
            inference_time = (time.time() - start_time) * 1000  # ms
            
            evasion_category = int(analysis["evasion_category"][0])
            sophistication_level = int(analysis["sophistication_level"][0])
            confidence = float(analysis["evasion_confidence"][0])
            
            return {
                "model_id": "evasion_gnn",
                "prediction": confidence,
                "confidence": confidence,
                "inference_time_ms": inference_time,
                "evasion_detected": confidence > 0.3,
                "evasion_category": evasion_category,
                "sophistication_level": sophistication_level,
            }
        except Exception as e:
            logger.error(f"GNN inference error: {e}")
            return {
                "model_id": "evasion_gnn",
                "prediction": 0.0,
                "confidence": 0.0,
                "inference_time_ms": 0.0,
                "evasion_detected": False,
                "error": str(e),
            }
    
    def _detect_anomalies(
        self,
        features: np.ndarray,
        memory_regions: List[Dict],
    ) -> List[Dict[str, Any]]:
        """Detect memory anomalies based on features."""
        anomalies = []
        
        # Check for unusual RWX regions
        num_rwx = features[6] if len(features) > 6 else 0
        if num_rwx > 5:
            anomalies.append({
                "anomaly_name": "Excessive RWX Regions",
                "severity_score": min(0.8, num_rwx / 10.0),
                "anomaly_description": f"Found {int(num_rwx)} RWX memory regions, which is unusual",
            })
        
        # Check for high fragmentation
        fragmentation = features[18] if len(features) > 18 else 0
        if fragmentation > 0.5:
            anomalies.append({
                "anomaly_name": "High Address Space Fragmentation",
                "severity_score": fragmentation,
                "anomaly_description": "Address space shows high fragmentation, possible memory manipulation",
            })
        
        # Check for unusual region sizes
        size_std = features[3] if len(features) > 3 else 0
        avg_size = features[2] if len(features) > 2 else 0
        if size_std > avg_size * 2 and avg_size > 0:
            anomalies.append({
                "anomaly_name": "Irregular Region Sizes",
                "severity_score": 0.6,
                "anomaly_description": "Memory regions show highly irregular size distribution",
            })
        
        return anomalies


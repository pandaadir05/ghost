"""
Feature Extraction for Memory Regions

Extracts comprehensive features from memory regions for ML model input.
"""

import numpy as np
from typing import List, Dict, Any, Optional, Tuple
import logging
import math

logger = logging.getLogger(__name__)

class MemoryFeatureExtractor:
    """
    Extracts features from memory regions for ML models.
    
    Features include:
    - Memory region statistics
    - Protection flag patterns
    - Address space layout
    - Entropy calculations
    - Cross-region relationships
    """
    
    def __init__(self):
        self.feature_names = self._get_feature_names()
    
    def _get_feature_names(self) -> List[str]:
        """Get list of feature names."""
        return [
            # Basic statistics
            "num_regions",
            "total_size",
            "avg_region_size",
            "std_region_size",
            "min_region_size",
            "max_region_size",
            
            # Protection flags
            "num_rwx",
            "num_rx",
            "num_rw",
            "num_r",
            "num_wx",
            "num_x",
            "num_private",
            "num_mapped",
            "num_image",
            
            # Size distribution
            "size_entropy",
            "size_skewness",
            "size_kurtosis",
            
            # Address space layout
            "address_gaps_mean",
            "address_gaps_std",
            "address_gaps_max",
            "address_fragmentation",
            
            # Region type distribution
            "private_ratio",
            "mapped_ratio",
            "image_ratio",
            
            # Protection distribution
            "rwx_ratio",
            "rx_ratio",
            "rw_ratio",
            
            # Spatial features
            "region_density",
            "clustering_coefficient",
        ]
    
    def extract_features(
        self,
        memory_regions: List[Dict[str, Any]],
        memory_content: Optional[List[bytes]] = None,
    ) -> np.ndarray:
        """
        Extract features from memory regions.
        
        Args:
            memory_regions: List of memory region dictionaries with keys:
                - base_address: int
                - size: int
                - protection: str or int (R, W, X flags)
                - region_type: str (PRIVATE, MAPPED, IMAGE, etc.)
            memory_content: Optional list of byte content for each region
            
        Returns:
            Feature vector as numpy array
        """
        if not memory_regions:
            return np.zeros(len(self.feature_names))
        
        features = []
        
        # Basic statistics
        sizes = [r["size"] for r in memory_regions]
        features.extend(self._extract_size_stats(sizes))
        
        # Protection flags
        features.extend(self._extract_protection_features(memory_regions))
        
        # Size distribution
        features.extend(self._extract_size_distribution(sizes))
        
        # Address space layout
        features.extend(self._extract_address_layout(memory_regions))
        
        # Region type distribution
        features.extend(self._extract_region_type_features(memory_regions))
        
        # Protection distribution
        features.extend(self._extract_protection_distribution(memory_regions))
        
        # Spatial features
        features.extend(self._extract_spatial_features(memory_regions))
        
        # Content-based features (if available)
        if memory_content:
            features.extend(self._extract_content_features(memory_content))
        else:
            # Pad with zeros if no content
            features.extend([0.0] * 5)
        
        return np.array(features, dtype=np.float32)
    
    def _extract_size_stats(self, sizes: List[int]) -> List[float]:
        """Extract size statistics."""
        if not sizes:
            return [0.0] * 6
        
        sizes_array = np.array(sizes, dtype=np.float64)
        
        return [
            len(sizes),  # num_regions
            float(np.sum(sizes_array)),  # total_size
            float(np.mean(sizes_array)),  # avg_region_size
            float(np.std(sizes_array)),  # std_region_size
            float(np.min(sizes_array)),  # min_region_size
            float(np.max(sizes_array)),  # max_region_size
        ]
    
    def _extract_protection_features(self, regions: List[Dict]) -> List[float]:
        """Extract protection flag features."""
        num_rwx = 0
        num_rx = 0
        num_rw = 0
        num_r = 0
        num_wx = 0
        num_x = 0
        
        for r in regions:
            protection = r.get("protection", "")
            
            # Handle string format like "RWX", "R-X", etc.
            if isinstance(protection, str):
                has_r = "R" in protection or "r" in protection
                has_w = "W" in protection or "w" in protection
                has_x = "X" in protection or "x" in protection
            else:
                # Handle numeric flags (bitmask)
                has_r = (protection & 0x1) != 0
                has_w = (protection & 0x2) != 0
                has_x = (protection & 0x4) != 0
            
            if has_r and has_w and has_x:
                num_rwx += 1
            elif has_r and has_x:
                num_rx += 1
            elif has_r and has_w:
                num_rw += 1
            elif has_r:
                num_r += 1
            elif has_w and has_x:
                num_wx += 1
            elif has_x:
                num_x += 1
        
        return [
            float(num_rwx),
            float(num_rx),
            float(num_rw),
            float(num_r),
            float(num_wx),
            float(num_x),
        ]
    
    def _extract_size_distribution(self, sizes: List[int]) -> List[float]:
        """Extract size distribution features."""
        if not sizes or len(sizes) < 2:
            return [0.0, 0.0, 0.0]
        
        sizes_array = np.array(sizes, dtype=np.float64)
        
        # Entropy of size distribution
        hist, _ = np.histogram(sizes_array, bins=min(20, len(sizes)))
        hist = hist[hist > 0]  # Remove zeros
        if len(hist) > 0:
            probs = hist / np.sum(hist)
            entropy = -np.sum(probs * np.log2(probs + 1e-10))
        else:
            entropy = 0.0
        
        # Skewness and kurtosis
        mean = np.mean(sizes_array)
        std = np.std(sizes_array)
        
        if std > 0:
            normalized = (sizes_array - mean) / std
            skewness = float(np.mean(normalized ** 3))
            kurtosis = float(np.mean(normalized ** 4) - 3.0)
        else:
            skewness = 0.0
            kurtosis = 0.0
        
        return [entropy, skewness, kurtosis]
    
    def _extract_address_layout(self, regions: List[Dict]) -> List[float]:
        """Extract address space layout features."""
        if len(regions) < 2:
            return [0.0, 0.0, 0.0, 0.0]
        
        # Sort by address
        sorted_regions = sorted(regions, key=lambda r: r["base_address"])
        
        gaps = []
        for i in range(len(sorted_regions) - 1):
            current_end = sorted_regions[i]["base_address"] + sorted_regions[i]["size"]
            next_start = sorted_regions[i + 1]["base_address"]
            gap = next_start - current_end
            if gap > 0:
                gaps.append(gap)
        
        if gaps:
            gaps_array = np.array(gaps, dtype=np.float64)
            gaps_mean = float(np.mean(gaps_array))
            gaps_std = float(np.std(gaps_array))
            gaps_max = float(np.max(gaps_array))
        else:
            gaps_mean = 0.0
            gaps_std = 0.0
            gaps_max = 0.0
        
        # Fragmentation: ratio of gaps to total address space
        if sorted_regions:
            total_span = (sorted_regions[-1]["base_address"] + sorted_regions[-1]["size"]) - sorted_regions[0]["base_address"]
            total_gaps = sum(gaps) if gaps else 0.0
            fragmentation = total_gaps / total_span if total_span > 0 else 0.0
        else:
            fragmentation = 0.0
        
        return [gaps_mean, gaps_std, gaps_max, fragmentation]
    
    def _extract_region_type_features(self, regions: List[Dict]) -> List[float]:
        """Extract region type distribution features."""
        if not regions:
            return [0.0, 0.0, 0.0]
        
        num_private = sum(1 for r in regions if r.get("region_type", "").upper() == "PRIVATE")
        num_mapped = sum(1 for r in regions if r.get("region_type", "").upper() == "MAPPED")
        num_image = sum(1 for r in regions if r.get("region_type", "").upper() == "IMAGE")
        
        total = len(regions)
        return [
            float(num_private) / total if total > 0 else 0.0,
            float(num_mapped) / total if total > 0 else 0.0,
            float(num_image) / total if total > 0 else 0.0,
        ]
    
    def _extract_protection_distribution(self, regions: List[Dict]) -> List[float]:
        """Extract protection distribution features."""
        if not regions:
            return [0.0, 0.0, 0.0]
        
        num_rwx = 0
        num_rx = 0
        num_rw = 0
        
        for r in regions:
            protection = r.get("protection", "")
            if isinstance(protection, str):
                has_r = "R" in protection or "r" in protection
                has_w = "W" in protection or "w" in protection
                has_x = "X" in protection or "x" in protection
            else:
                has_r = (protection & 0x1) != 0
                has_w = (protection & 0x2) != 0
                has_x = (protection & 0x4) != 0
            
            if has_r and has_w and has_x:
                num_rwx += 1
            elif has_r and has_x:
                num_rx += 1
            elif has_r and has_w:
                num_rw += 1
        
        total = len(regions)
        return [
            float(num_rwx) / total if total > 0 else 0.0,
            float(num_rx) / total if total > 0 else 0.0,
            float(num_rw) / total if total > 0 else 0.0,
        ]
    
    def _extract_spatial_features(self, regions: List[Dict]) -> List[float]:
        """Extract spatial relationship features."""
        if len(regions) < 2:
            return [0.0, 0.0]
        
        # Region density: regions per unit of address space
        sorted_regions = sorted(regions, key=lambda r: r["base_address"])
        total_span = (sorted_regions[-1]["base_address"] + sorted_regions[-1]["size"]) - sorted_regions[0]["base_address"]
        density = len(regions) / total_span if total_span > 0 else 0.0
        
        # Clustering coefficient: measure of how regions cluster together
        # Simplified: ratio of regions that are close to each other
        if len(regions) >= 2:
            distances = []
            for i in range(len(sorted_regions) - 1):
                current_end = sorted_regions[i]["base_address"] + sorted_regions[i]["size"]
                next_start = sorted_regions[i + 1]["base_address"]
                distances.append(next_start - current_end)
            
            if distances:
                avg_distance = np.mean(distances)
                # Clustering: inverse of average distance (normalized)
                clustering = 1.0 / (1.0 + avg_distance / 1e6)  # Normalize
            else:
                clustering = 0.0
        else:
            clustering = 0.0
        
        return [density, clustering]
    
    def _extract_content_features(self, memory_content: List[bytes]) -> List[float]:
        """Extract content-based features (entropy, patterns, etc.)."""
        if not memory_content:
            return [0.0] * 5
        
        entropies = []
        for content in memory_content:
            if content:
                entropy = self._calculate_entropy(content)
                entropies.append(entropy)
        
        if entropies:
            return [
                float(np.mean(entropies)),  # avg_entropy
                float(np.std(entropies)),  # std_entropy
                float(np.max(entropies)),  # max_entropy
                float(len([e for e in entropies if e > 7.0]) / len(entropies)),  # high_entropy_ratio
                float(len([e for e in entropies if e < 3.0]) / len(entropies)),  # low_entropy_ratio
            ]
        else:
            return [0.0] * 5
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte sequence."""
        if not data:
            return 0.0
        
        # Count byte frequencies
        counts = np.zeros(256, dtype=np.float64)
        for byte in data:
            counts[byte] += 1
        
        # Normalize to probabilities
        probs = counts / len(data)
        probs = probs[probs > 0]  # Remove zeros
        
        # Calculate entropy
        entropy = -np.sum(probs * np.log2(probs + 1e-10))
        return float(entropy)
    
    def prepare_cnn_input(
        self,
        memory_content: List[bytes],
        max_length: int = 1024,
    ) -> np.ndarray:
        """
        Prepare input for CNN model (byte sequences).
        
        Args:
            memory_content: List of byte sequences
            max_length: Maximum sequence length
            
        Returns:
            Array of shape (num_regions, max_length) with byte values
        """
        sequences = []
        
        for content in memory_content:
            # Convert to numpy array of bytes
            seq = np.frombuffer(content[:max_length], dtype=np.uint8)
            
            # Pad or truncate to max_length
            if len(seq) < max_length:
                padded = np.zeros(max_length, dtype=np.uint8)
                padded[:len(seq)] = seq
                seq = padded
            else:
                seq = seq[:max_length]
            
            sequences.append(seq)
        
        return np.array(sequences, dtype=np.uint8)
    
    def prepare_gnn_input(
        self,
        memory_regions: List[Dict[str, Any]],
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Prepare input for GNN model (graph structure).
        
        Args:
            memory_regions: List of memory region dictionaries
            
        Returns:
            Tuple of (node_features, edge_index, edge_attr)
        """
        if not memory_regions:
            return np.zeros((0, 32)), np.zeros((2, 0), dtype=np.int64), np.zeros((0, 8))
        
        # Extract node features (one per region)
        node_features = []
        for r in memory_regions:
            features = [
                float(r.get("size", 0)),
                float(r.get("base_address", 0) % (2**32)),  # Lower 32 bits
                float(1.0 if "R" in str(r.get("protection", "")) else 0.0),
                float(1.0 if "W" in str(r.get("protection", "")) else 0.0),
                float(1.0 if "X" in str(r.get("protection", "")) else 0.0),
                float(1.0 if r.get("region_type", "").upper() == "PRIVATE" else 0.0),
                float(1.0 if r.get("region_type", "").upper() == "MAPPED" else 0.0),
                float(1.0 if r.get("region_type", "").upper() == "IMAGE" else 0.0),
            ]
            
            # Pad to 32 features
            while len(features) < 32:
                features.append(0.0)
            features = features[:32]
            
            node_features.append(features)
        
        node_features = np.array(node_features, dtype=np.float32)
        
        # Create edges: connect regions that are adjacent or close
        edges = []
        edge_attrs = []
        
        sorted_regions = sorted(enumerate(memory_regions), key=lambda x: x[1]["base_address"])
        
        for i, (idx1, r1) in enumerate(sorted_regions):
            addr1_end = r1["base_address"] + r1["size"]
            
            # Connect to next few regions
            for j in range(i + 1, min(i + 5, len(sorted_regions))):
                idx2, r2 = sorted_regions[j]
                addr2_start = r2["base_address"]
                
                # Calculate edge features
                gap = addr2_start - addr1_end
                edge_attr = [
                    float(gap),
                    float(1.0 if gap < 0x10000 else 0.0),  # Close
                    float(1.0 if gap < 0x1000000 else 0.0),  # Medium
                    float(1.0 if r1.get("region_type") == r2.get("region_type") else 0.0),
                    float(1.0 if str(r1.get("protection")) == str(r2.get("protection")) else 0.0),
                    float(abs(r1.get("size", 0) - r2.get("size", 0)) / max(r1.get("size", 1), r2.get("size", 1))),
                    float(1.0 if gap == 0 else 0.0),  # Adjacent
                    float(1.0),  # Always connected
                ]
                
                edges.append([idx1, idx2])
                edge_attrs.append(edge_attr)
        
        if edges:
            edge_index = np.array(edges, dtype=np.int64).T
            edge_attr = np.array(edge_attrs, dtype=np.float32)
        else:
            edge_index = np.zeros((2, 0), dtype=np.int64)
            edge_attr = np.zeros((0, 8), dtype=np.float32)
        
        return node_features, edge_index, edge_attr


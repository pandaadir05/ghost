"""
Graph Neural Network for Evasion Technique Detection

This model uses GNN to analyze relationships between memory regions
and detect evasion techniques.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, GATConv, global_mean_pool, global_max_pool
from torch_geometric.data import Data, Batch
from typing import Dict, Any, Optional, List, Tuple
import logging

logger = logging.getLogger(__name__)

# Fallback if torch_geometric is not available
try:
    from torch_geometric.nn import GCNConv, GATConv, global_mean_pool, global_max_pool
    from torch_geometric.data import Data, Batch
    TORCH_GEOMETRIC_AVAILABLE = True
except ImportError:
    TORCH_GEOMETRIC_AVAILABLE = False
    logger.warning("torch_geometric not available, using fallback GNN implementation")

class EvasionGNN(nn.Module):
    """
    Graph Neural Network for evasion technique detection.
    
    Architecture:
    - Node features: Memory region properties
    - Edge features: Relationships between regions
    - GCN/GAT layers for graph convolution
    - Global pooling for graph-level prediction
    - Classification head for evasion techniques
    """
    
    def __init__(
        self,
        node_features: int = 32,  # Features per memory region
        edge_features: int = 8,   # Features per edge
        hidden_dim: int = 128,
        num_layers: int = 3,
        num_heads: int = 4,  # For GAT
        dropout: float = 0.2,
        num_evasion_classes: int = 4,  # AntiDebugging, AntiVirtualization, CodeObfuscation, BehavioralEvasion
        use_gat: bool = True,
    ):
        super(EvasionGNN, self).__init__()
        
        self.node_features = node_features
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.use_gat = use_gat and TORCH_GEOMETRIC_AVAILABLE
        
        # Input projection
        self.node_proj = nn.Linear(node_features, hidden_dim)
        
        # Graph convolution layers
        if self.use_gat:
            self.convs = nn.ModuleList()
            for i in range(num_layers):
                if i == 0:
                    self.convs.append(
                        GATConv(hidden_dim, hidden_dim // num_heads, heads=num_heads, dropout=dropout)
                    )
                else:
                    self.convs.append(
                        GATConv(hidden_dim, hidden_dim // num_heads, heads=num_heads, dropout=dropout)
                    )
        else:
            # Fallback: Simple MLP-based graph convolution
            self.convs = nn.ModuleList()
            for i in range(num_layers):
                self.convs.append(nn.Sequential(
                    nn.Linear(hidden_dim, hidden_dim),
                    nn.BatchNorm1d(hidden_dim),
                    nn.ReLU(),
                    nn.Dropout(dropout),
                ))
        
        # Batch normalization layers
        self.batch_norms = nn.ModuleList([
            nn.BatchNorm1d(hidden_dim) for _ in range(num_layers)
        ])
        
        # Dropout
        self.dropout = nn.Dropout(dropout)
        
        # Global pooling
        if TORCH_GEOMETRIC_AVAILABLE:
            self.pool = lambda x, batch: torch.cat([
                global_mean_pool(x, batch),
                global_max_pool(x, batch)
            ], dim=1)
        else:
            self.pool = lambda x, batch: self._simple_pool(x, batch)
        
        # Classification head
        pool_dim = hidden_dim * 2 if TORCH_GEOMETRIC_AVAILABLE else hidden_dim
        self.classifier = nn.Sequential(
            nn.Linear(pool_dim, 256),
            nn.LayerNorm(256),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(256, 128),
            nn.LayerNorm(128),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(128, num_evasion_classes),
        )
        
        # Sophistication level predictor
        self.sophistication_predictor = nn.Sequential(
            nn.Linear(pool_dim, 64),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(64, 4),  # Basic, Intermediate, Advanced, Expert
        )
        
        logger.info(f"Initialized EvasionGNN with node_features={node_features}, "
                   f"hidden_dim={hidden_dim}, num_layers={num_layers}, use_gat={self.use_gat}")
    
    def _simple_pool(self, x: torch.Tensor, batch: torch.Tensor) -> torch.Tensor:
        """Simple pooling fallback when torch_geometric is not available."""
        # Group by batch index
        unique_batches = torch.unique(batch)
        pooled = []
        
        for b in unique_batches:
            mask = (batch == b)
            node_features = x[mask]
            mean_pool = node_features.mean(dim=0)
            max_pool = node_features.max(dim=0)[0]
            pooled.append(torch.cat([mean_pool, max_pool]))
        
        return torch.stack(pooled)
    
    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: torch.Tensor,
        edge_attr: Optional[torch.Tensor] = None,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass.
        
        Args:
            x: Node features (num_nodes, node_features)
            edge_index: Edge connectivity (2, num_edges)
            batch: Batch assignment for each node (num_nodes,)
            edge_attr: Optional edge features
            
        Returns:
            Tuple of (evasion_logits, sophistication_logits)
        """
        # Project node features
        x = self.node_proj(x)
        
        # Graph convolution layers
        for i, conv in enumerate(self.convs):
            if self.use_gat:
                x_new = conv(x, edge_index)
            else:
                # Fallback: simple message passing
                x_new = conv(x)
            
            x = x + x_new  # Residual connection
            x = self.batch_norms[i](x)
            x = F.relu(x)
            x = self.dropout(x)
        
        # Global pooling
        graph_features = self.pool(x, batch)
        
        # Classification
        evasion_logits = self.classifier(graph_features)
        sophistication_logits = self.sophistication_predictor(graph_features)
        
        return evasion_logits, sophistication_logits
    
    def predict_proba(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: torch.Tensor,
        edge_attr: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """Get probability predictions."""
        with torch.no_grad():
            logits, _ = self.forward(x, edge_index, batch, edge_attr)
            return F.softmax(logits, dim=1)
    
    def predict(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: torch.Tensor,
        edge_attr: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """Get class predictions."""
        with torch.no_grad():
            logits, _ = self.forward(x, edge_index, batch, edge_attr)
            return torch.argmax(logits, dim=1)
    
    def analyze_evasion(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: torch.Tensor,
        edge_attr: Optional[torch.Tensor] = None,
    ) -> Dict[str, torch.Tensor]:
        """
        Analyze evasion techniques and return detailed results.
        
        Returns:
            Dictionary with:
            - evasion_category: Predicted evasion category
            - sophistication_level: Predicted sophistication level
            - confidence: Confidence scores
        """
        with torch.no_grad():
            evasion_logits, sophistication_logits = self.forward(x, edge_index, batch, edge_attr)
            
            evasion_probs = F.softmax(evasion_logits, dim=1)
            sophistication_probs = F.softmax(sophistication_logits, dim=1)
            
            evasion_confidence, predicted_category = torch.max(evasion_probs, dim=1)
            sophistication_confidence, predicted_level = torch.max(sophistication_probs, dim=1)
            
            return {
                "evasion_category": predicted_category,
                "sophistication_level": predicted_level,
                "evasion_confidence": evasion_confidence,
                "sophistication_confidence": sophistication_confidence,
                "evasion_probs": evasion_probs,
                "sophistication_probs": sophistication_probs,
            }


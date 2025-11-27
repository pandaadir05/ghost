"""
Transformer-based Model for Polymorphic Code Analysis

This model uses attention mechanisms to detect polymorphic code patterns
and mutation families in memory regions.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, Any, Optional, Tuple
import logging
import math

logger = logging.getLogger(__name__)

class PositionalEncoding(nn.Module):
    """Positional encoding for transformer."""
    
    def __init__(self, d_model: int, max_len: int = 5000, dropout: float = 0.1):
        super(PositionalEncoding, self).__init__()
        self.dropout = nn.Dropout(p=dropout)
        
        position = torch.arange(max_len).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2) * (-math.log(10000.0) / d_model))
        pe = torch.zeros(max_len, d_model)
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0)
        self.register_buffer('pe', pe)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = x + self.pe[:, :x.size(1), :]
        return self.dropout(x)

class PolymorphicTransformer(nn.Module):
    """
    Transformer model for polymorphic code detection.
    
    Architecture:
    - Byte embedding layer
    - Positional encoding
    - Multi-head self-attention
    - Feed-forward networks
    - Classification head
    """
    
    def __init__(
        self,
        input_size: int = 512,
        embedding_dim: int = 128,
        num_heads: int = 8,
        num_layers: int = 4,
        dim_feedforward: int = 512,
        dropout: float = 0.1,
        num_classes: int = 10,  # Multiple mutation families
        max_len: int = 512,
    ):
        super(PolymorphicTransformer, self).__init__()
        
        self.input_size = input_size
        self.embedding_dim = embedding_dim
        self.num_heads = num_heads
        self.num_layers = num_layers
        
        # Byte embedding
        self.embedding = nn.Embedding(256, embedding_dim)
        
        # Positional encoding
        self.pos_encoder = PositionalEncoding(embedding_dim, max_len, dropout)
        
        # Transformer encoder layers
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embedding_dim,
            nhead=num_heads,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            activation='gelu',
            batch_first=True,
        )
        self.transformer_encoder = nn.TransformerEncoder(
            encoder_layer,
            num_layers=num_layers,
        )
        
        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(embedding_dim, 256),
            nn.LayerNorm(256),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(256, 128),
            nn.LayerNorm(128),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(128, num_classes),
        )
        
        # Mutation generation predictor (for polymorphic analysis)
        self.mutation_predictor = nn.Sequential(
            nn.Linear(embedding_dim, 128),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(128, 1),  # Predict mutation generation number
        )
        
        logger.info(f"Initialized PolymorphicTransformer with embedding_dim={embedding_dim}, "
                   f"num_heads={num_heads}, num_layers={num_layers}")
    
    def forward(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass.
        
        Args:
            x: Input tensor of shape (batch_size, sequence_length) with byte values 0-255
            mask: Optional attention mask
            
        Returns:
            Tuple of (classification_logits, mutation_generation)
        """
        # Embed bytes
        x = self.embedding(x)  # (batch_size, seq_len, embedding_dim)
        
        # Add positional encoding
        x = self.pos_encoder(x)
        
        # Create padding mask if not provided
        if mask is None:
            # Assume all positions are valid (no padding)
            mask = torch.zeros(x.size(0), x.size(1), dtype=torch.bool, device=x.device)
        
        # Transformer encoder
        x = self.transformer_encoder(x, src_key_padding_mask=mask)
        
        # Global average pooling
        # Mask out padding positions
        if mask is not None:
            x = x.masked_fill(mask.unsqueeze(-1), 0.0)
            lengths = (~mask).sum(dim=1, keepdim=True).float()
            x = x.sum(dim=1) / lengths.clamp(min=1.0)
        else:
            x = x.mean(dim=1)
        
        # Classification
        class_logits = self.classifier(x)
        
        # Mutation generation prediction
        mutation_gen = self.mutation_predictor(x)
        
        return class_logits, mutation_gen.squeeze(-1)
    
    def predict_proba(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """Get probability predictions."""
        with torch.no_grad():
            logits, _ = self.forward(x, mask)
            return F.softmax(logits, dim=1)
    
    def predict(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """Get class predictions."""
        with torch.no_grad():
            logits, _ = self.forward(x, mask)
            return torch.argmax(logits, dim=1)
    
    def analyze_polymorphic(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        """
        Analyze polymorphic code and return detailed results.
        
        Returns:
            Dictionary with:
            - mutation_family: Predicted mutation family class
            - mutation_generation: Predicted generation number
            - confidence: Confidence scores
        """
        with torch.no_grad():
            class_logits, mutation_gen = self.forward(x, mask)
            probs = F.softmax(class_logits, dim=1)
            confidence, predicted_family = torch.max(probs, dim=1)
            
            return {
                "mutation_family": predicted_family,
                "mutation_generation": mutation_gen.clamp(min=0),
                "confidence": confidence,
                "family_probs": probs,
            }


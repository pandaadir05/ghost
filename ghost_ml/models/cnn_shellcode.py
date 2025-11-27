"""
Convolutional Neural Network for Shellcode Detection

This model uses 1D convolutions to analyze byte sequences in memory regions
for shellcode patterns.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class ShellcodeCNN(nn.Module):
    """
    CNN model for shellcode detection in memory regions.
    
    Architecture:
    - Input: Byte sequences (padded/truncated to fixed length)
    - 1D Convolutions for pattern detection
    - Pooling layers for feature aggregation
    - Fully connected layers for classification
    """
    
    def __init__(
        self,
        input_size: int = 1024,  # Fixed input sequence length
        embedding_dim: int = 64,
        num_filters: int = 128,
        kernel_sizes: list = [3, 5, 7],
        num_classes: int = 2,  # Binary: shellcode or not
        dropout: float = 0.3,
    ):
        super(ShellcodeCNN, self).__init__()
        
        self.input_size = input_size
        self.embedding_dim = embedding_dim
        self.num_filters = num_filters
        self.kernel_sizes = kernel_sizes
        self.num_classes = num_classes
        
        # Embedding layer: map bytes (0-255) to dense vectors
        self.embedding = nn.Embedding(256, embedding_dim)
        
        # Multiple convolution branches with different kernel sizes
        self.conv_branches = nn.ModuleList([
            nn.Sequential(
                nn.Conv1d(embedding_dim, num_filters, kernel_size=k, padding=k//2),
                nn.BatchNorm1d(num_filters),
                nn.ReLU(),
                nn.MaxPool1d(2),
                nn.Conv1d(num_filters, num_filters, kernel_size=k, padding=k//2),
                nn.BatchNorm1d(num_filters),
                nn.ReLU(),
                nn.MaxPool1d(2),
            )
            for k in kernel_sizes
        ])
        
        # Calculate output size after convolutions and pooling
        # Each branch reduces size by 4 (2 max pools of stride 2)
        conv_output_size = (input_size // 4) * num_filters * len(kernel_sizes)
        
        # Fully connected layers
        self.fc1 = nn.Linear(conv_output_size, 512)
        self.bn1 = nn.BatchNorm1d(512)
        self.dropout1 = nn.Dropout(dropout)
        
        self.fc2 = nn.Linear(512, 256)
        self.bn2 = nn.BatchNorm1d(256)
        self.dropout2 = nn.Dropout(dropout)
        
        self.fc3 = nn.Linear(256, num_classes)
        
        logger.info(f"Initialized ShellcodeCNN with input_size={input_size}, "
                   f"embedding_dim={embedding_dim}, num_filters={num_filters}")
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: Input tensor of shape (batch_size, sequence_length) with byte values 0-255
            
        Returns:
            Logits of shape (batch_size, num_classes)
        """
        # Embed bytes
        x = self.embedding(x)  # (batch_size, seq_len, embedding_dim)
        
        # Transpose for conv1d: (batch_size, embedding_dim, seq_len)
        x = x.transpose(1, 2)
        
        # Apply each convolution branch
        branch_outputs = []
        for conv_branch in self.conv_branches:
            branch_out = conv_branch(x)  # (batch_size, num_filters, reduced_seq_len)
            # Flatten
            branch_out = branch_out.view(branch_out.size(0), -1)
            branch_outputs.append(branch_out)
        
        # Concatenate all branches
        x = torch.cat(branch_outputs, dim=1)
        
        # Fully connected layers
        x = self.fc1(x)
        x = self.bn1(x)
        x = F.relu(x)
        x = self.dropout1(x)
        
        x = self.fc2(x)
        x = self.bn2(x)
        x = F.relu(x)
        x = self.dropout2(x)
        
        x = self.fc3(x)
        
        return x
    
    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        """Get probability predictions."""
        with torch.no_grad():
            logits = self.forward(x)
            return F.softmax(logits, dim=1)
    
    def predict(self, x: torch.Tensor) -> torch.Tensor:
        """Get class predictions."""
        with torch.no_grad():
            logits = self.forward(x)
            return torch.argmax(logits, dim=1)
    
    def extract_features(self, x: torch.Tensor) -> torch.Tensor:
        """Extract intermediate features for analysis."""
        x = self.embedding(x)
        x = x.transpose(1, 2)
        
        branch_outputs = []
        for conv_branch in self.conv_branches:
            branch_out = conv_branch(x)
            branch_out = branch_out.view(branch_out.size(0), -1)
            branch_outputs.append(branch_out)
        
        x = torch.cat(branch_outputs, dim=1)
        x = self.fc1(x)
        x = self.bn1(x)
        x = F.relu(x)
        
        return x


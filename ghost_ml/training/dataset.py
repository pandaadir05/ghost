"""Dataset classes for Ghost ML training."""

import numpy as np
import torch
from torch.utils.data import Dataset
from typing import List, Dict, Tuple, Optional


class MemoryDataset(Dataset):
    """
    Dataset for memory region analysis.

    Loads memory snapshots and their labels for training.
    """

    def __init__(
        self,
        memory_samples: List[np.ndarray],
        labels: List[int],
        feature_extractor: Optional[callable] = None,
        transform: Optional[callable] = None,
    ):
        """
        Args:
            memory_samples: List of memory byte arrays
            labels: List of integer labels
            feature_extractor: Optional feature extraction function
            transform: Optional data augmentation transforms
        """
        self.memory_samples = memory_samples
        self.labels = labels
        self.feature_extractor = feature_extractor
        self.transform = transform

        assert len(memory_samples) == len(labels), "Samples and labels must have same length"

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor]:
        sample = self.memory_samples[idx]
        label = self.labels[idx]

        # Extract features if extractor provided
        if self.feature_extractor:
            sample = self.feature_extractor(sample)

        # Apply transforms
        if self.transform:
            sample = self.transform(sample)

        # Convert to tensors
        if isinstance(sample, np.ndarray):
            sample = torch.from_numpy(sample)

        return sample, torch.tensor(label, dtype=torch.long)


class ShellcodeDataset(Dataset):
    """
    Dataset specifically for shellcode detection training.

    Handles byte sequences with padding/truncation to fixed length.
    """

    def __init__(
        self,
        byte_sequences: List[bytes],
        labels: List[int],
        max_length: int = 1024,
        augment: bool = False,
    ):
        """
        Args:
            byte_sequences: List of raw byte sequences
            labels: Binary labels (0=benign, 1=shellcode)
            max_length: Maximum sequence length (pad/truncate)
            augment: Whether to apply data augmentation
        """
        self.byte_sequences = byte_sequences
        self.labels = labels
        self.max_length = max_length
        self.augment = augment

        assert len(byte_sequences) == len(labels)

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor]:
        byte_seq = self.byte_sequences[idx]
        label = self.labels[idx]

        # Convert bytes to numpy array
        byte_array = np.frombuffer(byte_seq[:self.max_length], dtype=np.uint8)

        # Apply augmentation if enabled
        if self.augment and np.random.random() < 0.5:
            byte_array = self._augment(byte_array)

        # Pad or truncate
        if len(byte_array) < self.max_length:
            padded = np.zeros(self.max_length, dtype=np.uint8)
            padded[:len(byte_array)] = byte_array
            byte_array = padded
        else:
            byte_array = byte_array[:self.max_length]

        # Convert to tensor
        sample = torch.from_numpy(byte_array).long()
        label = torch.tensor(label, dtype=torch.long)

        return sample, label

    def _augment(self, byte_array: np.ndarray) -> np.ndarray:
        """
        Apply data augmentation to byte sequence.

        Simulates polymorphic mutations by applying small random changes.
        """
        augmented = byte_array.copy()

        # Random byte substitution (5% of bytes)
        num_substitutions = max(1, int(len(augmented) * 0.05))
        positions = np.random.choice(len(augmented), size=num_substitutions, replace=False)
        augmented[positions] = np.random.randint(0, 256, size=num_substitutions, dtype=np.uint8)

        return augmented


class GraphMemoryDataset(Dataset):
    """
    Dataset for graph-based memory analysis (GNN training).

    Each sample is a graph representing memory layout.
    """

    def __init__(
        self,
        memory_regions: List[List[Dict]],
        labels: List[int],
        graph_builder: callable,
    ):
        """
        Args:
            memory_regions: List of memory region lists (each list is one sample)
            labels: List of integer labels
            graph_builder: Function to build graph from memory regions
        """
        self.memory_regions = memory_regions
        self.labels = labels
        self.graph_builder = graph_builder

        assert len(memory_regions) == len(labels)

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int) -> Tuple[Dict, torch.Tensor]:
        regions = self.memory_regions[idx]
        label = self.labels[idx]

        # Build graph from memory regions
        graph_data = self.graph_builder(regions)

        return graph_data, torch.tensor(label, dtype=torch.long)

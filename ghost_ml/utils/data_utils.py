"""Data utility functions."""

import numpy as np
from typing import Tuple, List
from torch.utils.data import Dataset, DataLoader, random_split


def train_val_split(
    dataset: Dataset,
    val_fraction: float = 0.2,
    seed: int = 42,
) -> Tuple[Dataset, Dataset]:
    """
    Split dataset into train and validation sets.

    Args:
        dataset: Dataset to split
        val_fraction: Fraction for validation
        seed: Random seed

    Returns:
        Tuple of (train_dataset, val_dataset)
    """
    val_size = int(len(dataset) * val_fraction)
    train_size = len(dataset) - val_size

    generator = np.random.Generator(np.random.PCG64(seed))
    train_dataset, val_dataset = random_split(
        dataset,
        [train_size, val_size],
        generator=generator
    )

    return train_dataset, val_dataset


def create_data_loader(
    dataset: Dataset,
    batch_size: int = 32,
    shuffle: bool = True,
    num_workers: int = 0,
    pin_memory: bool = False,
) -> DataLoader:
    """
    Create a DataLoader with standard settings.

    Args:
        dataset: Dataset to load
        batch_size: Batch size
        shuffle: Whether to shuffle
        num_workers: Number of worker processes
        pin_memory: Whether to pin memory (for GPU)

    Returns:
        DataLoader instance
    """
    return DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=shuffle,
        num_workers=num_workers,
        pin_memory=pin_memory,
    )


def balance_dataset(
    samples: List,
    labels: List[int],
    strategy: str = "undersample",
) -> Tuple[List, List[int]]:
    """
    Balance dataset classes.

    Args:
        samples: List of samples
        labels: List of labels
        strategy: Balancing strategy ("undersample" or "oversample")

    Returns:
        Tuple of (balanced_samples, balanced_labels)
    """
    unique_labels = set(labels)
    label_counts = {label: labels.count(label) for label in unique_labels}

    if strategy == "undersample":
        min_count = min(label_counts.values())
        target_count = min_count
    elif strategy == "oversample":
        max_count = max(label_counts.values())
        target_count = max_count
    else:
        raise ValueError(f"Unknown strategy: {strategy}")

    balanced_samples = []
    balanced_labels = []

    for label in unique_labels:
        label_indices = [i for i, l in enumerate(labels) if l == label]
        current_count = len(label_indices)

        if current_count > target_count:
            # Undersample
            selected_indices = np.random.choice(label_indices, target_count, replace=False)
        else:
            # Oversample
            selected_indices = np.random.choice(label_indices, target_count, replace=True)

        for idx in selected_indices:
            balanced_samples.append(samples[idx])
            balanced_labels.append(labels[idx])

    return balanced_samples, balanced_labels

"""
Ghost ML - Machine Learning Models for Neural Memory Analysis

This package provides ML models for the Ghost framework's neural memory analyzer.
"""

__version__ = "1.0.0"

from .models import (
    ShellcodeCNN,
    PolymorphicTransformer,
    EvasionGNN,
    load_model,
    save_model,
)
from .features import MemoryFeatureExtractor
from .bridge import GhostMLBridge

__all__ = [
    "ShellcodeCNN",
    "PolymorphicTransformer",
    "EvasionGNN",
    "load_model",
    "save_model",
    "MemoryFeatureExtractor",
    "GhostMLBridge",
]


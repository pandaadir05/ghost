"""Model utility functions."""

import logging
from pathlib import Path
from typing import Dict, Any, Optional
import torch
import torch.nn as nn

logger = logging.getLogger(__name__)


def count_parameters(model: nn.Module) -> Dict[str, int]:
    """
    Count trainable and total parameters in a model.

    Args:
        model: PyTorch model

    Returns:
        Dictionary with parameter counts
    """
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total_params = sum(p.numel() for p in model.parameters())

    return {
        'trainable': trainable_params,
        'total': total_params,
        'frozen': total_params - trainable_params,
    }


def model_summary(model: nn.Module, input_size: Optional[tuple] = None) -> str:
    """
    Generate model summary string.

    Args:
        model: PyTorch model
        input_size: Optional input size for shape inference

    Returns:
        Summary string
    """
    param_counts = count_parameters(model)

    summary = [
        f"Model: {model.__class__.__name__}",
        f"Trainable parameters: {param_counts['trainable']:,}",
        f"Total parameters: {param_counts['total']:,}",
        f"Frozen parameters: {param_counts['frozen']:,}",
    ]

    if input_size:
        summary.append(f"Input size: {input_size}")

    return "\n".join(summary)


def save_model(
    model: nn.Module,
    path: Path,
    metadata: Optional[Dict[str, Any]] = None,
    optimizer: Optional[torch.optim.Optimizer] = None,
    epoch: Optional[int] = None,
):
    """
    Save model checkpoint with metadata.

    Args:
        model: Model to save
        path: Save path
        metadata: Optional metadata dictionary
        optimizer: Optional optimizer state
        epoch: Optional epoch number
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    checkpoint = {
        'model_state_dict': model.state_dict(),
        'model_class': model.__class__.__name__,
    }

    if metadata:
        checkpoint['metadata'] = metadata

    if optimizer:
        checkpoint['optimizer_state_dict'] = optimizer.state_dict()

    if epoch is not None:
        checkpoint['epoch'] = epoch

    torch.save(checkpoint, path)
    logger.info(f"Saved model to {path}")


def load_model(
    model: nn.Module,
    path: Path,
    device: str = "cpu",
    strict: bool = True,
) -> nn.Module:
    """
    Load model from checkpoint.

    Args:
        model: Model instance to load weights into
        path: Checkpoint path
        device: Device to load on
        strict: Whether to strictly enforce state dict keys

    Returns:
        Model with loaded weights
    """
    checkpoint = torch.load(path, map_location=device)

    if 'model_state_dict' in checkpoint:
        model.load_state_dict(checkpoint['model_state_dict'], strict=strict)
    else:
        model.load_state_dict(checkpoint, strict=strict)

    model.eval()
    logger.info(f"Loaded model from {path}")

    return model


def freeze_layers(model: nn.Module, layer_names: list):
    """
    Freeze specific layers in the model.

    Args:
        model: PyTorch model
        layer_names: List of layer names to freeze
    """
    for name, param in model.named_parameters():
        for layer_name in layer_names:
            if layer_name in name:
                param.requires_grad = False
                logger.info(f"Frozen layer: {name}")


def unfreeze_layers(model: nn.Module, layer_names: list):
    """
    Unfreeze specific layers in the model.

    Args:
        model: PyTorch model
        layer_names: List of layer names to unfreeze
    """
    for name, param in model.named_parameters():
        for layer_name in layer_names:
            if layer_name in name:
                param.requires_grad = True
                logger.info(f"Unfrozen layer: {name}")


def get_learning_rate(optimizer: torch.optim.Optimizer) -> float:
    """Get current learning rate from optimizer."""
    for param_group in optimizer.param_groups:
        return param_group['lr']
    return 0.0

"""ML Models for Ghost Neural Memory Analysis"""

from .cnn_shellcode import ShellcodeCNN
from .transformer_polymorphic import PolymorphicTransformer
from .gnn_evasion import EvasionGNN

__all__ = [
    "ShellcodeCNN",
    "PolymorphicTransformer",
    "EvasionGNN",
]

def load_model(model_path: str, model_type: str):
    """Load a trained model from disk."""
    import torch
    
    if model_type == "cnn":
        model = ShellcodeCNN()
    elif model_type == "transformer":
        model = PolymorphicTransformer()
    elif model_type == "gnn":
        model = EvasionGNN()
    else:
        raise ValueError(f"Unknown model type: {model_type}")
    
    checkpoint = torch.load(model_path, map_location="cpu")
    if isinstance(checkpoint, dict) and "model_state_dict" in checkpoint:
        model.load_state_dict(checkpoint["model_state_dict"])
    else:
        model.load_state_dict(checkpoint)
    
    model.eval()
    return model

def save_model(model, model_path: str, metadata: dict = None):
    """Save a trained model to disk."""
    import torch
    
    save_data = {
        "model_state_dict": model.state_dict(),
        "model_class": type(model).__name__,
    }
    
    if metadata:
        save_data["metadata"] = metadata
    
    torch.save(save_data, model_path)


#!/usr/bin/env python3
"""
Training script for Ghost ML models.

Trains ShellcodeCNN, PolymorphicTransformer, and EvasionGNN models.
"""

import argparse
import logging
import sys
from pathlib import Path

import torch
import torch.nn as nn
import torch.optim as optim
from torch.optim.lr_scheduler import CosineAnnealingLR

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ghost_ml.models import ShellcodeCNN, PolymorphicTransformer, EvasionGNN
from ghost_ml.training import ModelTrainer, ShellcodeDataset
from ghost_ml.training.metrics import compute_metrics
from ghost_ml.utils import model_summary, create_data_loader, train_val_split

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def train_cnn(args):
    """Train ShellcodeCNN model."""
    logger.info("Training ShellcodeCNN...")

    # Create model
    model = ShellcodeCNN(
        input_size=args.sequence_length,
        embedding_dim=64,
        num_filters=128,
        kernel_sizes=[3, 5, 7],
        num_classes=2,
        dropout=0.3,
    )

    logger.info(model_summary(model))

    # Setup training
    device = "cuda" if torch.cuda.is_available() else "cpu"
    logger.info(f"Using device: {device}")

    criterion = nn.CrossEntropyLoss()
    optimizer = optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-5)
    scheduler = CosineAnnealingLR(optimizer, T_max=args.epochs)

    # Create trainer
    trainer = ModelTrainer(
        model=model,
        optimizer=optimizer,
        criterion=criterion,
        device=device,
        scheduler=scheduler,
        grad_clip=1.0,
    )

    # Note: This is a template. In production, you would load real data here.
    logger.info("NOTE: This script requires real training data.")
    logger.info("Load your dataset and create train/val loaders before training.")

    # Example of how to use the trainer (commented out):
    # history = trainer.train(
    #     train_loader=train_loader,
    #     val_loader=val_loader,
    #     num_epochs=args.epochs,
    #     checkpoint_dir=args.output_dir / "cnn",
    #     early_stopping_patience=10,
    # )

    logger.info("ShellcodeCNN training template completed")


def train_transformer(args):
    """Train PolymorphicTransformer model."""
    logger.info("Training PolymorphicTransformer...")

    model = PolymorphicTransformer(
        input_size=512,
        embedding_dim=128,
        num_heads=8,
        num_layers=4,
        dim_feedforward=512,
        dropout=0.1,
        num_classes=10,
    )

    logger.info(model_summary(model))

    device = "cuda" if torch.cuda.is_available() else "cpu"
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-5)
    scheduler = CosineAnnealingLR(optimizer, T_max=args.epochs)

    trainer = ModelTrainer(
        model=model,
        optimizer=optimizer,
        criterion=criterion,
        device=device,
        scheduler=scheduler,
        grad_clip=1.0,
    )

    logger.info("PolymorphicTransformer training template completed")


def train_gnn(args):
    """Train EvasionGNN model."""
    logger.info("Training EvasionGNN...")

    model = EvasionGNN(
        node_features=32,
        edge_features=8,
        hidden_dim=128,
        num_layers=3,
        num_heads=4,
        dropout=0.2,
        num_evasion_classes=4,
    )

    logger.info(model_summary(model))

    device = "cuda" if torch.cuda.is_available() else "cpu"
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-5)
    scheduler = CosineAnnealingLR(optimizer, T_max=args.epochs)

    trainer = ModelTrainer(
        model=model,
        optimizer=optimizer,
        criterion=criterion,
        device=device,
        scheduler=scheduler,
        grad_clip=1.0,
    )

    logger.info("EvasionGNN training template completed")


def main():
    parser = argparse.ArgumentParser(description="Train Ghost ML models")
    parser.add_argument(
        "--model",
        type=str,
        choices=["cnn", "transformer", "gnn", "all"],
        default="all",
        help="Model to train"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("models"),
        help="Output directory for trained models"
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=50,
        help="Number of training epochs"
    )
    parser.add_argument(
        "--lr",
        type=float,
        default=0.001,
        help="Learning rate"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=32,
        help="Batch size"
    )
    parser.add_argument(
        "--sequence-length",
        type=int,
        default=1024,
        help="Sequence length for CNN"
    )

    args = parser.parse_args()

    # Create output directory
    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Train models
    if args.model in ["cnn", "all"]:
        train_cnn(args)

    if args.model in ["transformer", "all"]:
        train_transformer(args)

    if args.model in ["gnn", "all"]:
        train_gnn(args)

    logger.info("Training complete!")
    logger.info(f"Models will be saved to: {args.output_dir}")
    logger.info("\nTo use these models in production:")
    logger.info("1. Collect real malware and benign samples")
    logger.info("2. Implement data loading in this script")
    logger.info("3. Run training with your dataset")
    logger.info("4. Deploy trained models to the models/ directory")


if __name__ == "__main__":
    main()

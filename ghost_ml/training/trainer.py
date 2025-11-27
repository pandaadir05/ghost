"""Training infrastructure for Ghost ML models."""

import logging
import time
from pathlib import Path
from typing import Dict, Optional, Callable, Any

import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from torch.optim import Optimizer
from torch.optim.lr_scheduler import _LRScheduler

logger = logging.getLogger(__name__)


class ModelTrainer:
    """
    Generic trainer for Ghost ML models.

    Handles training loop, validation, checkpointing, and metrics tracking.
    """

    def __init__(
        self,
        model: nn.Module,
        optimizer: Optimizer,
        criterion: nn.Module,
        device: str = "cpu",
        scheduler: Optional[_LRScheduler] = None,
        grad_clip: Optional[float] = None,
    ):
        self.model = model.to(device)
        self.optimizer = optimizer
        self.criterion = criterion
        self.device = device
        self.scheduler = scheduler
        self.grad_clip = grad_clip

        self.epoch = 0
        self.best_val_loss = float('inf')
        self.history = {
            'train_loss': [],
            'val_loss': [],
            'train_acc': [],
            'val_acc': [],
        }

    def train_epoch(
        self,
        train_loader: DataLoader,
        progress_callback: Optional[Callable[[int, int, float], None]] = None,
    ) -> Dict[str, float]:
        """Train for one epoch."""
        self.model.train()
        total_loss = 0.0
        correct = 0
        total = 0

        for batch_idx, batch in enumerate(train_loader):
            # Move batch to device
            if isinstance(batch, (list, tuple)):
                inputs = batch[0].to(self.device)
                targets = batch[1].to(self.device)
            else:
                inputs = batch['input'].to(self.device)
                targets = batch['target'].to(self.device)

            # Forward pass
            self.optimizer.zero_grad()
            outputs = self.model(inputs)

            # Handle multi-output models
            if isinstance(outputs, tuple):
                outputs = outputs[0]

            loss = self.criterion(outputs, targets)

            # Backward pass
            loss.backward()

            if self.grad_clip:
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), self.grad_clip)

            self.optimizer.step()

            # Track metrics
            total_loss += loss.item()
            _, predicted = outputs.max(1)
            total += targets.size(0)
            correct += predicted.eq(targets).sum().item()

            # Progress callback
            if progress_callback:
                progress_callback(batch_idx, len(train_loader), loss.item())

        avg_loss = total_loss / len(train_loader)
        accuracy = 100.0 * correct / total if total > 0 else 0.0

        return {'loss': avg_loss, 'accuracy': accuracy}

    def validate(self, val_loader: DataLoader) -> Dict[str, float]:
        """Validate the model."""
        self.model.eval()
        total_loss = 0.0
        correct = 0
        total = 0

        with torch.no_grad():
            for batch in val_loader:
                # Move batch to device
                if isinstance(batch, (list, tuple)):
                    inputs = batch[0].to(self.device)
                    targets = batch[1].to(self.device)
                else:
                    inputs = batch['input'].to(self.device)
                    targets = batch['target'].to(self.device)

                # Forward pass
                outputs = self.model(inputs)

                # Handle multi-output models
                if isinstance(outputs, tuple):
                    outputs = outputs[0]

                loss = self.criterion(outputs, targets)

                # Track metrics
                total_loss += loss.item()
                _, predicted = outputs.max(1)
                total += targets.size(0)
                correct += predicted.eq(targets).sum().item()

        avg_loss = total_loss / len(val_loader) if len(val_loader) > 0 else 0.0
        accuracy = 100.0 * correct / total if total > 0 else 0.0

        return {'loss': avg_loss, 'accuracy': accuracy}

    def train(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
        num_epochs: int,
        checkpoint_dir: Optional[Path] = None,
        early_stopping_patience: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Train the model for multiple epochs.

        Args:
            train_loader: Training data loader
            val_loader: Validation data loader
            num_epochs: Number of epochs to train
            checkpoint_dir: Directory to save checkpoints
            early_stopping_patience: Stop if validation loss doesn't improve for N epochs

        Returns:
            Training history
        """
        if checkpoint_dir:
            checkpoint_dir = Path(checkpoint_dir)
            checkpoint_dir.mkdir(parents=True, exist_ok=True)

        patience_counter = 0

        for epoch in range(num_epochs):
            self.epoch = epoch + 1
            epoch_start = time.time()

            # Train
            train_metrics = self.train_epoch(train_loader)

            # Validate
            val_metrics = self.validate(val_loader)

            # Update scheduler
            if self.scheduler:
                self.scheduler.step()

            # Track history
            self.history['train_loss'].append(train_metrics['loss'])
            self.history['train_acc'].append(train_metrics['accuracy'])
            self.history['val_loss'].append(val_metrics['loss'])
            self.history['val_acc'].append(val_metrics['accuracy'])

            epoch_time = time.time() - epoch_start

            logger.info(
                f"Epoch {self.epoch}/{num_epochs} ({epoch_time:.2f}s) - "
                f"Train Loss: {train_metrics['loss']:.4f}, "
                f"Train Acc: {train_metrics['accuracy']:.2f}% - "
                f"Val Loss: {val_metrics['loss']:.4f}, "
                f"Val Acc: {val_metrics['accuracy']:.2f}%"
            )

            # Save checkpoint if validation improved
            if val_metrics['loss'] < self.best_val_loss:
                self.best_val_loss = val_metrics['loss']
                patience_counter = 0

                if checkpoint_dir:
                    self.save_checkpoint(checkpoint_dir / "best_model.pth")
                    logger.info(f"Saved best model (val_loss: {val_metrics['loss']:.4f})")
            else:
                patience_counter += 1

            # Early stopping
            if early_stopping_patience and patience_counter >= early_stopping_patience:
                logger.info(f"Early stopping after {self.epoch} epochs")
                break

            # Save periodic checkpoint
            if checkpoint_dir and (self.epoch % 10 == 0):
                self.save_checkpoint(checkpoint_dir / f"checkpoint_epoch_{self.epoch}.pth")

        return self.history

    def save_checkpoint(self, path: Path):
        """Save model checkpoint."""
        checkpoint = {
            'epoch': self.epoch,
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'best_val_loss': self.best_val_loss,
            'history': self.history,
        }

        if self.scheduler:
            checkpoint['scheduler_state_dict'] = self.scheduler.state_dict()

        torch.save(checkpoint, path)

    def load_checkpoint(self, path: Path):
        """Load model checkpoint."""
        checkpoint = torch.load(path, map_location=self.device)

        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        self.epoch = checkpoint['epoch']
        self.best_val_loss = checkpoint['best_val_loss']
        self.history = checkpoint['history']

        if self.scheduler and 'scheduler_state_dict' in checkpoint:
            self.scheduler.load_state_dict(checkpoint['scheduler_state_dict'])

"""Evaluation metrics for Ghost ML models."""

import numpy as np
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class ConfusionMatrix:
    """
    Confusion matrix for binary classification.

    Tracks true positives, false positives, true negatives, false negatives.
    """

    def __init__(self):
        self.tp = 0
        self.fp = 0
        self.tn = 0
        self.fn = 0

    def update(self, predictions: np.ndarray, targets: np.ndarray):
        """Update confusion matrix with new predictions."""
        predictions = predictions.flatten()
        targets = targets.flatten()

        self.tp += np.sum((predictions == 1) & (targets == 1))
        self.fp += np.sum((predictions == 1) & (targets == 0))
        self.tn += np.sum((predictions == 0) & (targets == 0))
        self.fn += np.sum((predictions == 0) & (targets == 1))

    def compute_metrics(self) -> Dict[str, float]:
        """Compute precision, recall, F1, accuracy."""
        precision = self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0
        recall = self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (self.tp + self.tn) / (self.tp + self.fp + self.tn + self.fn)

        return {
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'accuracy': accuracy,
            'true_positives': self.tp,
            'false_positives': self.fp,
            'true_negatives': self.tn,
            'false_negatives': self.fn,
        }

    def reset(self):
        """Reset all counters."""
        self.tp = 0
        self.fp = 0
        self.tn = 0
        self.fn = 0


def compute_metrics(
    predictions: np.ndarray,
    targets: np.ndarray,
    num_classes: int = 2,
) -> Dict[str, float]:
    """
    Compute comprehensive metrics for model evaluation.

    Args:
        predictions: Predicted labels
        targets: Ground truth labels
        num_classes: Number of classes

    Returns:
        Dictionary of metrics
    """
    predictions = predictions.flatten()
    targets = targets.flatten()

    # Overall accuracy
    accuracy = np.mean(predictions == targets)

    metrics = {'accuracy': float(accuracy)}

    # Binary classification metrics
    if num_classes == 2:
        cm = ConfusionMatrix()
        cm.update(predictions, targets)
        metrics.update(cm.compute_metrics())

    # Per-class accuracy
    for class_id in range(num_classes):
        class_mask = targets == class_id
        if class_mask.sum() > 0:
            class_acc = np.mean(predictions[class_mask] == targets[class_mask])
            metrics[f'class_{class_id}_accuracy'] = float(class_acc)

    return metrics


def compute_roc_auc(
    predictions_proba: np.ndarray,
    targets: np.ndarray,
) -> float:
    """
    Compute ROC AUC score.

    Args:
        predictions_proba: Predicted probabilities (0-1)
        targets: Binary ground truth labels

    Returns:
        ROC AUC score
    """
    from sklearn.metrics import roc_auc_score

    try:
        return float(roc_auc_score(targets, predictions_proba))
    except Exception as e:
        logger.warning(f"Could not compute ROC AUC: {e}")
        return 0.0


def precision_at_k(
    predictions_proba: np.ndarray,
    targets: np.ndarray,
    k: int = 100,
) -> float:
    """
    Compute precision at top K predictions.

    Useful for detection systems where we care about top alerts.

    Args:
        predictions_proba: Predicted probabilities
        targets: Ground truth labels
        k: Number of top predictions to consider

    Returns:
        Precision at K
    """
    # Get indices of top K predictions
    top_k_indices = np.argsort(predictions_proba)[-k:]

    # Compute precision on top K
    top_k_targets = targets[top_k_indices]
    precision = np.mean(top_k_targets == 1)

    return float(precision)

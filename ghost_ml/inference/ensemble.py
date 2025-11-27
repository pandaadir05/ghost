"""Ensemble prediction for combining multiple models."""

import logging
from typing import List, Dict, Optional
import numpy as np
import torch

from .engine import InferenceEngine

logger = logging.getLogger(__name__)


class EnsemblePredictor:
    """
    Ensemble predictor that combines multiple models.

    Supports various ensemble strategies for improved accuracy.
    """

    def __init__(
        self,
        engines: List[InferenceEngine],
        weights: Optional[List[float]] = None,
        strategy: str = "voting",
    ):
        """
        Args:
            engines: List of InferenceEngine instances
            weights: Optional weights for weighted voting
            strategy: Ensemble strategy ("voting", "weighted", "stacking")
        """
        self.engines = engines
        self.strategy = strategy

        if weights is None:
            self.weights = [1.0 / len(engines)] * len(engines)
        else:
            assert len(weights) == len(engines), "Weights must match number of engines"
            total = sum(weights)
            self.weights = [w / total for w in weights]

    def predict(
        self,
        inputs: torch.Tensor,
        return_confidence: bool = False,
    ) -> np.ndarray:
        """
        Make ensemble prediction.

        Args:
            inputs: Input data
            return_confidence: Return confidence scores

        Returns:
            Predictions (and optionally confidences)
        """
        if self.strategy == "voting":
            return self._voting_predict(inputs, return_confidence)
        elif self.strategy == "weighted":
            return self._weighted_predict(inputs, return_confidence)
        else:
            raise ValueError(f"Unknown strategy: {self.strategy}")

    def _voting_predict(
        self,
        inputs: torch.Tensor,
        return_confidence: bool,
    ) -> np.ndarray:
        """
        Majority voting ensemble.

        Each model votes for a class, final prediction is the majority.
        """
        all_predictions = []

        for engine in self.engines:
            predictions = engine.predict(inputs, return_probs=False)
            all_predictions.append(predictions)

        all_predictions = np.array(all_predictions)

        # Majority vote
        final_predictions = np.apply_along_axis(
            lambda x: np.bincount(x).argmax(),
            axis=0,
            arr=all_predictions
        )

        if return_confidence:
            # Confidence is fraction of models that agree
            confidences = np.apply_along_axis(
                lambda x: np.bincount(x).max() / len(x),
                axis=0,
                arr=all_predictions
            )
            return final_predictions, confidences

        return final_predictions

    def _weighted_predict(
        self,
        inputs: torch.Tensor,
        return_confidence: bool,
    ) -> np.ndarray:
        """
        Weighted ensemble using probability distributions.

        Combines model probabilities with weights.
        """
        all_probs = []

        for engine in self.engines:
            probs = engine.predict(inputs, return_probs=True)
            all_probs.append(probs)

        # Weighted average of probabilities
        weighted_probs = np.zeros_like(all_probs[0])
        for probs, weight in zip(all_probs, self.weights):
            weighted_probs += probs * weight

        # Final prediction
        final_predictions = weighted_probs.argmax(axis=1)

        if return_confidence:
            confidences = weighted_probs.max(axis=1)
            return final_predictions, confidences

        return final_predictions

    def evaluate_individual_models(
        self,
        inputs: torch.Tensor,
        targets: np.ndarray,
    ) -> Dict[int, Dict[str, float]]:
        """
        Evaluate each model individually.

        Returns:
            Dictionary mapping model index to metrics
        """
        results = {}

        for idx, engine in enumerate(self.engines):
            predictions = engine.predict(inputs)
            accuracy = np.mean(predictions == targets)

            results[idx] = {
                'accuracy': float(accuracy),
                'num_predictions': len(predictions),
            }

        return results

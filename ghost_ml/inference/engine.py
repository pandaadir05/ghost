"""Optimized inference engine for production deployment."""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Union
import time

import torch
import torch.nn as nn
import numpy as np

logger = logging.getLogger(__name__)


class InferenceEngine:
    """
    High-performance inference engine for Ghost ML models.

    Handles model loading, batching, and optimized inference for production.
    """

    def __init__(
        self,
        model: nn.Module,
        device: str = "cpu",
        enable_fp16: bool = False,
        compile_model: bool = False,
    ):
        """
        Args:
            model: PyTorch model
            device: Device to run inference on
            enable_fp16: Enable FP16 inference for speed
            compile_model: Use torch.compile for optimization
        """
        self.device = device
        self.model = model.to(device)
        self.model.eval()
        self.enable_fp16 = enable_fp16

        # Apply optimizations
        if enable_fp16 and device != "cpu":
            self.model = self.model.half()
            logger.info("Enabled FP16 inference")

        if compile_model and hasattr(torch, 'compile'):
            try:
                self.model = torch.compile(self.model)
                logger.info("Model compiled with torch.compile")
            except Exception as e:
                logger.warning(f"Could not compile model: {e}")

        self.inference_times = []

    @torch.no_grad()
    def predict(
        self,
        inputs: Union[torch.Tensor, np.ndarray, List],
        return_probs: bool = False,
        batch_size: Optional[int] = None,
    ) -> np.ndarray:
        """
        Run inference on inputs.

        Args:
            inputs: Input data (tensor, numpy array, or list)
            return_probs: Return probabilities instead of class predictions
            batch_size: Batch size for processing (None = all at once)

        Returns:
            Predictions as numpy array
        """
        # Convert inputs to tensor
        if isinstance(inputs, np.ndarray):
            inputs = torch.from_numpy(inputs)
        elif isinstance(inputs, list):
            inputs = torch.tensor(inputs)

        inputs = inputs.to(self.device)

        if self.enable_fp16 and self.device != "cpu":
            inputs = inputs.half()

        # Handle batching
        if batch_size is None or len(inputs) <= batch_size:
            return self._predict_batch(inputs, return_probs)
        else:
            return self._predict_batched(inputs, batch_size, return_probs)

    def _predict_batch(
        self,
        inputs: torch.Tensor,
        return_probs: bool,
    ) -> np.ndarray:
        """Process a single batch."""
        start_time = time.time()

        outputs = self.model(inputs)

        # Handle multi-output models
        if isinstance(outputs, tuple):
            outputs = outputs[0]

        if return_probs:
            probs = torch.softmax(outputs, dim=1)
            result = probs.cpu().numpy()
        else:
            predictions = outputs.argmax(dim=1)
            result = predictions.cpu().numpy()

        inference_time = time.time() - start_time
        self.inference_times.append(inference_time)

        return result

    def _predict_batched(
        self,
        inputs: torch.Tensor,
        batch_size: int,
        return_probs: bool,
    ) -> np.ndarray:
        """Process inputs in batches."""
        results = []

        for i in range(0, len(inputs), batch_size):
            batch = inputs[i:i + batch_size]
            batch_results = self._predict_batch(batch, return_probs)
            results.append(batch_results)

        return np.concatenate(results, axis=0)

    @torch.no_grad()
    def predict_with_confidence(
        self,
        inputs: Union[torch.Tensor, np.ndarray],
        batch_size: Optional[int] = None,
    ) -> tuple[np.ndarray, np.ndarray]:
        """
        Predict class and confidence score.

        Returns:
            Tuple of (predictions, confidence_scores)
        """
        probs = self.predict(inputs, return_probs=True, batch_size=batch_size)
        predictions = probs.argmax(axis=1)
        confidences = probs.max(axis=1)

        return predictions, confidences

    def get_inference_stats(self) -> Dict[str, float]:
        """Get inference performance statistics."""
        if not self.inference_times:
            return {}

        times = np.array(self.inference_times)
        return {
            'mean_inference_time': float(np.mean(times)),
            'median_inference_time': float(np.median(times)),
            'min_inference_time': float(np.min(times)),
            'max_inference_time': float(np.max(times)),
            'total_inferences': len(times),
        }

    def reset_stats(self):
        """Reset inference statistics."""
        self.inference_times = []

    @classmethod
    def from_checkpoint(
        cls,
        checkpoint_path: Union[str, Path],
        model_class: type,
        device: str = "cpu",
        **kwargs,
    ) -> "InferenceEngine":
        """
        Load model from checkpoint.

        Args:
            checkpoint_path: Path to checkpoint file
            model_class: Model class to instantiate
            device: Device to load model on
            **kwargs: Additional arguments for InferenceEngine

        Returns:
            InferenceEngine instance
        """
        checkpoint = torch.load(checkpoint_path, map_location=device)

        # Instantiate model
        model = model_class()

        # Load state dict
        if 'model_state_dict' in checkpoint:
            model.load_state_dict(checkpoint['model_state_dict'])
        else:
            model.load_state_dict(checkpoint)

        return cls(model, device=device, **kwargs)


class BatchInferenceEngine:
    """
    Specialized engine for high-throughput batch inference.

    Optimized for processing large numbers of samples.
    """

    def __init__(
        self,
        model: nn.Module,
        device: str = "cpu",
        max_batch_size: int = 64,
    ):
        self.engine = InferenceEngine(model, device=device)
        self.max_batch_size = max_batch_size

    def process_stream(
        self,
        data_stream: List[np.ndarray],
        batch_size: Optional[int] = None,
    ) -> List[np.ndarray]:
        """
        Process a stream of data samples.

        Args:
            data_stream: List of input samples
            batch_size: Batch size (defaults to max_batch_size)

        Returns:
            List of predictions
        """
        if batch_size is None:
            batch_size = self.max_batch_size

        results = []
        current_batch = []

        for sample in data_stream:
            current_batch.append(sample)

            if len(current_batch) >= batch_size:
                batch_tensor = torch.stack([torch.from_numpy(s) for s in current_batch])
                predictions = self.engine.predict(batch_tensor)
                results.extend(predictions)
                current_batch = []

        # Process remaining samples
        if current_batch:
            batch_tensor = torch.stack([torch.from_numpy(s) for s in current_batch])
            predictions = self.engine.predict(batch_tensor)
            results.extend(predictions)

        return results

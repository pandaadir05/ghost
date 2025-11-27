# Ghost ML - Neural Memory Machine Learning Models

This package provides machine learning models for the Ghost framework's neural memory analyzer.

## Models

1. **ShellcodeCNN** - Convolutional Neural Network for shellcode detection
2. **PolymorphicTransformer** - Transformer model for polymorphic code analysis
3. **EvasionGNN** - Graph Neural Network for evasion technique detection

## Installation

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install dragonslayer ML framework (if not already installed)
cd ../dragonslayer
pip install -e .
```

## Training Models

```bash
# Train all models
python scripts/train_neural_models.py --output-dir models --num-samples 1000

# Train specific model
python scripts/train_neural_models.py --model cnn --output-dir models
```

## Usage

The models are automatically loaded by the Rust codebase via the `ml_bridge` module when the `neural-ml` feature is enabled.

## Integration with Dragonslayer

This package uses the dragonslayer ML framework for:
- Model training infrastructure (`ModelTrainer`, `TrainingConfig`)
- Model management (`MLModel`, `ModelRegistry`)
- Feature extraction patterns
- Ensemble methods


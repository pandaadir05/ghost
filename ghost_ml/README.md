# Ghost ML

Python ML models for Ghost memory analysis.

## Models

- **ShellcodeCNN**: Convolutional neural network for shellcode detection
- **PolymorphicTransformer**: Transformer-based model for polymorphic code analysis
- **EvasionGNN**: Graph neural network for evasion technique detection

## Installation

```bash
pip install -r requirements.txt
```

## Usage

The models are called from Rust via the ML bridge. They analyze memory regions
and return threat assessments, detected patterns, and evasion techniques.

## Training

Models require training with real malware samples before production use.
The architecture is provided; training data must be sourced separately.


"""
Mutation Engine
===============

Implement mutation strategy for fuzzing.
This do the smart change to input for find bug.
"""

from enum import Enum
from typing import List
import random


class MutationStrategy(Enum):
    """Different way to mutate the input."""
    BIT_FLIP = "bit_flip"
    BYTE_FLIP = "byte_flip"
    ARITHMETIC = "arithmetic"
    INTERESTING_VALUES = "interesting"
    BLOCK_DELETION = "block_delete"
    BLOCK_DUPLICATION = "block_dup"
    SPLICE = "splice"
    HAVOC = "havoc"


class MutationEngine:
    """
    Mutation engine for fuzzing.
    
    Use many technique from AFL and other fuzzer.
    This was describe in presentation but code was fake.
    """
    
    # Interesting value that often cause problem
    INTERESTING_8 = [-128, -1, 0, 1, 16, 32, 64, 100, 127]
    INTERESTING_16 = [-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767]
    INTERESTING_32 = [-2147483648, -100663046, -32768, 0, 32767, 65535, 100663045, 2147483647]
    
    def __init__(self, seed: int = None):
        """Initialize mutation engine with optional seed."""
        if seed is not None:
            random.seed(seed)
        self.strategies = list(MutationStrategy)
        
    def mutate(self, data: bytes, strategy: MutationStrategy = None) -> bytes:
        """
        Apply mutation to input data.
        
        If strategy not specify, pick random one.
        Return mutated data as bytes.
        """
        if not data:
            return data
            
        if strategy is None:
            strategy = random.choice(self.strategies)
            
        # Map strategy to function
        mutation_map = {
            MutationStrategy.BIT_FLIP: self._bit_flip,
            MutationStrategy.BYTE_FLIP: self._byte_flip,
            MutationStrategy.ARITHMETIC: self._arithmetic,
            MutationStrategy.INTERESTING_VALUES: self._interesting_values,
            MutationStrategy.BLOCK_DELETION: self._block_delete,
            MutationStrategy.BLOCK_DUPLICATION: self._block_duplicate,
            MutationStrategy.SPLICE: self._splice,
            MutationStrategy.HAVOC: self._havoc,
        }
        
        mutator = mutation_map.get(strategy)
        if mutator:
            return mutator(data)
        return data
        
    def _bit_flip(self, data: bytes) -> bytes:
        """Flip single random bit in data."""
        if not data:
            return data
            
        data = bytearray(data)
        pos = random.randint(0, len(data) - 1)
        bit = random.randint(0, 7)
        data[pos] ^= (1 << bit)
        return bytes(data)
        
    def _byte_flip(self, data: bytes) -> bytes:
        """Flip entire byte (XOR with 0xFF)."""
        if not data:
            return data
            
        data = bytearray(data)
        pos = random.randint(0, len(data) - 1)
        data[pos] ^= 0xFF
        return bytes(data)
        
    def _arithmetic(self, data: bytes) -> bytes:
        """
        Apply arithmetic operation to random byte.
        Add or subtract small value.
        """
        if not data:
            return data
            
        data = bytearray(data)
        pos = random.randint(0, len(data) - 1)
        
        # Pick random delta value
        delta = random.choice([-35, -16, -8, -4, -1, 1, 4, 8, 16, 35])
        data[pos] = (data[pos] + delta) & 0xFF
        
        return bytes(data)
        
    def _interesting_values(self, data: bytes) -> bytes:
        """
        Replace byte/word/dword with interesting value.
        These value often cause problem in program.
        """
        if not data:
            return data
            
        data = bytearray(data)
        pos = random.randint(0, len(data) - 1)
        
        # Pick size: 1, 2, or 4 byte
        size = random.choice([1, 2, 4])
        
        if size == 1:
            value = random.choice(self.INTERESTING_8)
            data[pos] = value & 0xFF
        elif size == 2 and pos < len(data) - 1:
            value = random.choice(self.INTERESTING_16)
            data[pos] = value & 0xFF
            data[pos + 1] = (value >> 8) & 0xFF
        elif size == 4 and pos < len(data) - 3:
            value = random.choice(self.INTERESTING_32)
            for i in range(4):
                data[pos + i] = (value >> (i * 8)) & 0xFF
                
        return bytes(data)
        
    def _block_delete(self, data: bytes) -> bytes:
        """Delete random block from input."""
        if len(data) < 4:
            return data
            
        start = random.randint(0, len(data) - 2)
        end = random.randint(start + 1, min(start + 32, len(data)))
        
        return data[:start] + data[end:]
        
    def _block_duplicate(self, data: bytes) -> bytes:
        """Duplicate random block in input."""
        if len(data) < 4:
            return data
            
        start = random.randint(0, len(data) - 2)
        end = random.randint(start + 1, min(start + 32, len(data)))
        block = data[start:end]
        
        return data[:start] + block + block + data[end:]
        
    def _splice(self, data: bytes) -> bytes:
        """
        Splice two part of input together.
        Not very useful without corpus but implement anyway.
        """
        if len(data) < 8:
            return data
            
        cut = random.randint(1, len(data) - 1)
        return data[cut:] + data[:cut]
        
    def _havoc(self, data: bytes) -> bytes:
        """
        Apply multiple random mutation.
        This is aggressive strategy for find deep bug.
        """
        num_mutations = random.randint(2, 8)
        
        for _ in range(num_mutations):
            strategy = random.choice([
                MutationStrategy.BIT_FLIP,
                MutationStrategy.BYTE_FLIP,
                MutationStrategy.ARITHMETIC,
                MutationStrategy.INTERESTING_VALUES,
            ])
            data = self.mutate(data, strategy)
            
        return data

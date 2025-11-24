"""
Input Generator
===============

Generate test input for fuzzing using various strategy.
This can create input from scratch or from grammar.
"""

from typing import List, Dict, Optional, Callable
import random
import struct


class InputGenerator:
    """
    Generate test input for fuzzing.
    
    Support different generation strategy:
    - Random generation
    - Grammar-based generation
    - Template-based generation
    - Protocol-aware generation
    """
    
    def __init__(self, seed: Optional[int] = None):
        """Initialize input generator with optional seed."""
        if seed is not None:
            random.seed(seed)
            
        self.templates: List[bytes] = []
        self.grammar: Optional[Dict] = None
        
    def generate_random(self, size: int) -> bytes:
        """Generate completely random input of specify size."""
        return bytes(random.randint(0, 255) for _ in range(size))
        
    def generate_from_template(self, template: bytes, mutate: bool = True) -> bytes:
        """
        Generate input from template.
        
        Optionally mutate some byte for variation.
        """
        result = bytearray(template)
        
        if mutate:
            # Mutate random position
            num_mutations = random.randint(1, max(1, len(result) // 10))
            for _ in range(num_mutations):
                pos = random.randint(0, len(result) - 1)
                result[pos] = random.randint(0, 255)
                
        return bytes(result)
        
    def generate_structured(self, size: int) -> bytes:
        """
        Generate structured input with common pattern.
        
        Include thing like:
        - Magic number
        - Length field
        - Checksum
        - Padding
        """
        data = bytearray()
        
        # Add magic number
        magic = random.choice([
            b'MZ',      # PE header
            b'ELF',     # ELF header
            b'\x7fELF', # ELF with signature
            b'PK',      # ZIP
            b'\x89PNG', # PNG
            b'\xff\xd8\xff', # JPEG
        ])
        data.extend(magic)
        
        # Add length field
        remaining = size - len(data) - 4
        if remaining > 0:
            data.extend(struct.pack('<I', remaining))
            
        # Fill with random data
        while len(data) < size:
            data.append(random.randint(0, 255))
            
        return bytes(data[:size])
        
    def generate_from_grammar(self, grammar: Dict, start_symbol: str = "start") -> bytes:
        """
        Generate input from grammar specification.
        
        Grammar is dictionary with production rule.
        This allow generate protocol-aware input.
        
        Grammar format:
        {
            "start": ["<header><body>"],
            "header": ["GET ", "POST "],
            "body": ["<path> HTTP/1.1\r\n\r\n"],
            "path": ["/", "/api", "/admin"],
        }
        """
        if not grammar or start_symbol not in grammar:
            return b""
            
        result = self._expand_symbol(start_symbol, grammar, depth=0, max_depth=10)
        
        return result.encode('utf-8', errors='ignore')
        
    def _expand_symbol(self, symbol: str, grammar: Dict, depth: int, max_depth: int) -> str:
        """Recursively expand grammar symbol."""
        if depth >= max_depth:
            return ""
            
        # Check if terminal (no < >)
        if not symbol.startswith("<") or not symbol.endswith(">"):
            return symbol
            
        # Get production rule
        symbol_name = symbol[1:-1]  # Remove < >
        
        if symbol_name not in grammar:
            return symbol
            
        # Pick random production
        productions = grammar[symbol_name]
        if not productions:
            return ""
            
        production = random.choice(productions)
        
        # Expand each part
        result = ""
        i = 0
        while i < len(production):
            if production[i] == '<':
                # Find end of symbol
                end = production.find('>', i)
                if end == -1:
                    result += production[i:]
                    break
                    
                # Expand symbol
                subsymbol = production[i:end+1]
                result += self._expand_symbol(subsymbol, grammar, depth + 1, max_depth)
                i = end + 1
            else:
                result += production[i]
                i += 1
                
        return result
        
    def add_template(self, template: bytes):
        """Add template for generation."""
        self.templates.append(template)
        
    def generate_ebpf(self, num_instructions: int) -> bytes:
        """
        Generate eBPF bytecode for fuzzing.
        
        eBPF instructions are 8 bytes each with format:
        opcode(1) | dst(1) | src(1) | offset(2) | imm(4)
        
        This generate random but structurally valid eBPF instructions.
        """
        bytecode = bytearray()
        
        for _ in range(num_instructions):
            # Generate random eBPF instruction
            opcode = random.randint(0, 255)  # Any opcode, including invalid ones for fuzzing
            
            # Registers 0-10 are valid, but allow invalid for fuzzing
            dst_reg = random.randint(0, 15)
            src_reg = random.randint(0, 15)
            
            # Offset can be any 16-bit value
            offset = random.randint(0, 65535)
            
            # Immediate can be any 32-bit value
            imm = random.randint(-2147483648, 2147483647)
            
            # Pack into 8 bytes (little endian)
            instruction = struct.pack('<BBHi', opcode, (dst_reg & 0xF) | ((src_reg & 0xF) << 4), offset, imm)
            bytecode.extend(instruction)
            
        return bytes(bytecode)

"""
Corpus Manager
==============

Manage test case corpus for fuzzing.
Keep track of interesting input that give new coverage.
"""

from typing import List, Set, Dict, Optional
from dataclasses import dataclass
import os
import hashlib


@dataclass
class CorpusEntry:
    """Single entry in corpus."""
    data: bytes
    coverage: Set[int]
    input_hash: str
    size: int
    added_timestamp: float


class CorpusManager:
    """
    Manage corpus of test input.
    
    Keep only input that give unique coverage.
    This prevent corpus from grow too big.
    """
    
    def __init__(self, corpus_dir: str = "corpus", max_size: int = 10000):
        """
        Initialize corpus manager.
        
        Args:
            corpus_dir: Directory to store corpus
            max_size: Maximum number of input to keep
        """
        self.corpus_dir = corpus_dir
        self.max_size = max_size
        self.entries: List[CorpusEntry] = []
        self.seen_hashes: Set[str] = set()
        self.total_coverage: Set[int] = set()
        
        os.makedirs(corpus_dir, exist_ok=True)
        
    def add_input(self, data: bytes, coverage: Set[int], timestamp: float = 0.0) -> bool:
        """
        Add input to corpus if it provide new coverage.
        
        Return True if added, False if reject.
        """
        # Check if we already have this input
        input_hash = hashlib.sha256(data).hexdigest()
        if input_hash in self.seen_hashes:
            return False
            
        # Check if provide new coverage
        new_coverage = coverage - self.total_coverage
        if not new_coverage and len(self.entries) > 0:
            return False
            
        # Add to corpus
        entry = CorpusEntry(
            data=data,
            coverage=coverage,
            input_hash=input_hash,
            size=len(data),
            added_timestamp=timestamp
        )
        
        self.entries.append(entry)
        self.seen_hashes.add(input_hash)
        self.total_coverage.update(coverage)
        
        # Save to disk
        self._save_entry(entry, len(self.entries) - 1)
        
        # Check if need to trim corpus
        if len(self.entries) > self.max_size:
            self._trim_corpus()
            
        return True
        
    def get_random_input(self) -> Optional[bytes]:
        """Get random input from corpus."""
        if not self.entries:
            return None
            
        import random
        entry = random.choice(self.entries)
        return entry.data
        
    def get_all_inputs(self) -> List[bytes]:
        """Get all input from corpus."""
        return [entry.data for entry in self.entries]
        
    def load_from_directory(self, directory: str) -> int:
        """
        Load corpus from directory.
        Return number of input loaded.
        """
        if not os.path.exists(directory):
            return 0
            
        count = 0
        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)
            if os.path.isfile(filepath):
                try:
                    with open(filepath, 'rb') as f:
                        data = f.read()
                    
                    # Add with empty coverage (will be updated later)
                    input_hash = hashlib.sha256(data).hexdigest()
                    if input_hash not in self.seen_hashes:
                        entry = CorpusEntry(
                            data=data,
                            coverage=set(),
                            input_hash=input_hash,
                            size=len(data),
                            added_timestamp=0.0
                        )
                        self.entries.append(entry)
                        self.seen_hashes.add(input_hash)
                        count += 1
                except:
                    pass
                    
        return count
        
    def _save_entry(self, entry: CorpusEntry, index: int):
        """Save corpus entry to disk."""
        filename = f"input_{index:06d}"
        filepath = os.path.join(self.corpus_dir, filename)
        
        try:
            with open(filepath, 'wb') as f:
                f.write(entry.data)
        except:
            pass
            
    def _trim_corpus(self):
        """
        Trim corpus to max size.
        
        Remove entry that provide least unique coverage.
        This is simple heuristic, can be improve.
        """
        if len(self.entries) <= self.max_size:
            return
            
        # Sort by size of unique coverage
        # Keep input that cover most unique block
        
        # For now just keep first max_size entry
        # Better algorithm would minimize corpus while keep coverage
        self.entries = self.entries[:self.max_size]
        
    def get_stats(self) -> Dict:
        """Get statistics about corpus."""
        if not self.entries:
            return {
                'total_inputs': 0,
                'total_coverage': 0,
                'avg_size': 0,
                'min_size': 0,
                'max_size': 0
            }
            
        sizes = [entry.size for entry in self.entries]
        
        return {
            'total_inputs': len(self.entries),
            'total_coverage': len(self.total_coverage),
            'avg_size': sum(sizes) / len(sizes),
            'min_size': min(sizes),
            'max_size': max(sizes)
        }

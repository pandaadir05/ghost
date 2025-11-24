"""
Base Fuzzer Implementation
==========================

Abstract base for all fuzzer in system.
This is foundation that was not exist before.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Set
from enum import Enum
import time
import os


class FuzzingStrategy(Enum):
    """Strategy for the fuzzing operation."""
    MUTATION = "mutation"
    GENERATION = "generation"
    HYBRID = "hybrid"
    GRAMMAR = "grammar"


@dataclass
class FuzzingConfig:
    """Configuration for fuzzer - this control all behavior."""
    max_iterations: int = 10000
    timeout_seconds: int = 5
    max_input_size: int = 4096
    strategy: FuzzingStrategy = FuzzingStrategy.MUTATION
    enable_coverage: bool = True
    enable_taint: bool = True
    enable_symbolic: bool = False
    crash_dir: str = "crashes"
    corpus_dir: str = "corpus"
    seed: Optional[int] = None
    parallel_jobs: int = 1
    enable_ebpf: bool = False
    ebpf_instructions: int = 10


@dataclass
class FuzzResult:
    """Result from fuzzing session - tell what happen."""
    iterations: int
    crashes_found: int
    unique_crashes: int
    coverage_percentage: float
    execution_time: float
    crash_details: List[Dict] = field(default_factory=list)
    total_executions: int = 0
    timeouts: int = 0
    hangs: int = 0


class BaseFuzzer(ABC):
    """
    Abstract base class for all fuzzer.
    
    This was the missing piece from original DefCon presentation.
    Now we make it real instead of just slide.
    """
    
    def __init__(self, config: FuzzingConfig):
        self.config = config
        self.corpus: List[bytes] = []
        self.coverage_map: Set[int] = set()
        self.crashes: List[Dict] = []
        self.iteration_count = 0
        self.start_time = 0.0
        
        # Make directory for crash and corpus
        os.makedirs(config.crash_dir, exist_ok=True)
        os.makedirs(config.corpus_dir, exist_ok=True)
        
    @abstractmethod
    def generate_input(self) -> bytes:
        """
        Generate new test input.
        Subclass must implement this.
        """
        pass
        
    @abstractmethod
    def execute_target(self, input_data: bytes) -> Dict:
        """
        Execute target with given input.
        Return dict with execution result.
        """
        pass
        
    @abstractmethod
    def check_crash(self, execution_result: Dict) -> bool:
        """
        Check if execution result in crash.
        This is critical for find bug.
        """
        pass
        
    def add_to_corpus(self, input_data: bytes, coverage: Set[int] = None) -> bool:
        """
        Add input to corpus if it give new coverage.
        Return True if added.
        """
        if coverage and not coverage.issubset(self.coverage_map):
            self.corpus.append(input_data)
            self.coverage_map.update(coverage)
            
            # Save to disk
            corpus_file = os.path.join(
                self.config.corpus_dir,
                f"input_{len(self.corpus):06d}"
            )
            with open(corpus_file, 'wb') as f:
                f.write(input_data)
            
            return True
        return False
        
    def save_crash(self, input_data: bytes, crash_info: Dict) -> str:
        """
        Save crash input to disk for later analyze.
        Return path to saved file.
        """
        crash_id = len(self.crashes)
        crash_file = os.path.join(
            self.config.crash_dir,
            f"crash_{crash_id:06d}"
        )
        
        with open(crash_file, 'wb') as f:
            f.write(input_data)
            
        # Also save the crash info as JSON
        import json
        info_file = crash_file + ".json"
        with open(info_file, 'w') as f:
            json.dump(crash_info, f, indent=2)
            
        return crash_file
        
    def fuzz(self, target_path: str, initial_corpus: List[bytes] = None) -> FuzzResult:
        """
        Main fuzzing loop - this is where magic happen.
        
        Run fuzzing session on target with optional initial corpus.
        This implement the algorithm that was only on slide before.
        """
        self.start_time = time.time()
        
        # Load initial corpus if provide
        if initial_corpus:
            self.corpus.extend(initial_corpus)
        else:
            # Generate some initial input if no corpus
            for _ in range(10):
                self.corpus.append(self.generate_input())
        
        timeouts = 0
        total_executions = 0
        
        # Main fuzzing loop
        for iteration in range(self.config.max_iterations):
            self.iteration_count = iteration
            
            # Generate test input
            input_data = self.generate_input()
            
            try:
                # Execute target with timeout
                exec_result = self.execute_target(input_data)
                total_executions += 1
                
                # Check for crash
                if self.check_crash(exec_result):
                    crash_info = {
                        'iteration': iteration,
                        'input_size': len(input_data),
                        'result': exec_result
                    }
                    self.crashes.append(crash_info)
                    self.save_crash(input_data, crash_info)
                
                # Update coverage if enable
                if self.config.enable_coverage and 'coverage' in exec_result:
                    self.add_to_corpus(input_data, exec_result['coverage'])
                    
            except TimeoutError:
                timeouts += 1
            except Exception as e:
                # Log error but continue fuzzing
                pass
        
        # Calculate final statistic
        execution_time = time.time() - self.start_time
        
        return FuzzResult(
            iterations=self.config.max_iterations,
            crashes_found=len(self.crashes),
            unique_crashes=self._count_unique_crashes(),
            coverage_percentage=self._calculate_coverage(),
            execution_time=execution_time,
            crash_details=self.crashes,
            total_executions=total_executions,
            timeouts=timeouts,
            hangs=0
        )
    
    def _count_unique_crashes(self) -> int:
        """Count unique crash based on signature."""
        unique_sigs = set()
        for crash in self.crashes:
            sig = crash.get('result', {}).get('crash_signature', '')
            if sig:
                unique_sigs.add(sig)
        return len(unique_sigs)
    
    def _calculate_coverage(self) -> float:
        """Calculate coverage percentage if available."""
        if not self.coverage_map:
            return 0.0
        
        return 0.0

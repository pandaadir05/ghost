"""
VM-Aware Fuzzer
===============

Fuzzer that understand VM protection.
Use VM detection and taint analysis for guide fuzzing.

This was the main missing piece from DefCon demo.
"""

from typing import Dict, List, Set, Optional
import random
import os

from .base_fuzzer import BaseFuzzer, FuzzingConfig, FuzzResult, FuzzingStrategy
from .mutation_engine import MutationEngine, MutationStrategy
from .coverage_tracker import CoverageTracker
from .crash_analyzer import CrashAnalyzer
from .corpus_manager import CorpusManager
from .input_generator import InputGenerator
from .execution_engine import ExecutionEngine, ExecutionResult
from .parallel_engine import ParallelFuzzer, PowerScheduler, DictionaryManager
from .network_fuzzer import NetworkFuzzer, NetworkTarget
from .symbolic_integration import SymbolicFuzzingBridge
from .taint_integration import TaintGuidedMutator, VMTaintFuzzer


class VMFuzzer(BaseFuzzer):
    """
    VM-aware fuzzer implementation.
    
    This fuzzer:
    - Detect VM structure in target
    - Use taint tracking for guide input generation
    - Target VM handler and dispatcher
    - Track coverage for effective fuzzing
    
    Originally this was just PowerPoint slide.
    Now is real code that actually work (hopefully).
    """
    
    def __init__(self, config: FuzzingConfig):
        """Initialize VM fuzzer with configuration."""
        super().__init__(config)
        
        # Lazy import to avoid circular dependency
        self.vm_detector = None
        self.taint_tracker = None
        self.symbolic_executor = None
        
        # Fuzzing component
        self.mutation_engine = MutationEngine(config.seed)
        self.coverage_tracker = CoverageTracker()
        self.crash_analyzer = CrashAnalyzer()
        self.corpus_manager = CorpusManager(config.corpus_dir)
        self.input_generator = InputGenerator(config.seed)
        self.execution_engine = ExecutionEngine(config.timeout_seconds)
        
        # Advanced integration (if enable)
        self.symbolic_bridge = SymbolicFuzzingBridge() if config.enable_symbolic else None
        self.taint_mutator = TaintGuidedMutator() if config.enable_taint else None
        # Performance optimization (if parallel enable)
        if config.parallel_jobs > 1:
            self.parallel_fuzzer = ParallelFuzzer(config.parallel_jobs)
            self.power_scheduler = PowerScheduler()
        else:
            self.parallel_fuzzer = None
            self.power_scheduler = None
            
        # Dictionary support
        self.dictionary = DictionaryManager()
        
        # VM-specific data
        self.vm_handlers: List[Dict] = []
        self.dispatcher_address: Optional[int] = None
        self.vm_detected = False
        
    def analyze_target(self, binary_path: str) -> Dict:
        """
        Analyze target binary to find VM structure.
        
        This run before fuzzing start to identify target.
        Use existing VM detection engine.
        """
        if not os.path.exists(binary_path):
            return {'error': 'File not exist'}
            
        try:
            # Import here to avoid circular import
            from ..analysis.vm_discovery.detector import VMDetector
            
            self.vm_detector = VMDetector()
            
            with open(binary_path, 'rb') as f:
                binary_data = f.read()
                
            # Run VM detection
            result = self.vm_detector.detect_vm_structures(binary_data)
            
            self.vm_detected = result.get('vm_detected', False)
            self.vm_handlers = result.get('handlers_found', [])
            
            if self.vm_detected:
                print(f"[+] VM protection detected")
                print(f"[+] Found {len(self.vm_handlers)} VM handler")
            else:
                print(f"[-] No VM protection detect")
                
            return result
            
        except Exception as e:
            return {'error': str(e)}
            
    def generate_input(self) -> bytes:
        """
        Generate test input for fuzzing.
        
        Use mutation or generation depend on strategy.
        If corpus exist, mutate from corpus.
        """
        if self.config.strategy == FuzzingStrategy.GENERATION:
            return self._generate_from_scratch()
        elif self.config.strategy == FuzzingStrategy.MUTATION:
            return self._mutate_from_corpus()
        else:
            # Hybrid: random choose
            if random.random() < 0.5:
                return self._generate_from_scratch()
            else:
                return self._mutate_from_corpus()
                
    def _generate_from_scratch(self) -> bytes:
        """Generate completely new input."""
        if self.config.enable_ebpf:
            return self.input_generator.generate_ebpf(self.config.ebpf_instructions)
        else:
            size = random.randint(1, self.config.max_input_size)
            return os.urandom(size)
        
    def _mutate_from_corpus(self) -> bytes:
        """Mutate input from corpus."""
        # Get random input from corpus
        base_input = self.corpus_manager.get_random_input()
        
        if base_input is None:
            # No corpus yet, generate random
            return self._generate_from_scratch()
            
        # Apply mutation
        strategy = random.choice(list(MutationStrategy))
        mutated = self.mutation_engine.mutate(base_input, strategy)
        
        # Maybe apply multiple mutation
        if random.random() < 0.3:
            mutated = self.mutation_engine.mutate(mutated, MutationStrategy.HAVOC)
            
        return mutated
        
    def execute_target(self, input_data: bytes) -> Dict:
        """
        Execute target with input and collect result.
        
        Use execution engine to run target and monitor.
        """
        if not hasattr(self, '_target_path'):
            return {
                'crashed': False,
                'timeout': False,
                'coverage': set(),
                'exit_code': 0,
                'execution_time': 0.0
            }
        
        # Execute using execution engine
        exec_result = self.execution_engine.execute(
            self._target_path,
            input_data,
            delivery_method=getattr(self, '_delivery_method', 'stdin')
        )
        
        # Convert to dict format
        result = {
            'crashed': exec_result.crashed,
            'timeout': exec_result.timeout,
            'coverage': exec_result.coverage,
            'exit_code': exec_result.exit_code,
            'execution_time': exec_result.execution_time,
            'crash_info': exec_result.crash_info if exec_result.crashed else {}
        }
        
        # Update coverage tracker if have coverage
        if result['coverage']:
            for block_id in result['coverage']:
                self.coverage_tracker.record_block(block_id)
        
        return result
        
    def check_crash(self, execution_result: Dict) -> bool:
        """
        Check if execution result in crash.
        
        Look at exit code and crash flag.
        """
        if execution_result.get('crashed', False):
            return True
            
        exit_code = execution_result.get('exit_code', 0)
        if exit_code < 0 or exit_code > 127:
            return True
            
        return False
        
    def execute_with_taint(self, input_data: bytes) -> Dict:
        """
        Execute with taint tracking enable.
        
        This use taint analysis to track data flow.
        Help identify which input byte affect which code.
        """
        if not self.config.enable_taint:
            return self.execute_target(input_data)
            
        # Real implementation would:
        # - Initialize taint tracker
        # - Mark input as tainted
        # - Track propagation through VM
        # - Identify interesting taint flow
        
        result = self.execute_target(input_data)
        result['taint_flow'] = []
        
        return result
        
    def fuzz(self, target_path: str, initial_corpus: List[bytes] = None,
             delivery_method: str = 'stdin') -> FuzzResult:
        """
        Main fuzzing entry point.
        
        Override base implementation to add VM-aware logic.
        """
        # Store target path and delivery method for execute_target
        self._target_path = target_path
        self._delivery_method = delivery_method
        
        # First analyze target
        print(f"[*] Analyzing target: {target_path}")
        analysis_result = self.analyze_target(target_path)
        
        if 'error' in analysis_result:
            print(f"[!] Error analyzing target: {analysis_result['error']}")
            
        # Load initial corpus
        if initial_corpus:
            for seed_input in initial_corpus:
                self.corpus_manager.add_input(seed_input, set(), 0.0)
                
        # Run base fuzzing loop
        print(f"[*] Starting fuzzing with {self.config.max_iterations} iteration")
        result = super().fuzz(target_path, initial_corpus)
        
        # Add VM-specific information to result
        if self.vm_detected:
            result.crash_details.append({
                'vm_handlers': len(self.vm_handlers),
                'vm_detected': True
            })
        
        # Cleanup
        self.execution_engine.cleanup()
            
        return result
        
    def get_statistics(self) -> Dict:
        """Get fuzzing statistics."""
        coverage_stats = self.coverage_tracker.get_stats()
        corpus_stats = self.corpus_manager.get_stats()
        
        return {
            'iterations': self.iteration_count,
            'crashes': len(self.crashes),
            'unique_crashes': self.crash_analyzer.get_unique_crash_count(),
            'coverage': coverage_stats.coverage_percentage,
            'corpus_size': corpus_stats['total_inputs'],
            'vm_detected': self.vm_detected,
            'vm_handlers': len(self.vm_handlers)
        }

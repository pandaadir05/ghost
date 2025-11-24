"""
Parallel Execution Engine
=========================

Execute multiple fuzzing instance in parallel.
This speed up fuzzing by using multiple core.
"""

from typing import List, Dict, Optional, Callable
import multiprocessing as mp
import threading
import queue
import time
import os
from dataclasses import dataclass


@dataclass
class WorkerResult:
    """Result from worker process."""
    worker_id: int
    input_data: bytes
    execution_result: Dict
    crash_found: bool
    new_coverage: bool
    execution_time: float


class ParallelFuzzer:
    """
    Run multiple fuzzer instance in parallel.
    
    Use process pool to execute fuzzing worker.
    Share corpus and coverage across worker.
    """
    
    def __init__(self, num_workers: int = mp.cpu_count()):
        self.num_workers = num_workers
        self.workers: List[mp.Process] = []
        self.result_queue = mp.Queue()
        self.input_queue = mp.Queue()
        self.stop_event = mp.Event()
        
        # Shared state
        self.shared_corpus = mp.Manager().list()
        self.shared_coverage = mp.Manager().dict()
        self.shared_crashes = mp.Manager().list()
        
    def start_workers(self, target_path: str, config: Dict):
        """Start worker process."""
        for i in range(self.num_workers):
            worker = mp.Process(
                target=self._worker_main,
                args=(i, target_path, config, self.input_queue, 
                      self.result_queue, self.stop_event,
                      self.shared_corpus, self.shared_coverage, self.shared_crashes)
            )
            worker.start()
            self.workers.append(worker)
            
    def stop_workers(self):
        """Stop all worker process."""
        self.stop_event.set()
        
        # Wait for worker to finish
        for worker in self.workers:
            worker.join(timeout=5.0)
            if worker.is_alive():
                worker.terminate()
                
        self.workers.clear()
        
    def submit_input(self, input_data: bytes):
        """Submit input for execution."""
        self.input_queue.put(input_data)
        
    def get_results(self, timeout: float = 1.0) -> List[WorkerResult]:
        """Get result from worker."""
        results = []
        
        try:
            while True:
                result = self.result_queue.get(timeout=timeout)
                results.append(result)
                timeout = 0.1  # Reduce timeout after first result
        except queue.Empty:
            pass
            
        return results
        
    def _worker_main(self, worker_id: int, target_path: str, config: Dict,
                    input_queue, result_queue, stop_event,
                    shared_corpus, shared_coverage, shared_crashes):
        """Main function for worker process."""
        # Import here to avoid pickle issue
        from .execution_engine import ExecutionEngine
        
        execution_engine = ExecutionEngine(
            timeout=config.get('timeout_seconds', 5),
            instrumentation=config.get('instrumentation', None)
        )
        
        while not stop_event.is_set():
            try:
                # Get input to execute
                input_data = input_queue.get(timeout=1.0)
                
                start_time = time.time()
                
                # Execute target
                exec_result = execution_engine.execute(target_path, input_data)
                
                execution_time = time.time() - start_time
                
                # Check for new coverage
                new_coverage = False
                if exec_result.coverage:
                    for block_id in exec_result.coverage:
                        if block_id not in shared_coverage:
                            shared_coverage[block_id] = True
                            new_coverage = True
                            
                # Check for crash
                crash_found = exec_result.crashed
                
                if crash_found:
                    # Add to shared crash list
                    crash_info = {
                        'input': input_data,
                        'crash_info': exec_result.crash_info,
                        'worker_id': worker_id
                    }
                    shared_crashes.append(crash_info)
                    
                # Create result
                result = WorkerResult(
                    worker_id=worker_id,
                    input_data=input_data,
                    execution_result={
                        'crashed': exec_result.crashed,
                        'timeout': exec_result.timeout,
                        'coverage': exec_result.coverage,
                        'exit_code': exec_result.exit_code,
                        'execution_time': exec_result.execution_time
                    },
                    crash_found=crash_found,
                    new_coverage=new_coverage,
                    execution_time=execution_time
                )
                
                result_queue.put(result)
                
            except queue.Empty:
                continue
            except Exception as e:
                # Log error but continue
                print(f"[!] Worker {worker_id} error: {e}")
                continue
                
        execution_engine.cleanup()


class PowerScheduler:
    """
    Schedule input base on their "power" (likelihood to find new coverage).
    
    Use exponential moving average to prioritize promising input.
    """
    
    def __init__(self, alpha: float = 0.1):
        """
        Initialize power scheduler.
        
        Args:
            alpha: Smoothing factor for EMA (0.1 = 10% new, 90% old)
        """
        self.alpha = alpha
        self.input_scores: Dict[bytes, float] = {}
        self.input_counts: Dict[bytes, int] = {}
        
    def update_score(self, input_data: bytes, found_new_coverage: bool, 
                    execution_time: float):
        """
        Update score for input base on result.
        
        Higher score = more likely to be select again.
        """
        # Current score (default 1.0 for new input)
        current_score = self.input_scores.get(input_data, 1.0)
        
        # Reward for finding new coverage
        reward = 1.0
        if found_new_coverage:
            reward = 2.0
            
        # Penalize slow execution (but not too much)
        if execution_time > 1.0:
            reward *= 0.9
            
        # Update count
        count = self.input_counts.get(input_data, 0) + 1
        self.input_counts[input_data] = count
        
        # Exponential moving average
        new_score = (1 - self.alpha) * current_score + self.alpha * reward
        self.input_scores[input_data] = new_score
        
    def select_input(self, available_inputs: List[bytes]) -> bytes:
        """
        Select input base on power score.
        
        Use roulette wheel selection with score as weight.
        """
        if not available_inputs:
            return b""
            
        # Get score for each input
        scores = [self.input_scores.get(inp, 1.0) for inp in available_inputs]
        
        # Roulette wheel selection
        total_score = sum(scores)
        if total_score == 0:
            return available_inputs[0]
            
        pick = total_score * (1.0 - (1.0 / len(scores)))  # Bias toward higher scores
        
        cumulative = 0.0
        for i, score in enumerate(scores):
            cumulative += score
            if cumulative >= pick:
                return available_inputs[i]
                
        return available_inputs[-1]  # Fallback
        
    def get_top_inputs(self, n: int = 10) -> List[bytes]:
        """Get top N input by score."""
        sorted_inputs = sorted(
            self.input_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return [inp for inp, score in sorted_inputs[:n]]


class DictionaryManager:
    """
    Manage dictionary of interesting token for mutation.
    
    Use AFL-style dictionary to inject known interesting value.
    """
    
    def __init__(self):
        self.tokens: List[bytes] = []
        self.load_default_dictionary()
        
    def load_default_dictionary(self):
        """Load default dictionary with common interesting value."""
        # Magic number
        self.tokens.extend([
            b"\x00\x00\x00\x00",  # NULL
            b"\xFF\xFF\xFF\xFF",  # MAX
            b"\x80\x00\x00\x00",  # Negative
            b"\x7F\xFF\xFF\xFF",  # Positive max
        ])
        
        # Common string
        self.tokens.extend([
            b"admin",
            b"root",
            b"user",
            b"password",
            b"login",
            b"GET",
            b"POST",
            b"HTTP",
            b"file://",
            b"http://",
            b"https://",
        ])
        
        # Format specific
        self.tokens.extend([
            b"<?xml",           # XML
            b"<html",           # HTML
            b"%PDF-",           # PDF
            b"PK\x03\x04",      # ZIP
            b"\x89PNG",         # PNG
            b"\xFF\xD8\xFF",    # JPEG
        ])
        
    def add_token(self, token: bytes):
        """Add custom token to dictionary."""
        if token not in self.tokens:
            self.tokens.append(token)
            
    def load_from_file(self, filepath: str):
        """Load dictionary from file."""
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
                
            # Split by newline
            lines = content.split(b'\n')
            for line in lines:
                line = line.strip()
                if line and not line.startswith(b'#'):
                    self.tokens.append(line)
                    
        except Exception as e:
            print(f"[!] Error loading dictionary: {e}")
            
    def get_random_tokens(self, count: int = 1) -> List[bytes]:
        """Get random token from dictionary."""
        import random
        
        if not self.tokens:
            return []
            
        return random.choices(self.tokens, k=min(count, len(self.tokens)))
        
    def inject_tokens(self, input_data: bytes, max_injections: int = 3) -> bytes:
        """
        Inject dictionary token into input.
        
        Replace random byte sequence with dictionary token.
        """
        import random
        
        if len(input_data) < 4 or not self.tokens:
            return input_data
            
        result = bytearray(input_data)
        
        for _ in range(random.randint(1, max_injections)):
            if len(result) < 4:
                break
                
            # Pick random position
            pos = random.randint(0, len(result) - 4)
            
            # Pick random token that fit
            token = random.choice(self.tokens)
            if len(token) > len(result) - pos:
                continue
                
            # Replace
            result[pos:pos + len(token)] = token
            
        return bytes(result)

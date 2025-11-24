"""
Execution Engine
================

Execute target binary with monitoring and timeout.
This handle process spawning and result collection.
"""

from typing import Dict, Optional, List
import subprocess
import time
import os
import signal
import tempfile
from .instrumentation import CoverageInstrumenter, InstrumentationType


class ExecutionResult:
    """Result from executing target."""
    
    def __init__(self):
        self.crashed = False
        self.timeout = False
        self.exit_code = 0
        self.execution_time = 0.0
        self.stdout = b""
        self.stderr = b""
        self.coverage = set()
        self.crash_info = {}
        

class ExecutionEngine:
    """
    Execute target binary with monitoring.
    
    Handle:
    - Process spawning with timeout
    - Input delivery (stdin, file, args)
    - Crash detection
    - Coverage collection (if instrument)
    - Resource limit
    """
    
    def __init__(self, timeout: int = 5, 
                 instrumentation: InstrumentationType = InstrumentationType.NONE):
        """
        Initialize execution engine.
        
        Args:
            timeout: Timeout in second for each execution
            instrumentation: Type of instrumentation for coverage
        """
        self.timeout = timeout
        self.temp_dir = tempfile.mkdtemp(prefix="vmdragon_fuzz_")
        self.instrumenter = CoverageInstrumenter(instrumentation)
        self.coverage_enabled = (instrumentation != InstrumentationType.NONE)
        
    def execute(self, target_path: str, input_data: bytes, 
                delivery_method: str = "stdin") -> ExecutionResult:
        """
        Execute target with input.
        
        Args:
            target_path: Path to target binary
            input_data: Input data to deliver
            delivery_method: How to deliver input (stdin, file, arg)
            
        Return:
            ExecutionResult with all information
        """
        result = ExecutionResult()
        start_time = time.time()
        
        try:
            if delivery_method == "stdin":
                result = self._execute_stdin(target_path, input_data)
            elif delivery_method == "file":
                result = self._execute_file(target_path, input_data)
            elif delivery_method == "arg":
                result = self._execute_arg(target_path, input_data)
            else:
                raise ValueError(f"Unknown delivery method: {delivery_method}")
                
        except Exception as e:
            result.crashed = True
            result.crash_info = {'error': str(e)}
            
        result.execution_time = time.time() - start_time
        return result
        
    def _execute_stdin(self, target_path: str, input_data: bytes) -> ExecutionResult:
        """Execute with input deliver via stdin."""
        result = ExecutionResult()
        
        # Get command with instrumentation if enable
        cmd = self.instrumenter.get_coverage_command(target_path) if self.coverage_enabled else [target_path]
        
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            
            stdout, stderr = proc.communicate(input_data, timeout=self.timeout)
            
            result.exit_code = proc.returncode
            result.stdout = stdout
            result.stderr = stderr
            
            # Check if crash
            if proc.returncode < 0:
                result.crashed = True
                result.crash_info = {
                    'signal': -proc.returncode,
                    'type': self._signal_to_crash_type(-proc.returncode)
                }
                
        except subprocess.TimeoutExpired:
            result.timeout = True
            proc.kill()
        except Exception as e:
            result.crashed = True
            result.crash_info = {'error': str(e)}
            
        return result
        
    def _execute_file(self, target_path: str, input_data: bytes) -> ExecutionResult:
        """Execute with input in temporary file."""
        result = ExecutionResult()
        
        # Write input to temporary file
        input_file = os.path.join(self.temp_dir, "input.bin")
        with open(input_file, 'wb') as f:
            f.write(input_data)
            
        try:
            proc = subprocess.Popen(
                [target_path, input_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            
            stdout, stderr = proc.communicate(timeout=self.timeout)
            
            result.exit_code = proc.returncode
            result.stdout = stdout
            result.stderr = stderr
            
            if proc.returncode < 0:
                result.crashed = True
                result.crash_info = {
                    'signal': -proc.returncode,
                    'type': self._signal_to_crash_type(-proc.returncode)
                }
                
        except subprocess.TimeoutExpired:
            result.timeout = True
            proc.kill()
        except Exception as e:
            result.crashed = True
            result.crash_info = {'error': str(e)}
        finally:
            # Clean up temporary file
            try:
                os.remove(input_file)
            except:
                pass
                
        return result
        
    def _execute_arg(self, target_path: str, input_data: bytes) -> ExecutionResult:
        """Execute with input as command line argument."""
        result = ExecutionResult()
        
        try:
            # Convert bytes to string for argument
            arg = input_data.decode('utf-8', errors='ignore')
            
            proc = subprocess.Popen(
                [target_path, arg],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            
            stdout, stderr = proc.communicate(timeout=self.timeout)
            
            result.exit_code = proc.returncode
            result.stdout = stdout
            result.stderr = stderr
            
            if proc.returncode < 0:
                result.crashed = True
                result.crash_info = {
                    'signal': -proc.returncode,
                    'type': self._signal_to_crash_type(-proc.returncode)
                }
                
        except subprocess.TimeoutExpired:
            result.timeout = True
            proc.kill()
        except Exception as e:
            result.crashed = True
            result.crash_info = {'error': str(e)}
            
        return result
        
    def _signal_to_crash_type(self, sig: int) -> str:
        """Convert signal number to crash type."""
        signal_map = {
            signal.SIGSEGV: 'segmentation_fault',
            signal.SIGABRT: 'abort',
            signal.SIGILL: 'illegal_instruction',
            signal.SIGFPE: 'floating_point_exception',
            signal.SIGBUS: 'bus_error',
        }
        
        return signal_map.get(sig, f'signal_{sig}')
        
    def cleanup(self):
        """Clean up temporary file and directory."""
        try:
            import shutil
            shutil.rmtree(self.temp_dir)
        except:
            pass

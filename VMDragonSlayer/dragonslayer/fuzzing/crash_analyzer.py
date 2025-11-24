"""
Crash Analyzer
==============

Analyze crash and determine if unique.
This help prioritize which crash to investigate first.
"""

from dataclasses import dataclass
from typing import List, Optional, Dict
import hashlib


@dataclass
class CrashInfo:
    """Information about crash for triage."""
    crash_id: str
    input_hash: str
    crash_type: str
    address: Optional[int]
    instruction: Optional[str]
    stack_trace: List[str]
    registers: Dict[str, int]
    exploitability: str
    severity: str = "medium"


class CrashAnalyzer:
    """
    Analyze and triage crash.
    
    Determine which crash is unique and which is duplicate.
    Also assess exploitability like !exploitable extension.
    """
    
    def __init__(self):
        """Initialize crash analyzer."""
        self.unique_crashes: Dict[str, CrashInfo] = {}
        self.crash_count = 0
        
    def analyze_crash(self, crash_data: Dict, input_data: bytes) -> CrashInfo:
        """
        Analyze crash and create CrashInfo.
        
        Check if this crash is unique or duplicate of previous.
        Return CrashInfo object with all detail.
        """
        self.crash_count += 1
        
        # Generate signature for this crash
        crash_sig = self._generate_signature(crash_data)
        
        # Check if we see this before
        if crash_sig in self.unique_crashes:
            return self.unique_crashes[crash_sig]
            
        # This is new unique crash
        exploitability = self._assess_exploitability(crash_data)
        severity = self._assess_severity(crash_data)
        
        crash_info = CrashInfo(
            crash_id=crash_sig,
            input_hash=hashlib.sha256(input_data).hexdigest(),
            crash_type=self._classify_crash(crash_data),
            address=crash_data.get('address'),
            instruction=crash_data.get('instruction'),
            stack_trace=crash_data.get('stack_trace', []),
            registers=crash_data.get('registers', {}),
            exploitability=exploitability,
            severity=severity
        )
        
        self.unique_crashes[crash_sig] = crash_info
        return crash_info
        
    def _generate_signature(self, crash_data: Dict) -> str:
        """
        Generate unique signature for crash.
        
        Use crash type + address + top frame of stack.
        This method not perfect but work good enough.
        """
        sig_data = f"{crash_data.get('type', 'unknown')}"
        
        # Include address if available
        addr = crash_data.get('address', 0)
        if addr:
            sig_data += f":{addr:016x}"
            
        # Include top 3 frame from stack trace
        stack = crash_data.get('stack_trace', [])[:3]
        if stack:
            sig_data += ":" + ":".join(stack)
            
        return hashlib.md5(sig_data.encode()).hexdigest()
        
    def _assess_exploitability(self, crash_data: Dict) -> str:
        """
        Assess if crash is exploitable.
        
        Return: high, medium, low, or none
        This is simplified version of real triage.
        """
        crash_type = crash_data.get('type', '').lower()
        
        # Access violation are often exploitable
        if 'access_violation' in crash_type or 'segfault' in crash_type:
            # Check if write operation
            if crash_data.get('write_operation'):
                return 'high'
            # Check if near null
            addr = crash_data.get('address', 0)
            if addr < 0x10000:
                return 'low'
            return 'medium'
            
        # Stack overflow can be exploitable
        if 'stack_overflow' in crash_type or 'stack' in crash_type:
            return 'high'
            
        # Heap corruption usually exploitable
        if 'heap' in crash_type:
            return 'high'
            
        # Division by zero not exploitable
        if 'division' in crash_type or 'divide' in crash_type:
            return 'low'
            
        # Assert and abort not exploitable
        if 'assert' in crash_type or 'abort' in crash_type:
            return 'none'
            
        return 'medium'
        
    def _assess_severity(self, crash_data: Dict) -> str:
        """
        Assess severity of crash.
        Return: critical, high, medium, low
        """
        exploitability = self._assess_exploitability(crash_data)
        
        if exploitability == 'high':
            return 'critical'
        elif exploitability == 'medium':
            return 'high'
        elif exploitability == 'low':
            return 'medium'
        else:
            return 'low'
            
    def _classify_crash(self, crash_data: Dict) -> str:
        """
        Classify type of crash.
        
        Return string describe crash type.
        """
        crash_type = crash_data.get('type', 'unknown')
        
        # Normalize crash type
        crash_type_lower = crash_type.lower()
        
        if 'access' in crash_type_lower or 'segfault' in crash_type_lower:
            return 'access_violation'
        elif 'stack' in crash_type_lower:
            return 'stack_overflow'
        elif 'heap' in crash_type_lower:
            return 'heap_corruption'
        elif 'division' in crash_type_lower or 'divide' in crash_type_lower:
            return 'division_by_zero'
        elif 'assert' in crash_type_lower:
            return 'assertion_failure'
        elif 'abort' in crash_type_lower:
            return 'abort'
        else:
            return crash_type
            
    def get_unique_crash_count(self) -> int:
        """Return number of unique crash found."""
        return len(self.unique_crashes)
        
    def get_total_crash_count(self) -> int:
        """Return total number of crash (include duplicate)."""
        return self.crash_count
        
    def get_crashes_by_exploitability(self, level: str) -> List[CrashInfo]:
        """Get all crash with specific exploitability level."""
        return [
            crash for crash in self.unique_crashes.values()
            if crash.exploitability == level
        ]
        
    def export_report(self) -> Dict:
        """
        Export crash report as dictionary.
        This can be save as JSON for later review.
        """
        return {
            'total_crashes': self.crash_count,
            'unique_crashes': len(self.unique_crashes),
            'crashes': [
                {
                    'id': crash.crash_id,
                    'type': crash.crash_type,
                    'exploitability': crash.exploitability,
                    'severity': crash.severity,
                    'address': hex(crash.address) if crash.address else None,
                    'instruction': crash.instruction,
                    'input_hash': crash.input_hash,
                    'stack_trace': crash.stack_trace[:5]
                }
                for crash in self.unique_crashes.values()
            ]
        }

"""
Coverage Tracker
================

Track code coverage during fuzzing session.
This help find new code path and improve effectiveness.
"""

from typing import Set, Dict, Tuple
from dataclasses import dataclass


@dataclass
class CoverageStats:
    """Statistics about code coverage."""
    total_blocks: int
    covered_blocks: int
    edge_coverage: Set[Tuple[int, int]]
    coverage_percentage: float
    new_coverage_last_iteration: int = 0


class CoverageTracker:
    """
    Track code coverage during fuzzing.
    
    Use basic block and edge coverage for guide fuzzing.
    This technique is from AFL but implementation here is new.
    """
    
    def __init__(self):
        """Initialize coverage tracker."""
        self.coverage_map: Dict[int, int] = {}
        self.edge_map: Set[Tuple[int, int]] = set()
        self.prev_block: int = None
        self.total_blocks_seen = 0
        self.virgin_blocks: Set[int] = set()
        
    def record_block(self, block_id: int) -> bool:
        """
        Record basic block hit.
        
        Return True if this is new block (virgin coverage).
        """
        is_new = block_id not in self.coverage_map
        
        if is_new:
            self.virgin_blocks.add(block_id)
            self.total_blocks_seen += 1
            
        # Update hit count
        self.coverage_map[block_id] = self.coverage_map.get(block_id, 0) + 1
        
        # Track edge (transition between block)
        if self.prev_block is not None:
            edge = (self.prev_block, block_id)
            if edge not in self.edge_map:
                self.edge_map.add(edge)
                is_new = True
                
        self.prev_block = block_id
        
        return is_new
        
    def reset_prev_block(self):
        """Reset previous block for new execution."""
        self.prev_block = None
        
    def get_coverage_set(self) -> Set[int]:
        """Get set of all covered block."""
        return set(self.coverage_map.keys())
        
    def get_edge_set(self) -> Set[Tuple[int, int]]:
        """Get set of all covered edge."""
        return self.edge_map.copy()
        
    def get_stats(self) -> CoverageStats:
        """
        Get coverage statistic.
        
        Return CoverageStats with all the number.
        """
        covered = sum(1 for count in self.coverage_map.values() if count > 0)
        
        # Calculate percentage (hard without knowing total)
        percentage = 0.0
        if self.total_blocks_seen > 0:
            percentage = (covered / self.total_blocks_seen) * 100.0
            
        return CoverageStats(
            total_blocks=self.total_blocks_seen,
            covered_blocks=covered,
            edge_coverage=self.edge_map,
            coverage_percentage=percentage,
            new_coverage_last_iteration=len(self.virgin_blocks)
        )
        
    def has_new_coverage(self, previous_map: Dict[int, int]) -> bool:
        """
        Check if we got new coverage compare to previous.
        This is important for corpus selection.
        """
        if not previous_map:
            return True
            
        # Check for new block
        for block in self.coverage_map:
            if block not in previous_map:
                return True
                
        return False
        
    def merge_coverage(self, other_map: Dict[int, int]):
        """Merge coverage from another run."""
        for block_id, count in other_map.items():
            if block_id in self.coverage_map:
                self.coverage_map[block_id] += count
            else:
                self.coverage_map[block_id] = count
                self.total_blocks_seen += 1
                
    def get_hit_count(self, block_id: int) -> int:
        """Get number of time block was hit."""
        return self.coverage_map.get(block_id, 0)
        
    def export_coverage(self) -> Dict:
        """Export coverage data for save to file."""
        return {
            'blocks': dict(self.coverage_map),
            'edges': [list(edge) for edge in self.edge_map],
            'total_blocks': self.total_blocks_seen,
            'virgin_blocks': list(self.virgin_blocks)
        }

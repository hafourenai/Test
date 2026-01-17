# python/plugins/base_plugin.py
"""
Base Plugin Class
All plugins must inherit from this class
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any


class BasePlugin(ABC):
    """Base class for all security check plugins"""
    
    def __init__(self):
        self.name = "Base Plugin"
        self.description = "Base plugin template"
        self.severity = "Info"
    
    @abstractmethod
    def analyze(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze scan results and return findings
        
        Args:
            scan_results: Complete scan output from Go scanner
            
        Returns:
            List of findings, each with structure:
            {
                'plugin': str,
                'title': str,
                'description': str,
                'severity': str,
                'evidence': Any,
                'recommendation': str
            }
        """
        pass
    
    def get_metadata(self) -> Dict[str, str]:
        """Return plugin metadata"""
        return {
            'name': self.name,
            'description': self.description,
            'severity': self.severity
        }

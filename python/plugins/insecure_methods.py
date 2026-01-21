# python/plugins/insecure_methods.py
"""
Insecure HTTP Methods Plugin
Checks for dangerous HTTP methods enabled
"""

from python.plugins.base_plugin import BasePlugin
from typing import Dict, List, Any


class InsecureMethodsPlugin(BasePlugin):
    """Check for insecure HTTP methods"""
    
    def __init__(self):
        super().__init__()
        self.name = "Insecure HTTP Methods"
        self.description = "Detects dangerous HTTP methods like TRACE, PUT, DELETE"
        self.severity = "High"
        self.dangerous_methods = ['TRACE', 'PUT', 'DELETE', 'CONNECT']
        
    def analyze(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for dangerous HTTP methods"""
        findings = []
        
        http_info = scan_results.get('http_info', [])
        
        for http_scan in http_info:
            allowed = http_scan.get('allowed_methods', [])
            
            dangerous_found = [m for m in allowed if m.upper() in self.dangerous_methods]
            
            if dangerous_found:
                finding = {
                    'plugin': self.name,
                    'title': 'Dangerous HTTP Methods Enabled',
                    'description': f"Server allows potentially dangerous HTTP methods",
                    'severity': self.severity,
                    'evidence': {
                        'url': http_scan['url'],
                        'dangerous_methods': dangerous_found,
                        'all_allowed': allowed
                    },
                    'recommendation': self._get_recommendations(dangerous_found)
                }
                findings.append(finding)
        
        return findings
    
    def _get_recommendations(self, methods: List[str]) -> str:
        """Generate recommendations"""
        risks = {
            'TRACE': 'Can be used for XSS attacks (Cross-Site Tracing)',
            'PUT': 'May allow unauthorized file upload',
            'DELETE': 'May allow unauthorized resource deletion',
            'CONNECT': 'May be used to tunnel attacks through the server'
        }
        
        recs = ["Disable the following HTTP methods:\n"]
        for method in methods:
            risk = risks.get(method.upper(), 'May pose security risks')
            recs.append(f"• {method}: {risk}")
        
        recs.append("\nConfigure web server to only allow GET, POST, HEAD, OPTIONS")
        return "\n".join(recs)

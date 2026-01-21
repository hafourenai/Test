# python/plugins/security_headers.py
"""
Security Headers Plugin
Checks for missing security headers in HTTP responses
"""

from python.plugins.base_plugin import BasePlugin
from typing import Dict, List, Any


class SecurityHeadersPlugin(BasePlugin):
    """Check for missing HTTP security headers"""
    
    def __init__(self):
        super().__init__()
        self.name = "Security Headers Checker"
        self.description = "Identifies missing HTTP security headers"
        self.severity = "Medium"
        
    def analyze(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze HTTP info for missing security headers"""
        findings = []
        
        http_info = scan_results.get('http_info', [])
        
        for http_scan in http_info:
            missing = http_scan.get('missing_headers', [])
            
            if missing:
                finding = {
                    'plugin': self.name,
                    'title': 'Missing Security Headers',
                    'description': f"Server at {http_scan['url']} is missing critical security headers",
                    'severity': self.severity,
                    'evidence': {
                        'url': http_scan['url'],
                        'missing_headers': missing,
                        'current_headers': list(http_scan.get('headers', {}).keys())
                    },
                    'recommendation': self._get_recommendations(missing)
                }
                findings.append(finding)
        
        return findings
    
    def _get_recommendations(self, missing_headers: List[str]) -> str:
        """Generate recommendations for missing headers"""
        recommendations = {
            'X-Frame-Options': 'Set to DENY or SAMEORIGIN to prevent clickjacking',
            'X-Content-Type-Options': 'Set to nosniff to prevent MIME type sniffing',
            'Strict-Transport-Security': 'Enable HSTS to enforce HTTPS connections',
            'Content-Security-Policy': 'Implement CSP to prevent XSS attacks',
            'X-XSS-Protection': 'Set to "1; mode=block" for legacy browser protection'
        }
        
        recs = []
        for header in missing_headers:
            if header in recommendations:
                recs.append(f"• {header}: {recommendations[header]}")
        
        return "\n".join(recs)

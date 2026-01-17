# python/cve_matcher.py
"""
CVE Matcher - Matches detected services against CVE database
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)


class CVEMatcher:
    """Matches services against CVE vulnerability database"""
    
    def __init__(self, cve_feed_path: str = "../config/cve_feed.json"):
        self.cve_feed_path = Path(cve_feed_path)
        self.cve_database = []
        self._load_cve_feed()
    
    def _load_cve_feed(self):
        """Load CVE database from JSON file"""
        try:
            if self.cve_feed_path.exists():
                with open(self.cve_feed_path, 'r') as f:
                    data = json.load(f)
                    self.cve_database = data.get('cve_database', [])
                logger.info(f"✅ Loaded {len(self.cve_database)} CVE entries")
            else:
                logger.warning(f"CVE feed not found: {self.cve_feed_path}")
                # Create default empty database
                self.cve_database = []
        except Exception as e:
            logger.error(f"Error loading CVE feed: {e}")
            self.cve_database = []
    
    def match_service(self, service_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Match a service against CVE database
        
        Args:
            service_info: Service information dict with 'service', 'version', 'port'
            
        Returns:
            List of matching CVE entries
        """
        matches = []
        
        service_name = service_info.get('service', '').lower()
        service_version = service_info.get('version', '').lower()
        port = service_info.get('port', 0)
        
        for cve in self.cve_database:
            cve_service = cve.get('service', '').lower()
            version_pattern = cve.get('version_pattern', '.*')
            
            # Match service name
            if cve_service in service_name or service_name in cve_service:
                # Match version pattern
                if re.search(version_pattern, service_version, re.IGNORECASE):
                    match = {
                        'cve_id': cve.get('cve_id'),
                        'service': service_info.get('service'),
                        'version': service_info.get('version'),
                        'port': port,
                        'description': cve.get('description'),
                        'severity': cve.get('severity'),
                        'cvss_score': cve.get('cvss_score', 0.0),
                        'references': cve.get('references', [])
                    }
                    matches.append(match)
        
        return matches
    
    def get_severity_stats(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get statistics of vulnerabilities by severity"""
        stats = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Info')
            if severity in stats:
                stats[severity] += 1
        
        return stats

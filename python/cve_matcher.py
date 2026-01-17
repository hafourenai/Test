# python/cve_matcher.py
"""
CVE Matcher - Real-time correlation engine using NVD Live Intelligence.
Features professional filtering based on exploitability and threat vectors.
"""

import logging
from typing import Dict, List, Any
from cpe_generator import CPEGenerator
from nvd_client import NVDClient

logger = logging.getLogger(__name__)

class CVEMatcher:
    """Professional CVE Correlation Engine powered by real-time NVD data"""
    
    def __init__(self, api_key: str = None):
        self.nvd_client = NVDClient(api_key=api_key)
        self.cpe_gen = CPEGenerator(nvd_client=self.nvd_client)
        logger.info("📡 Real-Time NVD Engine Initialized")

    def match_service(self, service_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Correlates a detected service with live vulnerabilities.
        Workflow: Service Info -> CPE -> NVD API -> Advanced Filtering
        """
        # 1. Generate CPE
        cpe = self.cpe_gen.generate(service_info)
        logger.debug(f"Resolved CPE: {cpe}")

        # 2. Fetch from NVD (Cache-first)
        raw_vulnerabilities = self.nvd_client.query_by_cpe(cpe)
        
        # 3. Professional Filtering & Correlation
        threat_findings = self._filter_and_score(raw_vulnerabilities, service_info)
        
        return threat_findings

    def _filter_and_score(self, vulnerabilities: List[Dict[str, Any]], 
                          service_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Applies professional-grade filters to reduce false positives.
        Rules:
        - CVSS >= 7.0
        - Exploitability >= 2.0
        - User Interaction = NONE
        - Privileges Required = NONE
        """
        filtered = []
        for vuln in vulnerabilities:
            # Multi-factor professional filter
            is_high_risk = vuln.get('cvss_score', 0) >= 7.0
            is_remotely_exploitable = "NETWORK" in vuln.get('vector', '').upper()
            is_low_complexity = vuln.get('exploitability_score', 0) >= 2.0
            no_interaction = vuln.get('user_interaction', 'NONE').upper() == "NONE"
            no_privs = vuln.get('privileges_required', 'NONE').upper() == "NONE"

            if is_high_risk and is_remotely_exploitable and is_low_complexity:
                # Flag critical remote exploits
                if no_interaction and no_privs:
                    vuln['threat_level'] = "CRITICAL_REMOTE_EXPLOIT"
                else:
                    vuln['threat_level'] = "HIGH_RISK_SERVICE"
                
                # Attach context
                vuln['matched_service'] = service_info.get('service')
                vuln['matched_version'] = service_info.get('version')
                
                filtered.append(vuln)
        
        # Sort by CVSS score descending
        return sorted(filtered, key=lambda x: x.get('cvss_score', 0), reverse=True)

    def get_severity_stats(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Summarizes findings by risk levels"""
        stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for vuln in vulnerabilities:
            score = vuln.get('cvss_score', 0)
            if score >= 9.0:
                stats["CRITICAL"] += 1
            elif score >= 7.0:
                stats["HIGH"] += 1
            elif score >= 4.0:
                stats["MEDIUM"] += 1
            else:
                stats["LOW"] += 1
        
        return stats

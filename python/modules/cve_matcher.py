"""
CVE Matcher - Matches detected services with known vulnerabilities
Matches detected services with known vulnerabilities
"""

import logging
from typing import List, Dict, Optional
from nvd_client import NVDClient

logger = logging.getLogger(__name__)


class CVEMatcher:
    """Matches services with CVEs from NVD"""
    
    def __init__(self, nvd_api_key: Optional[str] = None, use_tor: bool = False):
        """
        Initialize CVE Matcher
        
        Args:
            nvd_api_key: Optional NVD API key for better rate limits
            use_tor: Whether to route NVD API traffic through Tor
        """
        self.nvd_client = NVDClient(api_key=nvd_api_key, use_tor=use_tor)
        logger.info("[Net] Real-Time NVD CVE Matcher Initialized")
        if use_tor:
            logger.info("[Tor] CVE Matcher will use Tor for NVD API requests")
    
    def match_vulnerabilities(self, services: List[Dict]) -> List[Dict]:
        """
        Match detected services with known CVEs
        
        Args:
            services: List of service dictionaries with 'name', 'version', 'port'
            
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        logger.info(f"[Search] Matching {len(services)} services against NVD database...")
        
        for service in services:
            service_name = service.get('name', 'unknown')
            version = service.get('version', None)
            port = service.get('port', 'unknown')
            
            # Skip if service name is unknown or generic
            if service_name in ['unknown', 'tcpwrapped', None]:
                continue
            
            logger.info(f"[Search] Checking {service_name} {version or '(version unknown)'} on port {port}")
            
            # Query NVD for this service
            cves = self.nvd_client.get_cves_for_service(service_name, version)
            
            if cves:
                logger.info(f"[Success] Found {len(cves)} CVEs for {service_name}")
                
                # Filter and categorize by severity
                critical = [c for c in cves if c['severity'] == 'CRITICAL']
                high = [c for c in cves if c['severity'] == 'HIGH']
                medium = [c for c in cves if c['severity'] == 'MEDIUM']
                low = [c for c in cves if c['severity'] == 'LOW']
                
                # Create finding for this service
                finding = {
                    'service': service_name,
                    'version': version,
                    'port': port,
                    'total_cves': len(cves),
                    'critical': len(critical),
                    'high': len(high),
                    'medium': len(medium),
                    'low': len(low),
                    'cves': cves[:10],  # Include top 10 most severe
                    'severity': self._calculate_overall_severity(critical, high, medium, low)
                }
                
                findings.append(finding)
                
                # Log summary
                if critical:
                    logger.warning(f"  CRITICAL: {len(critical)} critical CVEs found for {service_name}!")
                if high:
                    logger.warning(f"🟠 HIGH: {len(high)} high-severity CVEs found")
            else:
                logger.info(f"[Success] No known CVEs found for {service_name} {version or ''}")
        
        logger.info(f"[Done] Vulnerability matching complete: {len(findings)} services with CVEs")
        
        return findings
    
    def _calculate_overall_severity(self, critical, high, medium, low) -> str:
        """Calculate overall severity for a service"""
        if critical:
            return 'CRITICAL'
        elif high:
            return 'HIGH'
        elif medium:
            return 'MEDIUM'
        elif low:
            return 'LOW'
        return 'NONE'
    
    def format_findings(self, findings: List[Dict]) -> str:
        """
        Format vulnerability findings for display
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            Formatted string report
        """
        if not findings:
            return "\n  No vulnerabilities found in detected services"
        
        report = "\n" + "="*70 + "\n"
        report += "  VULNERABILITY REPORT\n"
        report += "="*70 + "\n"
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        findings.sort(key=lambda x: severity_order.get(x['severity'], 99))
        
        for finding in findings:
            service = finding['service']
            version = finding['version'] or 'unknown'
            port = finding['port']
            total = finding['total_cves']
            severity = finding['severity']
            
            # Service header
            report += f"\n  {service.upper()} {version} (Port {port})\n"
            report += f"   Overall Severity: {self._severity_emoji(severity)} {severity}\n"
            report += f"   Total CVEs: {total}\n"
            
            # Severity breakdown
            if finding['critical'] > 0:
                report += f"     Critical: {finding['critical']}\n"
            if finding['high'] > 0:
                report += f"   🟠 High: {finding['high']}\n"
            if finding['medium'] > 0:
                report += f"   🟡 Medium: {finding['medium']}\n"
            if finding['low'] > 0:
                report += f"   🟢 Low: {finding['low']}\n"
            
            # Top CVEs
            report += f"\n   📋 Top {min(5, len(finding['cves']))} CVEs:\n"
            for i, cve in enumerate(finding['cves'][:5], 1):
                cvss = cve.get('cvss_v3') or cve.get('cvss_v2') or 'N/A'
                report += f"\n   {i}. {cve['id']} - {cve['severity']}\n"
                report += f"      CVSS: {cvss}\n"
                report += f"      {cve['description'][:120]}...\n"
                report += f"      🔗 {cve['url']}\n"
            
            report += "\n" + "-"*70 + "\n"
        
        return report
    
    def _severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level"""
        emojis = {
            'CRITICAL': ' ',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'NONE': '⚪'
        }
        return emojis.get(severity, '⚪')
    
    def export_json(self, findings: List[Dict], filename: str = 'vulnerabilities.json'):
        """Export findings to JSON file"""
        import json
        
        with open(filename, 'w') as f:
            json.dump(findings, f, indent=2)
        
        logger.info(f"💾 Vulnerability report exported to {filename}")
    
    def export_csv(self, findings: List[Dict], filename: str = 'vulnerabilities.csv'):
        """Export findings to CSV file"""
        import csv
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Service', 'Version', 'Port', 'CVE-ID', 'Severity', 'CVSS', 'Description', 'URL'])
            
            for finding in findings:
                service = finding['service']
                version = finding['version'] or 'unknown'
                port = finding['port']
                
                for cve in finding['cves']:
                    writer.writerow([
                        service,
                        version,
                        port,
                        cve['id'],
                        cve['severity'],
                        cve.get('cvss_v3') or cve.get('cvss_v2') or 'N/A',
                        cve['description'][:200],
                        cve['url']
                    ])
        
        logger.info(f"💾 CSV report exported to {filename}")


# Example usage
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s:%(name)s:%(message)s'
    )
    
    # Example detected services
    services = [
        {'name': 'nginx', 'version': '1.24.0', 'port': 80},
        {'name': 'openssh', 'version': '9.6', 'port': 22},
        {'name': 'vsftpd', 'version': None, 'port': 21}
    ]
    
    # Initialize matcher
    matcher = CVEMatcher()
    
    # Match vulnerabilities
    findings = matcher.match_vulnerabilities(services)
    
    # Display report
    print(matcher.format_findings(findings))
    
    # Export results
    if findings:
        matcher.export_json(findings)
        matcher.export_csv(findings)

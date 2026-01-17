# python/output_handler.py
"""
Output Handler - Formats and saves scan results
"""

import json
from pathlib import Path
from typing import Dict, Any
from datetime import datetime


class OutputHandler:
    """Handles output formatting and file saving"""
    
    def __init__(self):
        self.output_dir = Path("../output")
        self.output_dir.mkdir(exist_ok=True)
    
    def save_json(self, data: Dict[str, Any], filepath: str):
        """Save scan results as JSON"""
        try:
            output_path = Path(filepath)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"✅ Report saved to: {output_path}")
        except Exception as e:
            print(f"❌ Error saving report: {e}")
    
    def print_summary(self, report: Dict[str, Any]):
        """Print formatted summary to console"""
        print("\n" + "="*60)
        print("📊 SCAN SUMMARY")
        print("="*60)
        
        # Metadata
        metadata = report.get('metadata', {})
        print(f"\n🎯 Target: {metadata.get('target', 'N/A')}")
        print(f"⏰ Timestamp: {metadata.get('timestamp', 'N/A')}")
        print(f"🔧 Scanner Version: {metadata.get('scanner_version', 'N/A')}")
        
        # Stealth mode info
        stealth = metadata.get('stealth_mode', {})
        if stealth.get('proxies_enabled') or stealth.get('tor_enabled'):
            print(f"\n🔒 Stealth Mode:")
            if stealth.get('tor_enabled'):
                print(f"   🧅 Tor: ENABLED")
            if stealth.get('proxies_enabled'):
                print(f"   🔄 Proxies: {stealth.get('proxy_count', 0)} loaded")
            if stealth.get('exit_ip'):
                print(f"   📡 Exit IP: {stealth.get('exit_ip')}")
        
        # Statistics
        stats = report.get('statistics', {})
        print(f"\n📈 Statistics:")
        print(f"   Open Ports: {stats.get('open_ports', 0)}")
        print(f"   Services Detected: {stats.get('services_detected', 0)}")
        print(f"   Vulnerabilities Found: {stats.get('vulnerabilities_found', 0)}")
        print(f"   Plugin Findings: {stats.get('plugin_findings', 0)}")
        
        # Open ports
        scan_results = report.get('scan_results', {})
        open_ports = scan_results.get('open_ports', [])
        if open_ports:
            print(f"\n🔓 Open Ports: {', '.join(map(str, open_ports[:20]))}")
            if len(open_ports) > 20:
                print(f"   ... and {len(open_ports) - 20} more")
        
        # Services
        services = scan_results.get('services', [])
        if services:
            print(f"\n🔍 Detected Services:")
            for svc in services[:10]:
                print(f"   Port {svc['port']}: {svc['service']} ({svc['version']})")
            if len(services) > 10:
                print(f"   ... and {len(services) - 10} more")
        
        # Vulnerabilities
        vulnerabilities = report.get('vulnerabilities', [])
        if vulnerabilities:
            print(f"\n⚠️  Vulnerabilities:")
            for vuln in vulnerabilities[:5]:
                severity_emoji = self._get_severity_emoji(vuln.get('severity'))
                print(f"   {severity_emoji} {vuln.get('cve_id')}: {vuln.get('description')}")
                print(f"      Port {vuln.get('port')} - {vuln.get('service')} {vuln.get('version')}")
            if len(vulnerabilities) > 5:
                print(f"   ... and {len(vulnerabilities) - 5} more")
        
        # Plugin findings
        plugin_findings = report.get('plugin_findings', [])
        if plugin_findings:
            print(f"\n🔌 Plugin Findings:")
            for finding in plugin_findings[:5]:
                severity_emoji = self._get_severity_emoji(finding.get('severity'))
                print(f"   {severity_emoji} {finding.get('title')}")
                print(f"      {finding.get('description')}")
            if len(plugin_findings) > 5:
                print(f"   ... and {len(plugin_findings) - 5} more")
        
        print("\n" + "="*60)
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level"""
        severity_map = {
            'Critical': '🔴',
            'High': '🟠',
            'Medium': '🟡',
            'Low': '🟢',
            'Info': 'ℹ️'
        }
        return severity_map.get(severity, 'ℹ️')
    
    def generate_html_report(self, report: Dict[str, Any], filepath: str):
        """Generate HTML report (future enhancement)"""
        # TODO: Implement HTML report generation
        pass

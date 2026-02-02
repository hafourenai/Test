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
        """Save scan results as JSON with automatic filename generation for directories"""
        try:
            output_path = Path(filepath)
            
            # Detect if this is a directory path (exists and is dir, OR looks like a directory)
            # A path "looks like a directory" if:
            # - It has no file extension (no suffix)
            # - OR it exists and is a directory
            # - OR it ends with a path separator
            is_directory = (
                (output_path.exists() and output_path.is_dir()) or
                (not output_path.suffix and not output_path.name.endswith('.json')) or
                str(filepath).endswith(('/', '\\'))
            )
            
            if is_directory:
                # Auto-generate filename based on scan metadata
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                target = data.get('metadata', {}).get('target', 'unknown')
                # Sanitize target for filename
                target = target.replace(':', '_').replace('/', '_').replace('\\', '_')
                
                # Determine scan mode for filename
                stealth_meta = data.get('metadata', {}).get('stealth_mode', {})
                if stealth_meta.get('budgeted'):
                    mode = 'stealth'
                elif stealth_meta.get('enabled'):
                    mode = 'proxy'
                else:
                    mode = 'scan'
                
                filename = f"{mode}_{target}_{timestamp}.json"
                output_path = output_path / filename
                print(f"[Info] Auto-generated filename: {filename}")
            
            # Ensure parent directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write JSON file
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            print(f"[Success] Report saved to: {output_path}")
            return str(output_path)
            
        except Exception as e:
            print(f"[Error] Failed to save report: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def print_summary(self, report: Dict[str, Any]):
        """Print formatted summary to console"""
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        
        # Metadata
        metadata = report.get('metadata', {})
        print(f"\n[Target] Target: {metadata.get('target', 'N/A')}")
        print(f"[Time] Timestamp: {metadata.get('timestamp', 'N/A')}")
        print(f"[Build] Scanner Version: {metadata.get('scanner_version', 'N/A')}")
        
        # Stealth mode info
        stealth = metadata.get('stealth_mode', {})
        if stealth.get('proxies_enabled') or stealth.get('tor_enabled'):
            print(f"\n[Stealth] Stealth Mode:")
            if stealth.get('tor_enabled'):
                print(f"   [Tor] Tor: ENABLED")
            if stealth.get('proxies_enabled'):
                print(f"   [IP] Proxies: {stealth.get('proxy_count', 0)} loaded")
            if stealth.get('exit_ip'):
                print(f"   [IP] Exit IP: {stealth.get('exit_ip')}")
        
        # Statistics
        stats = report.get('statistics', {})
        print(f"\n[Stat] Statistics:")
        print(f"   Open Ports: {stats.get('open_ports', 0)}")
        print(f"   Services Detected: {stats.get('services_detected', 0)}")
        print(f"   Vulnerabilities Found: {stats.get('vulnerabilities_found', 0)}")
        if 'confidence_distribution' in stats:
            dist = stats['confidence_distribution']
            print(f"     -> Confirmed: {dist.get('confirmed', 0)}, Potential: {dist.get('possible', 0)}, Informational: {dist.get('informational', 0)}")
        print(f"   Plugin Findings: {stats.get('plugin_findings', 0)}")
        
        # Open ports
        scan_results = report.get('scan_results', {})
        open_ports = scan_results.get('open_ports', [])
        if open_ports:
            print(f"\n[Port] Open Ports: {', '.join(map(str, open_ports[:20]))}")
            if len(open_ports) > 20:
                print(f"   ... and {len(open_ports) - 20} more")
        
        # Services
        services = scan_results.get('services', [])
        if services:
            print(f"\n[Search] Detected Services:")
            for svc in services[:10]:
                print(f"   Port {svc['port']}: {svc['service']} ({svc['version']})")
            if len(services) > 10:
                print(f"   ... and {len(services) - 10} more")
        
        # Vulnerabilities - Categorized
        vulnerabilities = report.get('vulnerabilities', [])
        if vulnerabilities:
            print(f"\n[Warning] Vulnerability Analysis:")
            
            # Group by relevance
            confirmed = [v for v in vulnerabilities if v.get('relevance') == 'confirmed']
            potential = [v for v in vulnerabilities if v.get('relevance') in ['likely', 'possible']]
            informational = [v for v in vulnerabilities if v.get('relevance') == 'informational']
            
            if confirmed:
                print(f"\n   ✅ CONFIRMED FINDINGS ({len(confirmed)}):")
                for vuln in confirmed[:5]:
                    print(f"      [!] {vuln.get('service')} {vuln.get('version')}: {vuln.get('explanation')}")
            
            if potential:
                print(f"\n   [WARNING] POTENTIAL VULNERABILITIES ({len(potential)}):")
                for vuln in potential[:5]:
                    print(f"      [-] {vuln.get('service')} {vuln.get('version')}: {vuln.get('critical') + vuln.get('high')} high-risk correlations")
            
            if informational:
                print(f"\n   ℹ️  THREAT INTELLIGENCE REFERENCES ({len(informational)}):")
                for vuln in informational[:3]:
                    print(f"      [?] {vuln.get('service')}: {vuln.get('total_cves')} keyword matches (Assumed Low Relevance)")
                    print(f"          Reason: {vuln.get('explanation', 'Generic match')}")

            print(f"\n   [Note] Results are correlation-based. No active exploit verification performed.")
        
        # Plugin findings
        plugin_findings = report.get('plugin_findings', [])
        if plugin_findings:
            print(f"\n[Plugin] Plugin Findings:")
            for finding in plugin_findings[:5]:
                severity_tag = self._get_severity_tag(finding.get('severity'))
                print(f"   {severity_tag} {finding.get('title')}")
                print(f"      {finding.get('description')}")
            if len(plugin_findings) > 5:
                print(f"   ... and {len(plugin_findings) - 5} more")
        
        print("\n" + "="*60)
    
    def _get_severity_tag(self, severity: str) -> str:
        """Get text tag for severity level"""
        severity_map = {
            'Critical': '[CRITICAL]',
            'High': '[HIGH]',
            'Medium': '[MEDIUM]',
            'Low': '[LOW]',
            'Info': '[INFO]'
        }
        return severity_map.get(severity, '[INFO]')
    
    def generate_html_report(self, report: Dict[str, Any], filepath: str):
        """Generate HTML report (future enhancement)"""
        # TODO: Implement HTML report generation
        pass

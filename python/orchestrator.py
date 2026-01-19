# python/orchestrator.py
"""
Base Scan Orchestrator
Coordinates the vulnerability scanning process with Active Service Fingerprinting
"""

import json
import subprocess
import sys
import logging
from typing import Dict, List, Any
from pathlib import Path

# Import service fingerprinter
try:
    from modules.service_fingerprinter import ServiceFingerprinter
except ImportError:
    # Fallback if modules package not in path
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from modules.service_fingerprinter import ServiceFingerprinter
    from build import build_go_scanner

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Orchestrates the vulnerability scanning process"""
    
    def __init__(self, go_scanner_path: str = None): # Path is now dynamic
        self.scan_results = {}
        self.fingerprinter = ServiceFingerprinter()
        logger.info("[Search] Active Service Fingerprinting Engine initialized")
    
    # ... (normalize_services, validate_target, _get_severity_tag remain the same) ...
    def normalize_services(self, services: List[Any]) -> List[Dict[str, Any]]:
        # ... (implementation same as before)
        normalized = []
        for svc in services:
            if isinstance(svc, int):
                normalized.append({"port": svc, "state": "open"})
            elif isinstance(svc, dict):
                normalized.append({"port": svc.get("port"), "state": svc.get("state", "open")})
        return normalized

    def validate_target(self, target: str) -> bool:
        if not target or len(target) == 0: return False
        restricted = ['localhost', '127.0.0.1', '0.0.0.0']
        if target in restricted:
            print(f"[!] Warning: Scanning {target} requires explicit permission")
            return False
        return True

    def _get_severity_tag(self, severity: str) -> str:
        severity_map = {
            'Critical': '[CRITICAL]', 'High': '[HIGH]',
            'Medium': '[MEDIUM]', 'Low': '[LOW]', 'Info': '[INFO]'
        }
        return severity_map.get(severity, '[INFO]')

    def execute_go_scanner(self, target: str, start_port: int = 1, 
                          end_port: int = 1000, timeout: int = 2, 
                          threads: int = 100, use_proxy: bool = False) -> Dict[str, Any]:
        """
        Execute Go scanner and return results.
        Uses the separate build layer for compilation.
        """
        
        print(f"[Scan] Starting scan on {target}...")
        print(f"   Port range: {start_port}-{end_port}")
        print(f"   Threads: {threads}")
        
        try:
            # Step 1: Build Scanner (Clean Architecture)
            # This handles path resolution and error reporting automatically
            scanner_path = build_go_scanner()
            
            # Step 2: Execute Scanner
            scan_cmd = [
                scanner_path,
                "-target", target,
                "-start", str(start_port),
                "-end", str(end_port),
                "-timeout", str(timeout),
                "-threads", str(threads)
            ]
            
            # Use proxy config if requested
            # (Note: The Go scanner should handle env vars or flags for proxy depending on implementation)
            # Assuming env vars HTTP_PROXY/HTTPS_PROXY are picked up if set in main.py
            
            result = subprocess.run(scan_cmd, capture_output=True, 
                                  text=True, timeout=300, check=False)
            
            if result.returncode != 0:
                raise RuntimeError(f"Scanner execution failed:\n{result.stderr}")
            
            # Parse JSON output
            try:
                scan_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                # Fallback: sometimes scanner might output logs mixed with JSON if not careful
                # But our scanner outputs pretty JSON at the end.
                logger.error(f"Failed to parse JSON. Raw output:\n{result.stdout[:200]}...")
                return {}
            
            # === ACTIVE SERVICE FINGERPRINTING ===
            print(f"\n[Search] Active Service Fingerprinting in progress...")
            fingerprinted_services = self._fingerprint_services(target, scan_data)
            scan_data['services'] = fingerprinted_services
            
            self.scan_results = scan_data
            
            print(f"[Success] Scan completed: {len(scan_data.get('open_ports', []))} open ports found")
            print(f"[Success] Fingerprinted: {len(fingerprinted_services)} services")
            return scan_data
            
        except FileNotFoundError as e:
            print(f"[Error] Dependency missing: {e}")
            return {}
        except RuntimeError as e:
            print(f"[Error] {e}")
            return {}
        except subprocess.TimeoutExpired:
            print("[Error] Scanner timeout (5 minutes)")
            return {}
        except Exception as e:
            print(f"[Error] Unexpected scanner error: {e}")
            return {}
    
    def _fingerprint_services(self, target: str, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Actively fingerprint all detected services with normalization.
        
        This is the critical missing layer that enables CVE correlation.
        Converts: Port 22 → OpenSSH 8.9p1
        Instead of: Port 22 → unknown
        
        Args:
            target: Target host
            scan_data: Raw scan results from Go scanner
            
        Returns:
            List of enriched service dictionaries with product and version
        """
        fingerprinted = []
        open_ports = scan_data.get('open_ports', [])
        if open_ports:
            print(f"\n[Port] Open Ports: {', '.join(map(str, open_ports[:20]))}")
        
        # STEP 1 — Enforce canonical schema via normalization layer
        normalized_services = self.normalize_services(open_ports)
        
        for svc in normalized_services:
            port = svc["port"]
            
            # Perform active fingerprinting
            fingerprint = self.fingerprinter.fingerprint(target, port)
            
            # Merge normalized service with fingerprint data
            enriched_service = {
                'port': port,
                'state': svc["state"],
                'service': fingerprint.get('service', 'unknown'),
                'product': fingerprint.get('product', 'unknown'),
                'version': fingerprint.get('version', 'unknown'),
                'banner': fingerprint.get('banner', '')
            }
            
            fingerprinted.append(enriched_service)
            
            # Log successful identifications
            if fingerprint.get('product') != 'unknown':
                logger.info(
                    f"Port {port}: {fingerprint['service']} "
                    f"({fingerprint['product']} {fingerprint['version']})"
                )
        
        return fingerprinted
    
    def get_results(self) -> Dict[str, Any]:
        """Get current scan results"""
        return self.scan_results
    
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

        # Services
        scan_results = report.get('scan_results', {})
        services = scan_results.get('services', [])
        if services:
            print(f"\n[Search] Detected Services:")
            for svc in services:
                print(f"   - Port {svc.get('port')}: {svc.get('service')} {svc.get('product')} {svc.get('version')}")
        
        # Vulnerabilities
        vulnerabilities = report.get('vulnerabilities', [])
        if vulnerabilities:
            print(f"\n[Warning] Vulnerabilities:")
            for vuln in vulnerabilities:
                severity_tag = self._get_severity_tag(vuln.get('severity', 'Info'))
                print(f"   {severity_tag} {vuln.get('name')} (CVE: {vuln.get('cve_id', 'N/A')})")
                print(f"     Description: {vuln.get('description', '')[:100]}...")
                print(f"     Affected: {vuln.get('affected_product')} {vuln.get('affected_version')}")
                print(f"     References: {', '.join(vuln.get('references', [])[:2])}")
        
        print("\n" + "="*60)

    def save_report(self, data: Dict[str, Any], output_path: str):
        """Save the scan report to a JSON file."""
        try:
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"[Success] Report saved to: {output_path}")
        except Exception as e:
            print(f"[Error] Error saving report: {e}")
    
    def apply_rate_limiting(self, delay: float = 0.1):
        """Apply rate limiting between requests"""
        import time
        time.sleep(delay)

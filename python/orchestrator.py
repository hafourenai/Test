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

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Orchestrates the vulnerability scanning process"""
    
    def __init__(self, go_scanner_path: str = "../go/main.go"):
        self.go_scanner_path = go_scanner_path
        self.scan_results = {}
        self.fingerprinter = ServiceFingerprinter()
        logger.info("🔍 Active Service Fingerprinting Engine initialized")
    
    def normalize_services(self, services: List[Any]) -> List[Dict[str, Any]]:
        """
        Service Data Normalization Layer - Enforces canonical service schema.
        
        This is the single source of truth for service structure.
        Transforms legacy formats into the required contract:
        
        Input (legacy):  [22, 80, 443]
        Output (canonical): [{"port": 22, "state": "open"}, ...]
        
        Args:
            services: Raw service data (can be list of ints or dicts)
            
        Returns:
            List of normalized service dictionaries
        """
        normalized = []
        
        for svc in services:
            # Legacy format: [22, 80, 443]
            if isinstance(svc, int):
                normalized.append({
                    "port": svc,
                    "state": "open"
                })
            
            # Partial dict format
            elif isinstance(svc, dict):
                normalized.append({
                    "port": svc.get("port"),
                    "state": svc.get("state", "open")
                })
        
        return normalized
        
    def validate_target(self, target: str) -> bool:
        """Validate target scope and format"""
        # Basic validation
        if not target or len(target) == 0:
            return False
        
        # Prevent scanning localhost/private IPs without explicit permission
        restricted = ['localhost', '127.0.0.1', '0.0.0.0']
        if target in restricted:
            print(f"⚠️  Warning: Scanning {target} requires explicit permission")
            return False
            
        return True
    
    def execute_go_scanner(self, target: str, start_port: int = 1, 
                          end_port: int = 1000, timeout: int = 2, 
                          threads: int = 100) -> Dict[str, Any]:
        """Execute Go scanner and return results"""
        
        print(f"🔍 Starting scan on {target}...")
        print(f"   Port range: {start_port}-{end_port}")
        print(f"   Threads: {threads}")
        
        try:
            # Build Go binary if needed
            go_dir = Path(self.go_scanner_path).parent
            binary_name = "scanner.exe" if sys.platform == "win32" else "scanner"
            binary_path = go_dir / binary_name
            
            # Build
            build_cmd = ["go", "build", "-o", binary_name, Path(self.go_scanner_path).name]
            build_result = subprocess.run(build_cmd, cwd=str(go_dir), 
                                        capture_output=True, text=True)
            
            if build_result.returncode != 0:
                raise Exception(f"Go build failed: {build_result.stderr}")
            
            # Execute scanner
            scan_cmd = [
                str(binary_path),
                "-target", target,
                "-start", str(start_port),
                "-end", str(end_port),
                "-timeout", str(timeout),
                "-threads", str(threads)
            ]
            
            result = subprocess.run(scan_cmd, capture_output=True, 
                                  text=True, timeout=300)
            
            if result.returncode != 0:
                raise Exception(f"Scanner failed: {result.stderr}")
            
            # Parse JSON output
            scan_data = json.loads(result.stdout)
            
            # === ACTIVE SERVICE FINGERPRINTING ===
            # This is the missing component that converts port numbers to software identities
            print(f"\\n🔬 Active Service Fingerprinting in progress...")
            fingerprinted_services = self._fingerprint_services(target, scan_data)
            scan_data['services'] = fingerprinted_services
            
            self.scan_results = scan_data
            
            print(f"✅ Scan completed: {len(scan_data.get('open_ports', []))} open ports found")
            print(f"✅ Fingerprinted: {len(fingerprinted_services)} services")
            return scan_data
            
        except subprocess.TimeoutExpired:
            print("❌ Scanner timeout (5 minutes)")
            return {}
        except json.JSONDecodeError as e:
            print(f"❌ Failed to parse scanner output: {e}")
            print(f"Raw output: {result.stdout[:500]}")
            return {}
        except Exception as e:
            print(f"❌ Scanner error: {e}")
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
    
    def apply_rate_limiting(self, delay: float = 0.1):
        """Apply rate limiting between requests"""
        import time
        time.sleep(delay)

# python/stealth_orchestrator.py
"""
Enhanced Orchestrator with Stealth Capabilities
Extends base orchestrator with proxy rotation and Tor support
"""

import json
import subprocess
import sys
import logging
from typing import Dict, List, Any
from pathlib import Path
from proxy_manager import ProxyManager, StealthScanner

# Import service fingerprinter
try:
    from modules.service_fingerprinter import ServiceFingerprinter
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent))
    from modules.service_fingerprinter import ServiceFingerprinter

logger = logging.getLogger(__name__)


class StealthOrchestrator:
    """Orchestrator with proxy rotation and Tor support"""
    
    def __init__(self, go_scanner_path: str = "../go/main.go", 
                 use_proxies: bool = True, use_tor: bool = False,
                 proxies_file: str = "proxies.txt"):
        self.go_scanner_path = go_scanner_path
        self.scan_results = {}
        
        # Initialize service fingerprinter
        self.fingerprinter = ServiceFingerprinter()
        logger.info("🔍 Active Service Fingerprinting Engine initialized")
        
        # Initialize proxy manager
        self.proxy_manager = None
        if use_proxies or use_tor:
            self.proxy_manager = ProxyManager(
                proxies_file=proxies_file,
                use_tor=use_tor
            )
            
            # Verify proxies on startup
            if use_proxies and self.proxy_manager.proxies:
                logger.info(f"Loaded {len(self.proxy_manager.proxies)} proxies")
                
                # Optional: validate proxies
                # self.proxy_manager.validate_all_proxies()
            
            if use_tor:
                logger.info("Tor integration enabled")
        
        self.stealth_scanner = StealthScanner(self.proxy_manager) if self.proxy_manager else None
    
    def validate_target(self, target: str) -> bool:
        """Validate target scope and format"""
        if not target or len(target) == 0:
            return False
        
        # Show current IP for verification
        if self.proxy_manager:
            current_ip = self.proxy_manager.get_public_ip(use_proxy=True)
            logger.info(f"🌐 Current public IP: {current_ip}")
        
        restricted = ['localhost', '127.0.0.1', '0.0.0.0']
        if target in restricted:
            print(f"⚠️  Warning: Scanning {target} requires explicit permission")
            return False
            
        return True
    
    def execute_go_scanner(self, target: str, start_port: int = 1, 
                          end_port: int = 1000, timeout: int = 2, 
                          threads: int = 100, use_proxy: bool = False) -> Dict[str, Any]:
        """Execute Go scanner with optional proxy support"""
        
        print(f"🔍 Starting stealth scan on {target}...")
        print(f"   Port range: {start_port}-{end_port}")
        print(f"   Threads: {threads}")
        
        if self.proxy_manager:
            if self.proxy_manager.use_tor:
                print(f"   🧅 Using Tor network")
            elif self.proxy_manager.proxies:
                print(f"   🔄 Proxy rotation enabled ({len(self.proxy_manager.proxies)} proxies)")
        
        try:
            go_dir = Path(self.go_scanner_path).parent
            
            # Cross-platform binary name
            binary_name = "scanner.exe" if sys.platform == "win32" else "scanner"
            binary_path = go_dir / binary_name
            
            # Build
            build_cmd = ["go", "build", "-o", binary_name, Path(self.go_scanner_path).name]
            build_result = subprocess.run(build_cmd, cwd=str(go_dir), 
                                        capture_output=True, text=True)
            
            if build_result.returncode != 0:
                raise Exception(f"Go build failed: {build_result.stderr}")
            
            # Prepare scanner command
            scan_cmd = [
                str(binary_path),
                "-target", target,
                "-start", str(start_port),
                "-end", str(end_port),
                "-timeout", str(timeout),
                "-threads", str(threads)
            ]
            
            # Add proxy if available
            if use_proxy and self.proxy_manager:
                proxy = self.proxy_manager.get_current_proxy('tor-fallback')
                if proxy:
                    # Pass proxy to Go scanner via environment
                    import os
                    env = os.environ.copy()
                    
                    # Extract proxy URL
                    proxy_url = proxy.get('http', '')
                    if proxy_url:
                        env['HTTP_PROXY'] = proxy_url
                        env['HTTPS_PROXY'] = proxy_url
                        print(f"   📡 Using proxy for Go scanner")
                    
                    result = subprocess.run(scan_cmd, capture_output=True, 
                                          text=True, timeout=300, env=env)
                else:
                    result = subprocess.run(scan_cmd, capture_output=True, 
                                          text=True, timeout=300)
            else:
                result = subprocess.run(scan_cmd, capture_output=True, 
                                      text=True, timeout=300)
            
            if result.returncode != 0:
                raise Exception(f"Scanner failed: {result.stderr}")
            
            scan_data = json.loads(result.stdout)
            
            # === ACTIVE SERVICE FINGERPRINTING ===
            print(f"\n🔬 Active Service Fingerprinting in progress...")
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
            return {}
        except Exception as e:
            print(f"❌ Scanner error: {e}")
            return {}
    
    def _fingerprint_services(self, target: str, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Actively fingerprint all detected services.
        Identical to base orchestrator but integrated with stealth mode.
        """
        fingerprinted = []
        open_ports = scan_data.get('open_ports', [])
        
        for port_info in open_ports:
            port = port_info.get('port')
            if not port:
                continue
            
            # Perform active fingerprinting
            fingerprint = self.fingerprinter.fingerprint(target, port)
            
            # Merge port info with fingerprint data
            enriched_service = {
                'port': port,
                'state': port_info.get('state', 'open'),
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

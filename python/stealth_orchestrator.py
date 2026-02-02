# python/stealth_orchestrator.py
"""
  Orchestrator with Stealth Capabilities
Extends base orchestrator with proxy rotation and Tor support
"""

import json
import subprocess
import sys
import logging
from typing import Dict, List, Any
from pathlib import Path
from .proxy_manager import ProxyManager, StealthScanner
from .build import build_go_scanner
import os

# Import service fingerprinter
try:
    from .modules.service_fingerprinter import ServiceFingerprinter
except ImportError:
    # sys.path.insert(0, str(Path(__file__).parent))
    from .modules.service_fingerprinter import ServiceFingerprinter

logger = logging.getLogger(__name__)


class StealthOrchestrator:
    """Orchestrator with proxy rotation and Tor support"""
    
    def __init__(self, go_scanner_path: str = "../go/main.go", 
                 use_proxies: bool = True, use_tor: bool = False,
                 proxies_file: str = "proxies.txt"):
        self.go_scanner_path = go_scanner_path
        self.scan_results = {}
        
        # Initialize service fingerprinter
        self.fingerprinter = ServiceFingerprinter(use_tor=use_tor)
        logger.info(f"  Active Service Fingerprinting Engine initialized (Tor: {use_tor})")
        
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
        if not target or len(target) == 0:
            return False
        
        # Show current IP for verification
        if self.proxy_manager:
            current_ip = self.proxy_manager.get_public_ip(use_proxy=True)
            logger.info(f"🌐 Current public IP: {current_ip}")
        
        restricted = ['localhost', '127.0.0.1', '0.0.0.0']
        if target in restricted:
            print(f"  Warning: Scanning {target} requires explicit permission")
            return False
            
        return True
    

    def execute_go_scanner(self, target: str, start_port: int = 1, 
                          end_port: int = 1000, timeout: int = 2, 
                          threads: int = 100, use_proxy: bool = False) -> Dict[str, Any]:
        """Execute Go scanner with optional proxy support"""
        
        print(f"  Starting stealth scan on {target}...")
        print(f"   Port range: {start_port}-{end_port}")
        print(f"   Threads: {threads}")
        
        if self.proxy_manager:
            if self.proxy_manager.use_tor:
                print(f"     Using Tor network")
            elif self.proxy_manager.proxies:
                print(f"   🔄 Proxy rotation enabled ({len(self.proxy_manager.proxies)} proxies)")
        
        try:
            # Step 1: Build (using centralized build layer)
            scanner_path = build_go_scanner()
            
            # Step 2: Prepare command
            scan_cmd = [
                scanner_path,
                "-target", target,
                "-start", str(start_port),
                "-end", str(end_port),
                "-timeout", str(timeout),
                "-threads", str(threads)
            ]
            
            # Prepare environment
            env = os.environ.copy()
            
            # Add proxy if available
            if use_proxy and self.proxy_manager:
                proxy = self.proxy_manager.get_current_proxy('tor-fallback')
                if proxy:
                    # Pass proxy to Go scanner via environment
                    if self.proxy_manager.use_tor:
                        env['USE_TOR'] = '1'
                        env['SOCKS5_PROXY'] = '127.0.0.1:9050'
                        print(f"   [Tor] Using Tor for Go scanner")
                    
                    # Extract proxy URL
                    proxy_url = proxy.get('http', '')
                    if proxy_url:
                        env['HTTP_PROXY'] = proxy_url
                        env['HTTPS_PROXY'] = proxy_url
                        if not self.proxy_manager.use_tor:
                            print(f"   [IP] Using proxy for Go scanner")
            
            # Execute
            result = subprocess.run(scan_cmd, capture_output=True, 
                                  text=True, timeout=300, env=env, check=False)
            
            if result.returncode != 0:
                raise RuntimeError(f"Scanner execution failed:\n{result.stderr}")
            
            try:
                scan_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                print(f"  Failed to parse JSON. Raw output:\n{result.stdout[:200]}...")
                return {}
            
            # === ACTIVE SERVICE FINGERPRINTING ===
            print(f"\n  Active Service Fingerprinting in progress...")
            fingerprinted_services = self._fingerprint_services(target, scan_data)
            scan_data['services'] = fingerprinted_services
            
            self.scan_results = scan_data
            
            print(f"  Scan completed: {len(scan_data.get('open_ports', []))} open ports found")
            print(f"  Fingerprinted: {len(fingerprinted_services)} services")
            return scan_data
            
        except FileNotFoundError as e:
            print(f"  Dependency error: {e}")
            return {}
        except RuntimeError as e:
            print(f"  {e}")
            return {}
        except subprocess.TimeoutExpired:
            print("  Scanner timeout (5 minutes)")
            return {}
        except Exception as e:
            print(f"  Scanner error: {e}")
            return {}
    
    def _fingerprint_services(self, target: str, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Actively fingerprint all detected services with normalization.
        Identical to base orchestrator but integrated with stealth mode.
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
    
    def fingerprint_discovered_services(self, target: str, ports: list) -> dict:
        """
        Lightweight fingerprinting for stealth-discovered services.
        
        This bridges budgeted discovery (StealthController) with 
        the enrichment pipeline (service fingerprinting).
        
        Args:
            target: Target host
            ports: List of discovered open ports from stealth scan
            
        Returns:
            Scan results dict compatible with existing CVE/reporting pipeline
        """
        print(f"\n  Fingerprinting {len(ports)} discovered service(s)...")
        
        # Create minimal scan_data structure
        scan_data = {
            "open_ports": ports,
            "target": target,
            "stealth_mode": True
        }
        
        # Fingerprint using existing engine (already stealth-aware)
        fingerprinted = self._fingerprint_services(target, scan_data)
        scan_data['services'] = fingerprinted
        
        self.scan_results = scan_data
        
        print(f"  Fingerprinted: {len(fingerprinted)} services")
        return scan_data
    
    def get_results(self) -> Dict[str, Any]:
        """Get current scan results"""
        return self.scan_results

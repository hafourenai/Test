# python/orchestrator.py
"""
Base Scan Orchestrator
Coordinates the vulnerability scanning process
"""

import json
import subprocess
import sys
from typing import Dict, List, Any
from pathlib import Path


class ScanOrchestrator:
    """Orchestrates the vulnerability scanning process"""
    
    def __init__(self, go_scanner_path: str = "../go/main.go"):
        self.go_scanner_path = go_scanner_path
        self.scan_results = {}
        
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
            self.scan_results = scan_data
            
            print(f"✅ Scan completed: {len(scan_data.get('open_ports', []))} open ports found")
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
    
    def get_results(self) -> Dict[str, Any]:
        """Get current scan results"""
        return self.scan_results
    
    def apply_rate_limiting(self, delay: float = 0.1):
        """Apply rate limiting between requests"""
        import time
        time.sleep(delay)

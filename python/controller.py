import random
import time
from .scanner import Scanner
from .port_selector import PortSelector

class StealthController:
    def __init__(
        self,
        port_selector: PortSelector,
        scanner: Scanner,
        target: str,
        stealth: bool
    ):
        self.port_selector = port_selector
        self.scanner = scanner
        self.target = target
        self.stealth = stealth

        self.max_attempts = 20 if stealth else 100
        self.max_duration = 60 if stealth else 300
        self.start_time = time.time()
        self.attempts = 0
        self.discovered_ports = []  # Track discovered ports

        self.ports = self.port_selector.select_ports(stealth)

        if stealth:
            random.shuffle(self.ports)

    def start_scan(self):
        if self.stealth:
            self._stealth_scan()
        else:
            self._normal_scan()

    def _normal_scan(self):
        for port in self.ports:
            if self._scanner_with_budget(port):
                print(f"Service detected on port {port}")
                return

    def _stealth_scan(self):
        scanned_ports = set()
        
        # Priority scan for web ports
        for web_port in [443, 80]:
            if web_port in self.ports:
                if self._scanner_with_budget(web_port):
                    print(f"[STEALTH] Web service detected on port {web_port}")
                    self.discovered_ports.append(web_port)
                scanned_ports.add(web_port)

        # Scan remaining ports (within budget)
        for port in self.ports:
            if port not in scanned_ports:
                # Check if budget exhausted
                if self.attempts >= self.max_attempts:
                    print("[STEALTH] Attempt budget exhausted.")
                    break
                if time.time() - self.start_time > self.max_duration:
                    print("[STEALTH] Time budget exhausted.")
                    break
                    
                if self._scanner_with_budget(port):
                    print(f"[STEALTH] Service detected on port {port}")
                    self.discovered_ports.append(port)

    def _scanner_with_budget(self, port: int) -> bool:
        """Scan a port within budget constraints"""
        self.attempts += 1
        result = self.scanner.scan_port(self.target, port)
        
        # Add stealth delay
        time.sleep(random.uniform(0.5, 2.0))
        
        return result
    
    def get_results(self):
        """
        Return structured scan results for pipeline integration.
        
        Returns:
            Dictionary with discovered ports and metadata
        """
        return {
            "open_ports": self.discovered_ports,
            "target": self.target,
            "stealth_metadata": {
                "attempts_used": self.attempts,
                "max_attempts": self.max_attempts,
                "duration": time.time() - self.start_time,
                "max_duration": self.max_duration,
                "budgeted": self.stealth
            }
        }

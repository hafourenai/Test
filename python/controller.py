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
                    return
                scanned_ports.add(web_port)

        # Scan remaining ports
        for port in self.ports:
            if port not in scanned_ports:
                if self._scanner_with_budget(port):
                    print(f"Service detected on port {port}")
                    return

    def _scanner_with_budget(self, port: int) -> bool:
        if self.attempts >= self.max_attempts:
            print("[STEALTH] Attempt budget exceeded.")
            return False

        if time.time() - self.start_time > self.max_duration:
            print("[STEALTH] Time budget exceeded.")
            return False

        self.attempts += 1

        result = self.scanner.scan_port(self.target, port)

        time.sleep(random.uniform(0.5, 2.0))

        return result

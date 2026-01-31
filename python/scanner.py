import socket

class Scanner:
    def scan_port(self, target: str, port: int) -> bool:
        try:
            with socket.create_connection((target, port), timeout=5):
                return True
        except (socket.timeout, ConnectionRefusedError, socket.gaierror, OSError):
            return False

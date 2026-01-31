import random

class PortSelector:
    COMMON_PORTS = [
        22, 25, 80, 443, 3306, 3389, 5432,
        8080, 8443, 9090, 9200, 5900, 27017
    ]

    def select_ports(self, stealth: bool) -> list:
        if stealth:
            return random.sample(self.COMMON_PORTS, 10)
        return self.COMMON_PORTS.copy()

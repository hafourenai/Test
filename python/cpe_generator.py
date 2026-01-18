"""
CPE Generator - Resolves service information into NIST CPE 2.3 identifiers.
Implements a Hybrid Resolver Pipeline: Static Map -> Fuzzy Match -> Fallback.
"""

import re
import logging
from typing import Dict, Any, Optional

try:
    from rapidfuzz import process, fuzz
except ImportError:
    process = None
    fuzz = None

logger = logging.getLogger(__name__)

class CPEGenerator:
    """Generates CPE 2.3 strings from service detection data"""

    STATIC_MAP = {
        "apache": {"vendor": "apache", "product": "http_server"},
        "nginx": {"vendor": "f5", "product": "nginx"},
        "openssh": {"vendor": "openbsd", "product": "openssh"},
        "openssl": {"vendor": "openssl", "product": "openssl"},
        "mysql": {"vendor": "oracle", "product": "mysql"},
        "mariadb": {"vendor": "mariadb", "product": "mariadb"},
        "postgresql": {"vendor": "postgresql", "product": "postgresql"},
        "redis": {"vendor": "redislabs", "product": "redis"},
        "iis": {"vendor": "microsoft", "product": "iis"},
        "vsftpd": {"vendor": "vsftpd_project", "product": "vsftpd"},
        "proftpd": {"vendor": "proftpd", "product": "proftpd"},
        "postfix": {"vendor": "postfix", "product": "postfix"},
    }

    def __init__(self, nvd_client: Optional[Any] = None):
        self.nvd_client = nvd_client

        # === RapidFuzz compatibility layer (v2 & v3+) ===
        self.fuzzy_scorer = None
        if fuzz:
            if hasattr(fuzz, "partial_ratio"):
                self.fuzzy_scorer = fuzz.partial_ratio   # RapidFuzz v3+
            else:
                self.fuzzy_scorer = fuzz.PARTIAL_RATIO   # RapidFuzz v2.x

    def generate(self, service_info: Dict[str, Any]) -> str:
        """
        Generate CPE from service information.
        Now enhanced to consume fingerprinted data from Active Service Fingerprinting Engine.
        
        Priority:
        1. Use fingerprinted 'product' and 'version' fields (from service_fingerprinter.py)
        2. Fall back to banner parsing for legacy compatibility
        """
        # Extract fingerprinted data (preferred)
        product = service_info.get('product', '').lower()
        version = service_info.get('version', '*')
        service = service_info.get('service', '').lower()
        banner = service_info.get('banner', '').lower()

        version = self._clean_version(version)

        # If we have fingerprinted product data, use it directly
        if product and product != 'unknown':
            cpe_base = self._match_static(product, banner)
            if cpe_base:
                return self._build_cpe(cpe_base['vendor'], cpe_base['product'], version)
        
        # Otherwise fall back to service/banner matching
        cpe_base = self._match_static(service, banner)
        if cpe_base:
            return self._build_cpe(cpe_base['vendor'], cpe_base['product'], version)

        if process and self.fuzzy_scorer:
            query = product if product != 'unknown' else service
            cpe_base = self._match_fuzzy(query, banner)
            if cpe_base:
                return self._build_cpe(cpe_base['vendor'], cpe_base['product'], version)

        if self.nvd_client:
            logger.debug(f"Attempting NVD Fallback for: {service} ({banner})")

        vendor = product if product != 'unknown' else service or "*"
        product_name = product if product != 'unknown' else service or "*"
        return self._build_cpe(vendor, product_name, version)

    def _match_static(self, service: str, banner: str) -> Optional[Dict[str, str]]:
        combined = f"{service} {banner}".lower()
        for key, value in self.STATIC_MAP.items():
            if key in combined:
                return value
        return None

    def _match_fuzzy(self, service: str, banner: str) -> Optional[Dict[str, str]]:
        query = f"{service} {banner}".strip()
        if not query:
            return None

        choices = list(self.STATIC_MAP.keys())

        match = process.extractOne(
            query,
            choices,
            scorer=self.fuzzy_scorer
        )

        if match and match[1] >= 85:
            return self.STATIC_MAP[match[0]]
        return None

    def _clean_version(self, version: str) -> str:
        if not version or version == "unknown":
            return "*"

        match = re.search(r'(\d+\.[\d\.]+)', version)
        if match:
            return match.group(1).rstrip('.')
        return version

    def _build_cpe(self, vendor: str, product: str, version: str) -> str:
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

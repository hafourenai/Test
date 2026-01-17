# python/cpe_generator.py
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
    # Fallback if rapidfuzz is not yet installed in the environment
    process = None
    fuzz = None

logger = logging.getLogger(__name__)

class CPEGenerator:
    """Generates CPE 2.3 strings from service detection data"""
    
    # Static mapping for the most common services to ensure high accuracy
    STATIC_MAP = {
        "apache": {"vendor": "apache", "product": "http_server"},
        "nginx": {"vendor": "f5", "product": "nginx"}, # NGINX is now F5
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

    def generate(self, service_info: Dict[str, Any]) -> str:
        """
        Translates messy fingerprint data into a valid CPE 2.3 string.
        Pipeline: Static -> Fuzzy -> Fallback (NVD API)
        """
        service = service_info.get('service', '').lower()
        banner = service_info.get('banner', '').lower()
        version = service_info.get('version', '*')
        
        # 1. Clean version (remove trailing trash)
        version = self._clean_version(version)
        
        # 2. Try Static Map
        cpe_base = self._match_static(service, banner)
        if cpe_base:
            return self._build_cpe(cpe_base['vendor'], cpe_base['product'], version)
            
        # 3. Try Fuzzy Match (if rapidfuzz is available)
        if process:
            cpe_base = self._match_fuzzy(service, banner)
            if cpe_base:
                return self._build_cpe(cpe_base['vendor'], cpe_base['product'], version)
        
        # 4. Fallback (NVD API Search - if client provided)
        if self.nvd_client:
            logger.debug(f"Attempting NVD Fallback for: {service} ({banner})")
            # Logic for NVD CPE search would go here if client has the method
        
        # 5. Last Resort: Best Guess (Generic)
        vendor = service or "*"
        product = service or "*"
        return self._build_cpe(vendor, product, version)

    def _match_static(self, service: str, banner: str) -> Optional[Dict[str, str]]:
        """Checks if service or banner keywords exist in STATIC_MAP"""
        combined = f"{service} {banner}".lower()
        for key, value in self.STATIC_MAP.items():
            if key in combined:
                return value
        return None

    def _match_fuzzy(self, service: str, banner: str) -> Optional[Dict[str, str]]:
        """Uses fuzzy logic to resolve vendor/product"""
        query = f"{service} {banner}".strip()
        choices = list(self.STATIC_MAP.keys())
        
        # Find best match above 85% confidence
        match = process.extractOne(query, choices, scorer=fuzz.PARTIAL_RATIO)
        if match and match[1] >= 85:
            return self.STATIC_MAP[match[0]]
        return None

    def _clean_version(self, version: str) -> str:
        """Sanitizes version strings for CPE format"""
        if not version or version == "unknown":
            return "*"
        # Extract only the numeric/dotted part + optional letters (e.g., 2.4.58-ubuntu1 -> 2.4.58)
        match = re.search(r'(\d+\.[\d\.]+)', version)
        if match:
            return match.group(1).rstrip('.')
        return version

    def _build_cpe(self, vendor: str, product: str, version: str) -> str:
        """Constructs a CPE 2.3 string"""
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

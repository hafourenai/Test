# python/nvd_client.py
"""
NVD API Client - Real-time vulnerability intelligence from NIST.
Implements 24h SQLite caching, CPE deduplication, and rate-limit handling.
"""

import os
import time
import json
import sqlite3
import logging
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class NVDClient:
    """Professional NVD API v2.0 Client with persistent caching"""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CACHE_DB = "nvd_cache.db"
    
    def __init__(self, api_key: Optional[str] = None, cache_dir: str = ".cache"):
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.cache_dir = cache_dir
        self.session = requests.Session()
        
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
            
        self.db_path = os.path.join(self.cache_dir, self.CACHE_DB)
        self._init_db()
        
        # Rate limiting state
        self.last_request_time = 0
        self.request_delay = 0.6 if self.api_key else 6.0 # NIST limits: 6s without key, 0.6s with key

    def _init_db(self):
        """Initializes the persistent SQLite cache"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_cache (
                    cpe_name TEXT PRIMARY KEY,
                    data TEXT,
                    timestamp DATETIME
                )
            """)

    def query_by_cpe(self, cpe_name: str) -> List[Dict[str, Any]]:
        """
        Queries NVD for vulnerabilities by CPE name.
        Checks cache first (24h TTL).
        """
        # 1. Check Cache
        cached_data = self._get_from_cache(cpe_name)
        if cached_data:
            logger.debug(f"Cache hit for {cpe_name}")
            return cached_data

        # 2. Rate Limit Handling
        self._wait_for_rate_limit()

        # 3. API Request
        logger.info(f"Querying NVD API for {cpe_name}")
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
            
        params = {"cpeName": cpe_name}
        
        try:
            response = self.session.get(self.BASE_URL, params=params, headers=headers, timeout=15)
            
            if response.status_code == 429:
                logger.warning("NVD API Rate limit hit. Cooling down...")
                time.sleep(30)
                return self.query_by_cpe(cpe_name) # Recursive retry
                
            response.raise_for_status()
            data = response.json()
            
            # Extract relevant CVE info
            vulnerabilities = self._parse_vulnerabilities(data)
            
            # 4. Save to Cache
            self._save_to_cache(cpe_name, vulnerabilities)
            
            self.last_request_time = time.time()
            return vulnerabilities

        except Exception as e:
            logger.error(f"NVD API request failed for {cpe_name}: {e}")
            return []

    def _get_from_cache(self, cpe_name: str) -> Optional[List[Dict[str, Any]]]:
        """Retrieves data from SQLite cache if not expired (24h)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT data, timestamp FROM cve_cache WHERE cpe_name = ?", 
                    (cpe_name,)
                )
                row = cursor.fetchone()
                
                if row:
                    data_str, ts_str = row
                    timestamp = datetime.fromisoformat(ts_str)
                    
                    if datetime.now() - timestamp < timedelta(hours=24):
                        return json.loads(data_str)
        except Exception as e:
            logger.error(f"Cache read error: {e}")
        return None

    def _save_to_cache(self, cpe_name: str, data: List[Dict[str, Any]]):
        """Saves API response to the persistent cache"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO cve_cache (cpe_name, data, timestamp) VALUES (?, ?, ?)",
                    (cpe_name, json.dumps(data), datetime.now().isoformat())
                )
        except Exception as e:
            logger.error(f"Cache write error: {e}")

    def _wait_for_rate_limit(self):
        """Enforces NIST-compliant rate limiting"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.request_delay:
            time.sleep(self.request_delay - elapsed)

    def _parse_vulnerabilities(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parses raw NVD JSON into internal vulnerability objects"""
        parsed = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            
            # Prefer CVSS v3.1, then 3.0, then 2.0
            cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
            cvss_v30 = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
            cvss_v2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
            
            active_cvss = cvss_v31 or cvss_v30 or cvss_v2
            
            # Combined info
            parsed.append({
                "cve_id": cve.get("id"),
                "description": cve.get("descriptions", [{}])[0].get("value", ""),
                "cvss_score": active_cvss.get("baseScore", 0.0),
                "severity": active_cvss.get("baseSeverity", "UNKNOWN").upper(),
                "vector": active_cvss.get("vectorString", ""),
                "exploitability_score": cvss_v31.get("exploitabilityScore", cvss_v30.get("exploitabilityScore", 0.0)),
                "user_interaction": active_cvss.get("userInteraction", "NONE"),
                "privileges_required": active_cvss.get("privilegesRequired", "NONE"),
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified")
            })
        return parsed

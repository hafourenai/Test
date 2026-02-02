"""
NVD API Client - Tor-Enabled Version
Supports NVD API 2.0 with proper error handling, rate limiting, and Tor integration
"""

import time
import logging
import sys
import os
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import json
import requests
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from python.tor_session import TorSession
    from python.config import NVD_API_KEY, TOR_SOCKS_PROXY
    TOR_AVAILABLE = True
except ImportError:
    TOR_AVAILABLE = False
    TorSession = None  # Define TorSession to avoid NameError
    import requests

logger = logging.getLogger(__name__)


class NVDClient:
    """Client for interacting with NVD API 2.0"""
    
    def __init__(self, api_key: Optional[str] = None, use_tor: bool = False):
        """
        Initialize NVD Client
        
        Args:
            api_key: Optional NVD API key for higher rate limits
                    Get one free at: https://nvd.nist.gov/developers/request-an-api-key
            use_tor: Whether to route traffic through Tor (default: False)
        """
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key or os.getenv('NVD_API_KEY')
        self.use_tor = use_tor
        
        # Initialize session (Tor or regular)
        if use_tor and TOR_AVAILABLE:
            self.session = TorSession()
            logger.info("[Tor] NVD Client using Tor network")
        elif use_tor and not TOR_AVAILABLE:
            logger.warning("[!] Tor requested but not available, using direct connection")
            import requests
            self.session = requests.Session()
        else:
            import requests
            self.session = requests.Session()
        
        # Rate limiting
        if api_key:
            self.requests_per_30_seconds = 50  # With API key
            self.sleep_time = 0.6  # 30s / 50 requests
        else:
            self.requests_per_30_seconds = 5   # Without API key
            self.sleep_time = 6.0  # 30s / 5 requests
        
        self.last_request_time = 0
        
        # Setup headers
        self.headers = {
            'User-Agent': 'VulnerabilityScanner/2.0 (Educational Purpose)',
            'Accept': 'application/json'
        }
        
        if self.api_key:
            self.headers['apiKey'] = self.api_key
            logger.info("[Success] NVD API initialized with API key (50 req/30s)")
        else:
            logger.warning("[!] NVD API initialized without API key (5 req/30s)")
            logger.warning("   Get free API key: https://nvd.nist.gov/developers/request-an-api-key")
    
    def _rate_limit(self):
        """Enforce rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.sleep_time:
            sleep_duration = self.sleep_time - time_since_last
            logger.debug(f"Rate limiting: sleeping {sleep_duration:.2f}s")
            time.sleep(sleep_duration)
        
        self.last_request_time = time.time()
    
    def search_by_cpe(self, cpe_name: str, max_results: int = 100) -> List[Dict]:
        """
        Search CVEs by CPE name
        
        Args:
            cpe_name: CPE 2.3 formatted string (e.g., "cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*:*")
            max_results: Maximum number of results to return
            
        Returns:
            List of CVE dictionaries
        """
        self._rate_limit()
        
        # Remove wildcards from CPE for better matching
        # NVD API 2.0 uses cpeName parameter for exact matching
        # or virtualMatchString for partial matching
        
        params = {
            'resultsPerPage': min(max_results, 2000),  # API max is 2000
        }
        
        # Determine if we should use cpeName (exact) or virtualMatchString (partial)
        if '*' in cpe_name or cpe_name.count(':') < 12:
            # Use virtual match for wildcards or incomplete CPEs
            params['virtualMatchString'] = cpe_name
            logger.debug(f"Using virtualMatchString: {cpe_name}")
        else:
            # Use exact match for complete CPEs
            params['cpeName'] = cpe_name
            logger.debug(f"Using cpeName: {cpe_name}")
        
        try:
            logger.info(f"[Query] Querying NVD API for: {cpe_name}")
            
            # Use TorSession.get() or requests.Session.get() depending on session type
            if isinstance(self.session, TorSession):
                response = self.session.get(
                    self.base_url,
                    params=params,
                    headers=self.headers,
                    timeout=30
                )
            else:
                response = self.session.get(
                    self.base_url,
                    params=params,
                    headers=self.headers,
                    timeout=30
                )
            
            # Log the actual URL for debugging
            logger.debug(f"Request URL: {response.url}")
            
            if response.status_code == 403:
                logger.error("[Error] NVD API rate limit exceeded or access forbidden")
                logger.info("[Info] Consider getting an API key or waiting before retrying")
                return []
            
            if response.status_code == 404:
                logger.warning(f"[Warning] No CVEs found for: {cpe_name}")
                return []
            
            response.raise_for_status()
            
            data = response.json()
            
            vulnerabilities = data.get('vulnerabilities', [])
            total_results = data.get('totalResults', 0)
            
            logger.info(f"[Success] Found {total_results} CVEs for {cpe_name}")
            
            # Use same extraction logic as search_by_cpe
            return self._extract_cves(data)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"[Error] NVD API request failed: {e}")
            return []
        except Exception as e:
            logger.error(f"[Error] Unexpected error querying NVD: {e}")
            return []
    
    def search_by_keyword(self, keyword: str, max_results: int = 100) -> List[Dict]:
        """
        Search CVEs by keyword
        
        Args:
            keyword: Search keyword (e.g., "nginx", "openssh")
            max_results: Maximum number of results
            
        Returns:
            List of CVE dictionaries
        """
        self._rate_limit()
        
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': min(max_results, 2000)
        }
        
        try:
            if isinstance(self.session, TorSession):
                response = self.session.get(
                    self.base_url,
                    params=params,
                    headers=self.headers,
                    timeout=30
                )
            else:
                response = self.session.get(
                    self.base_url,
                    params=params,
                    headers=self.headers,
                    timeout=30
                )
            
            response.raise_for_status()
            data = response.json()
            
            total_results = data.get('totalResults', 0)
            logger.info(f"  Found {total_results} CVEs for keyword: {keyword}")
            
            # Use same extraction logic as search_by_cpe
            return self._extract_cves(data)
            
        except Exception as e:
            logger.error(f"  Keyword search failed: {e}")
            return []
    
    def get_cves_for_service(self, service_name: str, version: str = None) -> List[Dict]:
        """
        Get CVEs for a service, trying multiple strategies
        
        Args:
            service_name: Service name (e.g., "nginx", "openssh")
            version: Optional version number
            
        Returns:
            List of CVE dictionaries sorted by severity
        """
        cves = []
        
        # Strategy 1: Try keyword search first (broader)
        keyword = f"{service_name} {version}" if version else service_name
        cves.extend(self.search_by_keyword(keyword, max_results=50))
        
        # Strategy 2: Try common CPE patterns
        if not cves:
            cpe_patterns = self._generate_cpe_patterns(service_name, version)
            for cpe in cpe_patterns:
                results = self.search_by_cpe(cpe, max_results=50)
                cves.extend(results)
                if results:
                    break  # Stop if we found results
        
        # Remove duplicates and sort by severity
        seen = set()
        unique_cves = []
        for cve in cves:
            if cve['id'] not in seen:
                seen.add(cve['id'])
                unique_cves.append(cve)
        
        # Sort by CVSS score (highest first)
        unique_cves.sort(key=lambda x: (x.get('cvss_v3') or x.get('cvss_v2') or 0), reverse=True)
        
        return unique_cves
    
    def _generate_cpe_patterns(self, service_name: str, version: str = None) -> List[str]:
        """Generate possible CPE patterns for a service"""
        patterns = []
        
        # Common vendor mappings
        vendor_map = {
            'nginx': ['nginx', 'f5'],
            'openssh': ['openbsd', 'openssh'],
            'apache': ['apache'],
            'mysql': ['mysql', 'oracle'],
            'postgresql': ['postgresql'],
            'vsftpd': ['vsftpd_project'],
            'proftpd': ['proftpd'],
        }
        
        service_lower = service_name.lower()
        vendors = vendor_map.get(service_lower, [service_lower])
        
        for vendor in vendors:
            if version:
                # Exact version
                patterns.append(f"cpe:2.3:a:{vendor}:{service_lower}:{version}:*:*:*:*:*:*:*")
            # Wildcard version for broader search
            patterns.append(f"cpe:2.3:a:{vendor}:{service_lower}:*:*:*:*:*:*:*:*")
        
        return patterns
    
    def _extract_cpes(self, data: Dict) -> List[Dict]:
        """Extract CPE information from API response"""
        cpe_matches = []
        vulnerabilities = data.get('vulnerabilities', [])
        
        for vuln in vulnerabilities:
            cve = vuln.get('cve', {})
            cve_id = cve.get('id', 'Unknown')
            
            # Extract CPE data from configurations
            cpe_data = self._extract_cpe_data(cve)
            cpe_matches.extend(cpe_data)
        
        return cpe_matches

    def _extract_cpe_data(self, cve: Dict) -> List[Dict]:
        """Extract CPE version range data from CVE structure"""
        cpe_data = []
        configurations = cve.get('configurations', [])
        
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe_match in cpe_matches:
                    cpe_info = {
                        'cpe23Uri': cpe_match.get('cpe23Uri', ''),
                        'vulnerable': cpe_match.get('vulnerable', True),
                        'versionStartIncluding': cpe_match.get('versionStartIncluding'),
                        'versionEndIncluding': cpe_match.get('versionEndIncluding'),
                        'versionStartExcluding': cpe_match.get('versionStartExcluding'),
                        'versionEndExcluding': cpe_match.get('versionEndExcluding')
                    }
                    
                    if cpe_info['cpe23Uri']:
                        parsed = self._parse_cpe_uri(cpe_info['cpe23Uri'])
                        cpe_info.update(parsed)
                    
                    cpe_data.append(cpe_info)
        
        return cpe_data
    
    def _parse_cpe_uri(self, cpe_uri: str) -> Dict:
        """Parse CPE 2.3 URI to extract vendor, product, version"""
        if not cpe_uri:
            return {'vendor': '', 'product': '', 'version': ''}
        
        parts = cpe_uri.split(':')
        if len(parts) < 6:
            return {'vendor': '', 'product': '', 'version': ''}
        
        return {
            'vendor': parts[3] if len(parts) > 3 else '',
            'product': parts[4] if len(parts) > 4 else '',
            'version': parts[5] if len(parts) > 5 else ''
        }
    
    def _extract_cves(self, data: Dict) -> List[Dict]:
        """Extract CVE information from API response"""
        cves = []
        vulnerabilities = data.get('vulnerabilities', [])
        
        for vuln in vulnerabilities:
            cve = vuln.get('cve', {})
            cve_id = cve.get('id', 'Unknown')
            
            metrics = cve.get('metrics', {})
            cvss_v3 = None
            cvss_v2 = None
            severity = 'Unknown'
            
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_v3 = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                severity = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_v3 = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                severity = metrics['cvssMetricV30'][0]['cvssData']['baseSeverity']
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_v2 = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                severity = self._cvss_v2_to_severity(cvss_v2)
            
            descriptions = cve.get('descriptions', [])
            description = next(
                (d['value'] for d in descriptions if d.get('lang') == 'en'),
                'No description available'
            )
            
            # Extract CPE data for   version matching
            cpe_data = self._extract_cpe_data(cve)
            
            cves.append({
                'id': cve_id,
                'description': description,
                'cvss_v3': cvss_v3,
                'cvss_v2': cvss_v2,
                'severity': severity,
                'published': cve.get('published', ''),
                'modified': cve.get('lastModified', ''),
                'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                'cpe_data': cpe_data
            })
        
        return cves
    
    def _cvss_v2_to_severity(self, score: float) -> str:
        """Convert CVSS v2 score to severity rating"""
        if score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'


# Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s:%(name)s:%(message)s'
    )
    
    # Initialize client (add your API key if you have one)
    client = NVDClient(api_key=None)  # or api_key="your-key-here"
    
    # Test 1: Search for nginx vulnerabilities
    print("\n" + "="*60)
    print("Test 1: Searching for nginx vulnerabilities")
    print("="*60)
    nginx_cves = client.get_cves_for_service('nginx', '1.24.0')
    
    if nginx_cves:
        print(f"\n  Found {len(nginx_cves)} CVEs for nginx 1.24.0")
        print("\nTop 3 vulnerabilities:")
        for cve in nginx_cves[:3]:
            print(f"\n  {cve['id']} - {cve['severity']}")
            print(f"   CVSS: {cve.get('cvss_v3') or cve.get('cvss_v2')}")
            print(f"   {cve['description'][:150]}...")
            print(f"   URL: {cve['url']}")
    else:
        print("  No CVEs found")
    
    # Test 2: Search for OpenSSH vulnerabilities
    print("\n" + "="*60)
    print("Test 2: Searching for OpenSSH vulnerabilities")
    print("="*60)
    ssh_cves = client.get_cves_for_service('openssh', '9.6')
    
    if ssh_cves:
        print(f"\n  Found {len(ssh_cves)} CVEs for OpenSSH 9.6")
        print("\nTop 3 vulnerabilities:")
        for cve in ssh_cves[:3]:
            print(f"\n  {cve['id']} - {cve['severity']}")
            print(f"   CVSS: {cve.get('cvss_v3') or cve.get('cvss_v2')}")
            print(f"   {cve['description'][:150]}...")
    else:
        print("  No CVEs found")
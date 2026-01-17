# python/nvd_fetcher.py
"""
NVD API Integration
Fetches CVE data from NIST National Vulnerability Database
"""

import requests
import json
import time
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class NVDFetcher:
    """Fetches CVE data from NVD API"""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize NVD Fetcher
        
        Args:
            api_key: NVD API key (optional, but recommended for higher rate limits)
        """
        self.api_key = api_key or os.getenv('NVD_API_KEY')
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Rate limiting
        if self.api_key:
            self.requests_per_30s = 50  # With API key
            self.delay_between_requests = 0.6  # 600ms
        else:
            self.requests_per_30s = 5  # Without API key
            self.delay_between_requests = 6.0  # 6 seconds
        
        self.last_request_time = 0
        
        logger.info(f"NVD Fetcher initialized {'with' if self.api_key else 'without'} API key")
        logger.info(f"Rate limit: {self.requests_per_30s} requests per 30 seconds")
    
    def _rate_limit(self):
        """Apply rate limiting between requests"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.delay_between_requests:
            sleep_time = self.delay_between_requests - time_since_last
            logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def fetch_recent_cves(self, days: int = 30, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Fetch recent CVEs from NVD
        
        Args:
            days: Number of days to look back (default: 30)
            severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
        
        Returns:
            List of CVE entries
        """
        logger.info(f"Fetching CVEs from last {days} days...")
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT00:00:00.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT23:59:59.999'),
        }
        
        if severity:
            params['cvssV3Severity'] = severity
        
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        cves = []
        start_index = 0
        results_per_page = 2000
        
        while True:
            self._rate_limit()
            
            params['startIndex'] = start_index
            params['resultsPerPage'] = results_per_page
            
            try:
                logger.info(f"Fetching CVEs (index {start_index})...")
                response = requests.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get('vulnerabilities', [])
                    
                    for vuln in vulnerabilities:
                        cve_data = self._parse_cve(vuln)
                        if cve_data:
                            cves.append(cve_data)
                    
                    total_results = data.get('totalResults', 0)
                    logger.info(f"Retrieved {len(vulnerabilities)} CVEs (total: {total_results})")
                    
                    # Check if we have more results
                    if start_index + len(vulnerabilities) >= total_results:
                        break
                    
                    start_index += len(vulnerabilities)
                else:
                    logger.error(f"NVD API error: {response.status_code} - {response.text}")
                    break
                    
            except Exception as e:
                logger.error(f"Error fetching CVEs: {e}")
                break
        
        logger.info(f"✅ Fetched {len(cves)} CVEs total")
        return cves
    
    def fetch_cves_by_keyword(self, keyword: str, max_results: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch CVEs by keyword search
        
        Args:
            keyword: Search keyword (e.g., 'apache', 'nginx', 'ssh')
            max_results: Maximum number of results to fetch
        
        Returns:
            List of CVE entries
        """
        logger.info(f"Searching CVEs for keyword: '{keyword}'...")
        
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': min(max_results, 2000)
        }
        
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        self._rate_limit()
        
        try:
            response = requests.get(
                self.base_url,
                params=params,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                cves = []
                for vuln in vulnerabilities:
                    cve_data = self._parse_cve(vuln)
                    if cve_data:
                        cves.append(cve_data)
                
                logger.info(f"✅ Found {len(cves)} CVEs for '{keyword}'")
                return cves
            else:
                logger.error(f"NVD API error: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error searching CVEs: {e}")
            return []
    
    def _parse_cve(self, vuln_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse CVE data from NVD API response
        
        Args:
            vuln_data: Raw vulnerability data from API
        
        Returns:
            Parsed CVE entry or None
        """
        try:
            cve = vuln_data.get('cve', {})
            cve_id = cve.get('id', 'UNKNOWN')
            
            # Get description
            descriptions = cve.get('descriptions', [])
            description = next(
                (d['value'] for d in descriptions if d.get('lang') == 'en'),
                'No description available'
            )
            
            # Get CVSS scores
            metrics = cve.get('metrics', {})
            cvss_v3 = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', [])
            
            cvss_score = 0.0
            severity = 'Unknown'
            
            if cvss_v3:
                cvss_data = cvss_v3[0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = cvss_data.get('baseSeverity', 'Unknown')
            
            # Get references
            references = []
            ref_data = cve.get('references', [])
            for ref in ref_data[:3]:  # Limit to 3 references
                url = ref.get('url', '')
                if url:
                    references.append(url)
            
            # Try to extract affected products/services
            configurations = cve.get('configurations', [])
            affected_services = set()
            
            for config in configurations:
                nodes = config.get('nodes', [])
                for node in nodes:
                    cpe_matches = node.get('cpeMatch', [])
                    for cpe in cpe_matches:
                        criteria = cpe.get('criteria', '')
                        # Extract product name from CPE
                        # CPE format: cpe:2.3:a:vendor:product:version:...
                        parts = criteria.split(':')
                        if len(parts) >= 5:
                            product = parts[4]
                            affected_services.add(product)
            
            # Determine service type for matching
            service = 'unknown'
            description_lower = description.lower()
            
            if any(x in description_lower for x in ['apache', 'nginx', 'http', 'web']):
                service = 'http'
            elif 'ssh' in description_lower or 'openssh' in description_lower:
                service = 'ssh'
            elif 'ftp' in description_lower:
                service = 'ftp'
            elif 'mysql' in description_lower or 'mariadb' in description_lower:
                service = 'mysql'
            elif 'postgresql' in description_lower or 'postgres' in description_lower:
                service = 'postgresql'
            elif 'redis' in description_lower:
                service = 'redis'
            elif 'mongodb' in description_lower:
                service = 'mongodb'
            elif 'smtp' in description_lower or 'mail' in description_lower:
                service = 'smtp'
            
            return {
                'cve_id': cve_id,
                'service': service,
                'version_pattern': '.*',  # Match all versions by default
                'description': description[:200],  # Truncate long descriptions
                'severity': severity,
                'cvss_score': cvss_score,
                'references': references,
                'affected_products': list(affected_services)[:5]  # Limit to 5
            }
            
        except Exception as e:
            logger.warning(f"Error parsing CVE: {e}")
            return None
    
    def save_to_json(self, cves: List[Dict[str, Any]], output_file: str):
        """
        Save CVEs to JSON file
        
        Args:
            cves: List of CVE entries
            output_file: Output file path
        """
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            'cve_database': cves,
            'metadata': {
                'version': '2.0',
                'last_updated': datetime.now().isoformat(),
                'total_cves': len(cves),
                'sources': ['NVD - National Vulnerability Database'],
                'api_used': 'NVD API 2.0'
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"✅ Saved {len(cves)} CVEs to {output_file}")
    
    def fetch_critical_cves(self, max_results: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch only critical severity CVEs
        
        Args:
            max_results: Maximum number of results
        
        Returns:
            List of critical CVE entries
        """
        return self.fetch_recent_cves(days=365, severity='CRITICAL')[:max_results]
    
    def fetch_high_severity_cves(self, max_results: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch high severity CVEs
        
        Args:
            max_results: Maximum number of results
        
        Returns:
            List of high severity CVE entries
        """
        return self.fetch_recent_cves(days=365, severity='HIGH')[:max_results]


def update_cve_database(api_key: Optional[str] = None, output_file: str = '../config/cve_feed.json'):
    """
    Update CVE database from NVD
    
    Args:
        api_key: NVD API key (optional)
        output_file: Output file path
    """
    print("🔄 Updating CVE database from NVD...")
    
    fetcher = NVDFetcher(api_key=api_key)
    
    # Fetch critical and high severity CVEs from last year
    print("\n📥 Fetching CRITICAL CVEs...")
    critical_cves = fetcher.fetch_critical_cves(max_results=50)
    
    print("\n📥 Fetching HIGH severity CVEs...")
    high_cves = fetcher.fetch_high_severity_cves(max_results=50)
    
    # Combine and deduplicate
    all_cves = critical_cves + high_cves
    unique_cves = {cve['cve_id']: cve for cve in all_cves}.values()
    cve_list = list(unique_cves)
    
    # Sort by CVSS score (highest first)
    cve_list.sort(key=lambda x: x['cvss_score'], reverse=True)
    
    # Save to file
    fetcher.save_to_json(cve_list, output_file)
    
    print(f"\n✅ CVE database updated successfully!")
    print(f"   Total CVEs: {len(cve_list)}")
    print(f"   Critical: {sum(1 for c in cve_list if c['severity'] == 'CRITICAL')}")
    print(f"   High: {sum(1 for c in cve_list if c['severity'] == 'HIGH')}")
    print(f"   Output: {output_file}")


if __name__ == '__main__':
    # Load API key from .env file
    from pathlib import Path
    import re
    
    env_file = Path(__file__).parent.parent / '.env'
    api_key = None
    
    if env_file.exists():
        with open(env_file, 'r') as f:
            content = f.read()
            match = re.search(r'NVD_API_KEY\s*=\s*([a-f0-9-]+)', content)
            if match:
                api_key = match.group(1)
                print(f"✅ Loaded API key from .env: {api_key[:8]}...")
    
    if not api_key:
        print("⚠️  No API key found in .env file")
        print("   Continuing with public rate limits (slower)")
    
    # Update database
    update_cve_database(api_key=api_key)

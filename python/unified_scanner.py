"""
Unified Scanner Orchestrator
Integrates stealth engine, payload manager, proxy rotation, and CVE matching
"""

import asyncio
import logging
import time
from typing import List, Dict, Any, Optional, Set
from pathlib import Path
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re
import json
import datetime

try:
    from stealth_engine import StealthEngine
    from payload_manager import PayloadManager
    from proxy_manager import ProxyManager
    from tor_session import TorSession
    from modules.nvd.cve_matcher import CVEMatcher
    from modules.service_fingerprinter import ServiceFingerprinter
    from config import (
        DEFAULT_STEALTH_LEVEL, DEFAULT_PROXY_STRATEGY, NVD_API_KEY, 
        EXPORT_DIR, DEFAULT_EXPORT_FORMAT, DEFAULT_MAX_DEPTH, 
        DEFAULT_MAX_PAGES, DEFAULT_PORTS, CORE_DISCOVERY_PATHS
    )
except ImportError:
    # If run as a package (e.g. from parent dir with -m python.unified_scanner)
    from .stealth_engine import StealthEngine
    from .payload_manager import PayloadManager
    from .proxy_manager import ProxyManager
    from .tor_session import TorSession
    from .modules.nvd.cve_matcher import CVEMatcher
    from .modules.service_fingerprinter import ServiceFingerprinter
    from .config import (
        DEFAULT_STEALTH_LEVEL, DEFAULT_PROXY_STRATEGY, NVD_API_KEY, 
        EXPORT_DIR, DEFAULT_EXPORT_FORMAT, DEFAULT_MAX_DEPTH, 
        DEFAULT_MAX_PAGES, DEFAULT_PORTS, CORE_DISCOVERY_PATHS
    )

logger = logging.getLogger(__name__)


class UnifiedScanner:
    """
    Unified vulnerability scanner with integrated stealth, proxy rotation, and CVE matching
    """
    
    def __init__(
        self,
        stealth_level: str = DEFAULT_STEALTH_LEVEL,
        use_tor: bool = False,
        use_proxies: bool = False,
        proxies_file: str = 'proxies.txt',
        proxy_strategy: str = DEFAULT_PROXY_STRATEGY,
        nvd_api_key: Optional[str] = None,
        enable_cve_matching: bool = True,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_pages: int = DEFAULT_MAX_PAGES
    ):
        """
        Initialize unified scanner
        
        Args:
            stealth_level: Stealth mode level (ghost, ninja, balanced, fast,  )
            use_tor: Enable Tor routing
            use_proxies: Enable proxy rotation
            proxies_file: Path to proxies file
            proxy_strategy: Proxy rotation strategy
            nvd_api_key: NVD API key for CVE matching
            enable_cve_matching: Enable CVE correlation
            max_depth: Maximum crawling depth
            max_pages: Maximum number of pages to crawl
        """
        logger.info("="*60)
        logger.info("Initializing Unified Vulnerability Scanner")
        logger.info("="*60)
        
        # Initialize stealth engine
        self.stealth_engine = StealthEngine(stealth_level=stealth_level)
        logger.info(f"[Init] Stealth Engine: {stealth_level} mode")
        
        # Initialize payload manager
        self.payload_manager = PayloadManager()
        logger.info("[Init] Payload Manager: Ready")
        
        # Initialize proxy manager (if enabled)
        self.proxy_manager = None
        if use_proxies or use_tor:
            # Smart path resolution for proxies_file
            p_path = Path(proxies_file)
            if not p_path.exists():
                # Try relative to the project root (parent of 'python/' folder)
                root_proxies = Path(__file__).parent.parent / proxies_file
                if root_proxies.exists():
                    proxies_file = str(root_proxies)
                    logger.info(f"[Init] Found proxies at root: {proxies_file}")
            
            self.proxy_manager = ProxyManager(
                proxies_file=proxies_file,
                use_tor=use_tor,
                strategy=proxy_strategy
            )
            logger.info(f"[Init] Proxy Manager: {proxy_strategy} strategy")
        
        # Initialize service fingerprinter
        self.fingerprinter = ServiceFingerprinter(use_tor=use_tor)
        logger.info("[Init] Service Fingerprinter: Ready")
        
        # Initialize CVE matcher (if enabled)
        self.cve_matcher = None
        if enable_cve_matching:
            self.cve_matcher = CVEMatcher(
                nvd_api_key=nvd_api_key,
                use_tor=use_tor,
                scoring=True
            )
            logger.info("[Init] CVE Matcher: Enabled")
        
        # Discovery limits
        self.max_depth = max_depth
        self.max_pages = max_pages
        
        # Scan statistics
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'vulnerabilities_found': 0,
            'waf_detected': False,
            'start_time': None,
            'end_time': None
        }
        
        # Discovered web assets
        self.discovered_urls = set()
        self.discovered_forms = []
        self.discovered_params = {} # url -> list of params
        self.misconfigurations = [] # List of findings
        self.tech_stacks = {} # url -> tech info
        
        # Load advanced payloads automatically
        self._auto_load_payloads()

        logger.info("="*60)
        logger.info("[Success] Scanner initialization complete")
        logger.info("="*60)

    def _auto_load_payloads(self):
        """Automatically load advanced payloads from project Payloads directory"""
        # Get absolute path to the project root
        project_root = Path(__file__).resolve().parent.parent
        base_path = project_root / 'Payloads'
        
        if not base_path.exists():
            # Try lowercase if not found
            base_path = project_root / 'payloads'
            
        if not base_path.exists():
            print(f"[!] Warning: Folder Payloads tidak ditemukan di {base_path}")
            return

        print(f"[*] Loading payloads dari: {base_path}")
        
        # Load XSS
        xss_dir = base_path / 'XSS'
        if xss_dir.exists():
            count = 0
            for f in xss_dir.rglob('*.txt'):
                count += self.payload_manager.load_payloads('xss', str(f))
            if count:
                print(f"[+] Integrated {count} advanced XSS payloads")

        # Load SQLi
        sqli_dir = base_path / 'SQLI'
        if sqli_dir.exists():
            count = 0
            for f in sqli_dir.rglob('*.txt'):
                count += self.payload_manager.load_payloads('sqli', str(f))
            
            # Also Time-Based
            time_sqli = base_path / 'Time-Based SQLi'
            if time_sqli.exists():
                for f in time_sqli.rglob('*.txt'):
                    count += self.payload_manager.load_payloads('sqli', str(f))
                    
            if count:
                print(f"[+] Integrated {count} advanced SQLi payloads")

        # Load LFI
        lfi_dir = base_path / 'LFI'
        if lfi_dir.exists():
            count = 0
            for f in lfi_dir.rglob('*.txt'):
                count += self.payload_manager.load_payloads('lfi', str(f))
            if count:
                print(f"[+] Integrated {count} advanced LFI payloads")
    
    def load_payloads(self, xss_file: Optional[str] = None, 
                     sqli_file: Optional[str] = None,
                     lfi_file: Optional[str] = None) -> Dict[str, int]:
        """
        Load custom payloads
        
        Args:
            xss_file: Path to XSS payloads file
            sqli_file: Path to SQLi payloads file
            lfi_file: Path to LFI payloads file
            
        Returns:
            Dictionary with payload counts
        """
        counts = {}
        
        if xss_file:
            counts['xss'] = self.payload_manager.load_payloads('xss', xss_file)
        
        if sqli_file:
            counts['sqli'] = self.payload_manager.load_payloads('sqli', sqli_file)
        
        if lfi_file:
            counts['lfi'] = self.payload_manager.load_payloads('lfi', lfi_file)
        
        return counts
    
    async def scan_target(self, target: str, ports: List[int] = None) -> Dict:
        """
        Perform comprehensive vulnerability scan
        
        Args:
            target: Target URL or IP
            ports: List of ports to scan (optional)
            
        Returns:
            Scan results dictionary
        """
        self.stats['start_time'] = time.time()
        
        logger.info("\n" + "="*60)
        logger.info(f"Starting scan: {target}")
        logger.info("="*60)
        
        results = {
            'target': target,
            'scan_config': {
                'stealth_level': self.stealth_engine.level,
                'tor_enabled': self.proxy_manager.use_tor if self.proxy_manager else False,
                'proxy_enabled': bool(self.proxy_manager and self.proxy_manager.proxies),
                'cve_matching': bool(self.cve_matcher)
            },
            'services': [],
            'cve_findings': [],
            'dast_findings': [],
            'statistics': {}
        }
        
        # Step 1: Service fingerprinting
        logger.info("\n[Step 1/4] Service Fingerprinting")
        services = await self._fingerprint_services(target, ports)
        results['services'] = services
        
        # Update tech stack from fingerprints
        for s in services:
            if s.get('product') != 'unknown':
                self.tech_stacks[target] = self.tech_stacks.get(target, {})
                self.tech_stacks[target][s.get('service', 'service')] = s.get('product')
        
        # Step 2: Web Discovery (Spidering & Parameter Mapping)
        logger.info("\n[Step 2/4] Web Discovery & Context Mapping")
        await self._discover_web_assets(target)
        results['web_assets'] = {
            'urls_found': len(self.discovered_urls),
            'forms_found': len(self.discovered_forms),
            'parameters_found': sum(len(p) for p in self.discovered_params.values()),
            'misconfigurations': len(self.misconfigurations)
        }
        results['misconfigurations'] = self.misconfigurations
        results['tech_stacks'] = self.tech_stacks
        
        # Step 3: CVE matching (if enabled)
        if self.cve_matcher and services:
            logger.info("\n[Step 3/4] CVE Correlation")
            cve_findings = self.cve_matcher.match_vulnerabilities(services)
            results['cve_findings'].extend(cve_findings)
            self.stats['vulnerabilities_found'] += len(cve_findings)
        
        # Step 4: Active vulnerability testing
        logger.info("\n[Step 4/4] Targeted Payload Injection")
        dast_findings = await self._test_vulnerabilities(target)
        results['dast_findings'].extend(dast_findings)
        self.stats['vulnerabilities_found'] += len(dast_findings)
        
        # Finalize statistics
        self.stats['end_time'] = time.time()
        self.stats['duration'] = self.stats['end_time'] - self.stats['start_time']
        
        # Add WAF detection info
        waf_info = self.stealth_engine.get_waf_info()
        results['waf_detected'] = waf_info
        
        # Add proxy stats (if available)
        if self.proxy_manager:
            results['proxy_stats'] = self.proxy_manager.get_proxy_stats_summary()
        
        results['statistics'] = self.stats.copy()
        
        # Save report automatically
        report_path = self._save_report(results)
        if report_path:
            results['report_path'] = str(report_path)
        
        logger.info("\n" + "="*60)
        logger.info("Scan Complete")
        logger.info("="*60)
        logger.info(f"Duration: {self.stats['duration']:.2f}s")
        logger.info(f"Requests: {self.stats['total_requests']} "
                   f"(Success: {self.stats['successful_requests']}, "
                   f"Failed: {self.stats['failed_requests']})")
        logger.info(f"Vulnerabilities: {self.stats['vulnerabilities_found']}")
        logger.info(f"WAF Detected: {waf_info['detected']}")
        
        if report_path:
             logger.info(f"Report saved to: {report_path}")

        return results
    
    def _save_report(self, results: Dict) -> Optional[Path]:
        """
        Save scan results to file
        
        Returns:
            Path to saved report or None if failed
        """
        try:
            # Ensure export directory exists
            EXPORT_DIR.mkdir(parents=True, exist_ok=True)
            
            # Generate filename based on target and timestamp
            target_clean = results['target'].replace('://', '_').replace('/', '_').replace(':', '_').replace('.', '_')
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_{target_clean}_{timestamp}.json"
            report_path = EXPORT_DIR / filename
            
            # Save as JSON
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4)
            
            # Also save a human-readable summary
            summary_filename = f"scan_{target_clean}_{timestamp}_summary.txt"
            summary_path = EXPORT_DIR / summary_filename
            with open(summary_path, 'w', encoding='utf-8') as f:
                f.write("="*60 + "\n")
                f.write(f"VULNERABILITY SCAN SUMMARY\n")
                f.write("="*60 + "\n")
                f.write(f"Target: {results['target']}\n")
                f.write(f"Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Duration: {results['statistics']['duration']:.2f}s\n")
                f.write(f"Vulnerabilities Found: {results['statistics']['vulnerabilities_found']}\n")
                f.write(f"WAF Detected: {results['waf_detected']['detected']}\n")
                f.write("-" * 60 + "\n\n")
                
                if results['services']:
                    f.write("DISCOVERED SERVICES:\n")
                    for s in results['services']:
                        f.write(f"  - Port {s.get('port')}: {s.get('product', 'unknown')} {s.get('version', '')}\n")
                    f.write("\n")
                
                if results['dast_findings']:
                    f.write("ACTIVE VULNERABILITIES (DAST):\n")
                    for finding in results['dast_findings']:
                        f.write(f"  [!] {finding['type']}\n")
                        f.write(f"      Location: {finding['location']}\n")
                        f.write(f"      Confidence: {finding['confidence']}\n")
                        f.write("-" * 20 + "\n")
                    f.write("\n")
                
                if results['cve_findings']:
                    f.write("POTENTIAL CVE CORRELATIONS:\n")
                    # Simplified CVE list for summary
                    for cve in results['cve_findings'][:10]: # Limit to top 10
                        f.write(f"  - {cve.get('id', 'Unknown')}: {cve.get('summary', '')[:100]}...\n")
                    if len(results['cve_findings']) > 10:
                        f.write(f"  ... and {len(results['cve_findings']) - 10} more\n")
                    f.write("\n")
                
                if results['misconfigurations']:
                    f.write("SECURITY MISCONFIGURATIONS:\n")
                    for misc in results['misconfigurations']:
                        f.write(f"  [!] {misc['type']} at {misc['location']}\n")
                        for detail in misc['details']:
                            f.write(f"      - {detail}\n")
                    f.write("\n")
                
                if results['tech_stacks']:
                    f.write("DETECTED TECH STACK (PER PAGE):\n")
                    for url, stack in list(results['tech_stacks'].items())[:10]:
                        f.write(f"  - {url}: {stack}\n")
            
            return report_path
            
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            return None

    async def _fingerprint_services(self, target: str, ports: List[int] = None) -> List[Dict]:
        """Fingerprint services on target"""
        services = []
        
        # Default ports if none specified
        if not ports:
            ports = DEFAULT_PORTS
        
        logger.info(f"Scanning {len(ports)} ports...")
        
        for port in ports:
            try:
                # Apply stealth delay
                self.stealth_engine.apply_delay()
                
                # Fingerprint service
                service_info = self.fingerprinter.fingerprint(target, port)
                
                if service_info and service_info.get('service') != 'unknown':
                    service_info['port'] = port # Ensure port is included
                    services.append(service_info)
                    logger.info(f"  [+] Port {port}: {service_info.get('product', 'unknown')} "
                              f"{service_info.get('version', '')}")
                
                self.stats['total_requests'] += 1
                self.stats['successful_requests'] += 1
                
            except Exception as e:
                logger.debug(f"  [-] Port {port}: {e}")
                self.stats['failed_requests'] += 1
        
        logger.info(f"Found {len(services)} services")
        return services
    
    async def _discover_web_assets(self, target: str):
        """Recursive discovery of URLs, forms, and parameters"""
        if not target.startswith(('http://', 'https://')):
             base_url = f"http://{target}"
        else:
             base_url = target
             
        logger.info(f"Spidering {base_url} (Max Depth: {self.max_depth})...")
        
        queue = [(base_url, 0)]
        seen = {base_url}
        pages_crawled = 0
        
        # Quick discovery of common paths
        for path in CORE_DISCOVERY_PATHS:
            url = urljoin(base_url, path)
            self.discovered_urls.add(url)

        import aiohttp
        async with aiohttp.ClientSession() as session:
            while queue and pages_crawled < self.max_pages:
                url, depth = queue.pop(0)
                if depth > self.max_depth:
                    continue
                
                logger.info(f"Crawling: {url} (Depth: {depth})")
                pages_crawled += 1
                
                try:
                    self.stealth_engine.apply_delay()
                    async with session.get(url, timeout=10, allow_redirects=True) as response:
                        # 1. Tech Stack Detection (Basic)
                        server = response.headers.get('Server', 'Unknown')
                        powered_by = response.headers.get('X-Powered-By', 'Unknown')
                        self.tech_stacks[url] = {'web_server': server, 'language': powered_by}
                        logger.info(f"  Tech Stack: {self.tech_stacks[url]}")
                        
                        # 2. Misconfiguration Checks
                        self._check_misconfigurations(url, response.headers)
                        
                        if response.status == 200:
                            html = await response.text()
                            soup = BeautifulSoup(html, 'html.parser')
                            
                            # Find Links
                            for a in soup.find_all('a', href=True):
                                link = urljoin(url, a['href'])
                                # Stay on same domain
                                if urlparse(link).netloc == urlparse(base_url).netloc:
                                    self.discovered_urls.add(link)
                                    
                                    # Add to queue if not seen
                                    clean_link = link.split('#')[0].rstrip('/')
                                    if clean_link not in seen:
                                        seen.add(clean_link)
                                        queue.append((link, depth + 1))
                                    
                                    # Map params
                                    query = urlparse(link).query
                                    if query:
                                        params = [p.split('=')[0] for p in query.split('&') if '=' in p]
                                        if params:
                                            self.discovered_params[link] = params
                            
                            # Find Forms
                            for form in soup.find_all('form'):
                                action = urljoin(url, form.get('action', ''))
                                method = form.get('method', 'get').lower()
                                inputs = []
                                for inp in form.find_all(['input', 'textarea']):
                                    name = inp.get('name')
                                    if name:
                                        inputs.append({'name': name, 'type': inp.get('type', 'text')})
                                
                                if inputs:
                                    self.discovered_forms.append({'action': action, 'method': method, 'inputs': inputs})
                
                except Exception as e:
                    logger.debug(f"Discovery failed for {url}: {e}")
            
        logger.info(f"  [+] Found {len(self.discovered_urls)} potential paths")
        logger.info(f"  [+] Found {len(self.discovered_forms)} HTML forms")
        logger.info(f"  [+] Identified {len(self.discovered_params)} unique parameter sets")
        logger.info(f"  [+] Detected {len(self.misconfigurations)} misconfigurations")

    def _check_misconfigurations(self, url: str, headers: Dict):
        """Check for common security misconfigurations in headers"""
        missing_headers = []
        
        security_headers = {
            'Strict-Transport-Security': 'HSTS not enabled',
            'Content-Security-Policy': 'CSP not defined',
            'X-Content-Type-Options': 'X-Content-Type-Options missing',
            'X-Frame-Options': 'X-Frame-Options missing (Risk of Clickjacking)',
            'X-XSS-Protection': 'X-XSS-Protection missing'
        }
        
        for header, msg in security_headers.items():
            if header not in headers:
                missing_headers.append(msg)
        
        if missing_headers:
            finding = {
                'type': 'Security Misconfiguration',
                'location': url,
                'details': missing_headers,
                'confidence': '90%'
            }
            self.misconfigurations.append(finding)
            for msg in missing_headers[:2]: # Log first two for brevity
                logger.warning(f"  [LOW] Security Misconfiguration at {url}: {msg}")
        
        # Server signature disclosure
        if 'Server' in headers and any(x in headers['Server'].lower() for x in ['apache', 'nginx', 'php']):
             self.misconfigurations.append({
                'type': 'Information Disclosure',
                'location': url,
                'details': [f"Server version disclosure: {headers['Server']}"],
                'confidence': '75%'
             })
             logger.warning(f"  [LOW] Information Disclosure at {url} (Server banner)")

    async def _test_vulnerabilities(self, target_original: str) -> List[Dict]:
        """Test for active vulnerabilities using discovered context"""
        findings = []
        import aiohttp
        
        # Get payloads
        xss_payloads = self.payload_manager.get_payloads('xss', encode=True, max_count=10)
        sqli_payloads = self.payload_manager.get_payloads('sqli', encode=True, max_count=10)
        
        if not xss_payloads and not sqli_payloads:
            logger.warning("No payloads loaded, skipping active testing")
            return findings
            
        targets_to_test = []
        
        # 1. Prepare URL parameter targets
        for url, params in self.discovered_params.items():
            for param in params:
                targets_to_test.append({'url': url, 'param': param, 'type': 'url_param'})
                
        # 2. Prepare Form targets
        for form in self.discovered_forms[:5]: # Limit forms for stealth
            targets_to_test.append({'form': form, 'type': 'form'})
            
        # 3. Fallback to homepage if nothing found
        if not targets_to_test:
            targets_to_test.append({'url': target_original, 'param': 'query', 'type': 'url_param'})

        logger.info(f"Hunter Engine: Testing {len(targets_to_test)} unique attack vectors...")
        
        async with aiohttp.ClientSession() as session:
            for target in targets_to_test:
                # Test XSS
                for payload in xss_payloads[:5]:
                    self.stealth_engine.apply_delay()
                    finding = await self._send_payload(session, target, payload, 'XSS')
                    if finding:
                        findings.append(finding)
                        logger.info(f"  [!] VULNERABILITY FOUND: {finding['type']} on {finding['location']}")
                
                # Test SQLi
                for payload in sqli_payloads[:5]:
                    self.stealth_engine.apply_delay()
                    finding = await self._send_payload(session, target, payload, 'SQLi')
                    if finding:
                        findings.append(finding)
                        logger.info(f"  [!] VULNERABILITY FOUND: {finding['type']} on {finding['location']}")

        return findings

    async def _send_payload(self, session, target, payload, vuln_type) -> Optional[Dict]:
        """Helper to send payload and detect vulnerability"""
        try:
            url = target.get('url', target.get('form', {}).get('action', ''))
            param = target.get('param', '')
            method = target.get('form', {}).get('method', 'get').lower()
            
            # Simple signature detection
            xss_signatures = ['<script>', 'alert(', 'onerror=', 'onload=']
            sqli_signatures = ['SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL query', 'SQLite3::']
            
            actual_url = url
            params = {}
            
            if target['type'] == 'url_param':
                actual_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
            else:
                # Form injection
                for inp in target['form']['inputs']:
                    params[inp['name']] = payload if inp['name'] == target['form']['inputs'][0]['name'] else 'test'
            
            start_time = time.time()
            if method == 'get':
                async with session.get(actual_url, params=params if target['type'] == 'form' else None, timeout=10) as resp:
                    body = await resp.text()
            else:
                async with session.post(actual_url, data=params, timeout=10) as resp:
                    body = await resp.text()
            
            self.stats['total_requests'] += 1
            self.stats['successful_requests'] += 1
            
            # Detection logic
            if vuln_type == 'XSS':
                if payload in body or any(sig in body for sig in xss_signatures):
                    return {
                        'type': 'Cross-Site Scripting (Reflected)',
                        'location': actual_url,
                        'payload': payload,
                        'confidence': 'High'
                    }
            elif vuln_type == 'SQLi':
                if any(sig in body.lower() for sig in sqli_signatures):
                    return {
                        'type': 'SQL Injection (Error-Based)',
                        'location': actual_url,
                        'payload': payload,
                        'confidence': 'High'
                    }
                # Simple time-based detection (if payload 
                if (time.time() - start_time) > 5 and 'sleep' in payload.lower():
                     return {
                        'type': 'SQL Injection (Time-Based)',
                        'location': actual_url,
                        'payload': payload,
                        'confidence': 'Medium'
                    }
                    
        except Exception:
            self.stats['failed_requests'] += 1
            
        return None
    
    def get_statistics(self) -> Dict:
        """Get scan statistics"""
        stats = self.stats.copy()
        
        # Add payload stats
        stats['payload_stats'] = self.payload_manager.get_stats()
        
        # Add proxy stats
        if self.proxy_manager:
            stats['proxy_stats'] = self.proxy_manager.get_proxy_stats_summary()
        
        # Add WAF info
        stats['waf_info'] = self.stealth_engine.get_waf_info()
        
        return stats
    
    def cleanup(self):
        """Cleanup resources"""
        logger.info("[Cleanup] Shutting down scanner...")
        
        # Remove dead proxies
        if self.proxy_manager:
            self.proxy_manager.remove_dead_proxies()
        
        logger.info("[Cleanup] Complete")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Unified Vulnerability & CVE Scanner')
    parser.add_argument('target', help='Target IP or domain', nargs='?')
    parser.add_argument('-p', '--ports', help='Comma-separated list of ports to scan', default='22,80,443,3306,8080')
    parser.add_argument('--stealth', default='ninja', help='Stealth level (ghost, ninja, balanced, fast,  )')
    parser.add_argument('--tor', action='store_true', help='Route traffic through Tor (requires Tor service on 127.0.0.1:9050)')
    parser.add_argument('--proxies', action='store_true', help='Enable proxy rotation from proxies.txt')
    parser.add_argument('--proxies-file', default='proxies.txt', help='Path to custom proxies file')
    parser.add_argument('--depth', type=int, default=DEFAULT_MAX_DEPTH, help=f'Maximum crawling depth (default: {DEFAULT_MAX_DEPTH})')
    parser.add_argument('--pages', type=int, default=DEFAULT_MAX_PAGES, help=f'Maximum pages to crawl (default: {DEFAULT_MAX_PAGES})')
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    async def main():
        target = args.target
        if not target:
            target = input("[?] Masukkan target (URL/IP): ").strip()
            if not target:
                print("[!] Target tidak boleh kosong.")
                return

    
        try:
            port_list = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print("[!] Format port salah. Gunakan contoh: 80,443,8080")
            return

    
        print(f"[*] Menyiapkan Unified Scanner... (API Key: {'Set [OK]' if NVD_API_KEY else 'Not Set [Slow Mode]'})")
        scanner = UnifiedScanner(
            stealth_level=args.stealth,
            use_tor=args.tor,
            use_proxies=args.proxies,
            proxies_file=args.proxies_file,
            nvd_api_key=NVD_API_KEY, 
            enable_cve_matching=True,
            max_depth=args.depth,
            max_pages=args.pages
        )
        
        
        print(f"[*] Memulai scan pada {target} (Port: {args.ports})...")
        results = await scanner.scan_target(target, ports=port_list)
        
        
        print("\n" + "="*60)
        print("RINGKASAN SCAN")
        print("="*60)
        print(f"Target: {results['target']}")
        if results['services']:
            for service in results['services']:
                 print(f"  - Port {service.get('port', '??')}: {service.get('product', 'unknown')} {service.get('version', '')}")
        else:
            print("  (Tidak ada service aktif yang ditemukan)")
        
        print(f"Vulnerabilities Found: {len(results['cve_findings']) + len(results['dast_findings'])}")
        print(f"Scan Duration: {results['statistics']['duration']:.2f}s")
        print("="*60)
        
        
        if results['dast_findings']:
            print("\n" + "!"*60)
            print("  ACTIVE EXPLOITATION FINDINGS (CONFIRMED")
            print("!"*60)
            for f in results['dast_findings']:
                print(f"  [!] {f['type'].upper()}")
                print(f"      Location: {f['location']}")
                print(f"      Payload:  {f['payload']}")
                print(f"      Confidence: {f['confidence']}")
                print("-" * 40)
        
        
        if results['misconfigurations']:
            print("\n" + "?"*60)
            print("  SECURITY MISCONFIGURATIONS & HEADERS")
            print("?"*60)
            for m in results['misconfigurations']:
                print(f"  [?] {m['type']} at {m['location']}")
                for detail in m['details']:
                    print(f"      - {detail}")
                print("-" * 20)

        
        if results['cve_findings'] and scanner.cve_matcher:
            print(scanner.cve_matcher.format_findings(results['cve_findings']))
        
        
        scanner.cleanup()
    
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Scan dihentikan oleh pengguna.")

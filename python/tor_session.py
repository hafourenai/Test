"""
Tor Session - Professional Networking Layer
Forces all HTTP traffic through Tor SOCKS5 proxy to prevent leaks

This is the ONLY HTTP client that should be used in the application.
All modules must import and use TorSession instead of direct requests calls.
"""

import requests
import logging
import time
import random
import socket
try:
    import socks
except ImportError:
    socks = None
from typing import Optional, Dict, Any
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class TorSession:
    """
    Professional Tor-enabled HTTP session with automatic retry and DNS leak prevention.
    
    Architecture:
        HTTP Client Layer → TorSession (SOCKS5h) → Tor Network → Internet
    
    Key Features:
        - SOCKS5h proxy binding (prevents DNS leaks)
        - Automatic retry on circuit failure
        - Timeout handling
        - User-Agent normalization
        - Session persistence
    """
    
    def __init__(
        self,
        tor_proxy: str = "socks5h://127.0.0.1:9050",
        timeout: int = 30,
        max_retries: int = 3,
        verify_ssl: bool = False
    ):
        """
        Initialize Tor session
        
        Args:
            tor_proxy: Tor SOCKS5 proxy URL (use socks5h:// to prevent DNS leaks)
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts on failure
            verify_ssl: Whether to verify SSL certificates
        """
        self.tor_proxy = tor_proxy
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        
        # Create session with Tor proxy
        self.session = requests.Session()
        
        # Configure proxies - CRITICAL: use socks5h:// not socks5://
        # socks5h = hostname resolution through SOCKS proxy (prevents DNS leaks)
        # socks5  = local DNS resolution (LEAKS DNS!)
        self.session.proxies = {
            'http': tor_proxy,
            'https': tor_proxy
        }
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers with randomized User-Agent
        self.session.headers.update({
            'User-Agent': self._get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        logger.info("[Tor] TorSession initialized with SOCKS5h proxy")
        logger.debug(f"   Proxy: {tor_proxy}")
        logger.debug(f"   Timeout: {timeout}s")
        logger.debug(f"   Max retries: {max_retries}")
    
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Perform GET request through Tor
        
        Args:
            url: Target URL
            **kwargs: Additional arguments passed to requests.get()
            
        Returns:
            Response object or None on failure
        """
        return self._request('GET', url, **kwargs)
    
    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Perform POST request through Tor
        
        Args:
            url: Target URL
            **kwargs: Additional arguments passed to requests.post()
            
        Returns:
            Response object or None on failure
        """
        return self._request('POST', url, **kwargs)
    
    def _request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Internal request handler with retry logic
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            **kwargs: Additional request arguments
            
        Returns:
            Response object or None on failure
        """
        # Set default timeout if not provided
        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout
        
        # Set SSL verification
        if 'verify' not in kwargs:
            kwargs['verify'] = self.verify_ssl
        
        # Randomize User-Agent per request for better anonymity
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        if 'User-Agent' not in kwargs['headers']:
            kwargs['headers']['User-Agent'] = self._get_random_user_agent()
        
        for attempt in range(self.max_retries):
            try:
                logger.debug(f"[Net] {method} {url} (attempt {attempt + 1}/{self.max_retries})")
                
                response = self.session.request(method, url, **kwargs)
                
                # Log successful request
                logger.debug(f"[Success] {method} {url} - Status: {response.status_code}")
                
                return response
                
            except requests.exceptions.ProxyError as e:
                logger.error(f"[Error] Tor proxy error: {e}")
                logger.error("   Is Tor running at 127.0.0.1:9050?")
                logger.error("   Check with: curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip")
                
                if attempt < self.max_retries - 1:
                    wait_time = (attempt + 1) * 2
                    logger.info(f"   Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    return None
            
            except requests.exceptions.Timeout as e:
                logger.warning(f"[Timeout] Request timeout: {url}")
                
                if attempt < self.max_retries - 1:
                    logger.info(f"   Retrying (attempt {attempt + 2}/{self.max_retries})...")
                    time.sleep(1)
                else:
                    logger.error(f"  Max retries exceeded for {url}")
                    return None
            
            except requests.exceptions.RequestException as e:
                logger.error(f"[Error] Request failed: {e}")
                
                if attempt < self.max_retries - 1:
                    time.sleep(2)
                else:
                    return None
            
            except Exception as e:
                logger.error(f"[Error] Unexpected error: {e}")
                return None
        
        return None
    
    def verify_tor_connection(self) -> bool:
        """
        Verify that we're actually using Tor network
        
        Returns:
            True if connected through Tor, False otherwise
        """
        try:
            logger.info("[Search] Verifying Tor connection...")
            
            # Check Tor Project API
            response = self.get('https://check.torproject.org/api/ip', timeout=10)
            
            if response and response.status_code == 200:
                data = response.json()
                is_tor = data.get('IsTor', False)
                ip = data.get('IP', 'unknown')
                
                if is_tor:
                    logger.info(f"[Success] Tor connection verified!")
                    logger.info(f"   Exit IP: {ip}")
                    return True
                else:
                    logger.error(f"[Error] NOT using Tor! Current IP: {ip}")
                    logger.error("   Traffic is leaking directly to ISP!")
                    return False
            else:
                logger.error("[Error] Could not verify Tor connection")
                return False
                
        except Exception as e:
            logger.error(f"[Error] Tor verification failed: {e}")
            return False
    
    def get_current_ip(self) -> Optional[str]:
        """
        Get current exit IP address
        
        Returns:
            IP address string or None on failure
        """
        try:
            response = self.get('https://api.ipify.org?format=json', timeout=10)
            
            if response and response.status_code == 200:
                ip = response.json().get('ip', 'unknown')
                logger.info(f"[IP] Current exit IP: {ip}")
                return ip
            
            return None
            
        except Exception as e:
            logger.error(f"  Could not get IP: {e}")
            return None
    
    def renew_identity(self) -> bool:
        """
        Request new Tor circuit (new identity)
        Requires Tor control port access
        
        Returns:
            True if successful, False otherwise
        """
        try:
            from stem import Signal
            from stem.control import Controller
            
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                logger.info("[Success] Tor identity renewed (new circuit)")
                time.sleep(5)  # Wait for new circuit
                return True
                
        except ImportError:
            logger.warning("  stem library not installed")
            logger.info("   Install with: pip install stem")
            return False
            
        except Exception as e:
            logger.warning(f"  Could not renew Tor identity: {e}")
            logger.info("   Make sure Tor control port is accessible")
            return False
    
    def get_proxy_socket(self, timeout: int = 10) -> Optional[socket.socket]:
        """
        Create a proxy-aware socket for raw TCP connections
        
        Args:
            timeout: Socket timeout
            
        Returns:
            Proxied socket or None if socks library is missing
        """
        if not socks:
            logger.error("[Error] 'socks' library (PySocks) is not installed")
            return None
            
        try:
            s = socks.socksocket()
            
            # Configure proxy
            # Parse tor_proxy string (e.g., socks5h://127.0.0.1:9050)
            proxy_addr = "127.0.0.1"
            proxy_port = 9050
            
            if "://" in self.tor_proxy:
                addr_part = self.tor_proxy.split("://")[-1]
                if ":" in addr_part:
                    proxy_addr, proxy_port = addr_part.split(":")
                    proxy_port = int(proxy_port)
            
            s.set_proxy(socks.SOCKS5, proxy_addr, proxy_port, rdns=True)
            s.settimeout(timeout)
            
            return s
        except Exception as e:
            logger.error(f"[Error] Failed to create proxy socket: {e}")
            return None
    
    def _get_random_user_agent(self) -> str:
        """
        Get random User-Agent to avoid fingerprinting
        
        Returns:
            Random User-Agent string
        """
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
        ]
        return random.choice(user_agents)
    
    def close(self):
        """Close the session"""
        self.session.close()
        logger.debug("[Closed] TorSession closed")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


# Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s - %(message)s'
    )
    
    print("="*60)
    print("Tor Session Test")
    print("="*60)
    
    # Create Tor session
    with TorSession() as tor:
        # Verify Tor connection
        if tor.verify_tor_connection():
            print("\n  Tor is working correctly!")
            
            # Get current IP
            ip = tor.get_current_ip()
            print(f"📡 Exit IP: {ip}")
            
            # Test HTTP request
            print("\n  Testing HTTP request...")
            response = tor.get('https://httpbin.org/headers')
            if response:
                print(f"  Request successful - Status: {response.status_code}")
        else:
            print("\n  Tor is NOT working!")
            print("   Make sure Tor is running:")
            print("   sudo systemctl start tor")

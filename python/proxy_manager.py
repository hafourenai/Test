# python/proxy_manager.py
"""
Proxy & Tor Integration Manager
Implements proxy rotation and Tor integration to avoid blocking
"""

import random
import time
import subprocess
import socket
import logging
import os
import requests  # Import at module level for type hints
from pathlib import Path
from typing import Optional, List, Dict

try:
    from .tor_session import TorSession
    from .config import TOR_SOCKS_PROXY, TOR_CONTROL_PORT
except ImportError:
    TorSession = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ProxyManager:
    """Manages proxy rotation and Tor integration"""
    
    def __init__(self, proxies_file: str = "proxies.txt", use_tor: bool = False, 
                 strategy: str = 'weighted'):
        self.proxies_file = Path(proxies_file)
        self.use_tor = use_tor
        self.proxies = []
        self.current_proxy_index = 0
        self.tor_process = None
        self.tor_port = 9050
        self.tor_control_port = int(os.getenv('TOR_CONTROL_PORT', 9051))
        self.rotation_strategy = strategy
        
        # Proxy performance tracking
        self.proxy_stats = {}  # {proxy_id: {total, successful, latencies, last_used}}
        self.request_count = 0
        
        # Initialize Tor session for verification
        self.tor_session = TorSession() if TorSession else None
        
        # Cache real IP for fail-safe checks
        self.real_ip = self.get_public_ip(use_proxy=False)
        
        # Load proxies from file
        if self.proxies_file.exists():
            self._load_proxies()
        else:
            logger.warning(f"Proxies file not found: {proxies_file}")
        
        # Initialize Tor if enabled
        if self.use_tor:
            self._initialize_tor()
        
        logger.info(f"[Proxy] Strategy: {strategy}, Proxies: {len(self.proxies)}, Tor: {use_tor}")
    
    def _load_proxies(self):
        """Load proxies from proxies.txt"""
        try:
            with open(self.proxies_file, 'r') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse proxy format: protocol://ip:port or ip:port
                proxy = self._parse_proxy(line)
                if proxy:
                    proxy_id = self._get_proxy_id(proxy)
                    proxy['id'] = proxy_id
                    self.proxies.append(proxy)
                    # Initialize stats
                    self.proxy_stats[proxy_id] = {
                        'total_requests': 0,
                        'successful_requests': 0,
                        'failed_requests': 0,
                        'latencies': [],
                        'last_used': 0,
                        'success_rate': 1.0,
                        'avg_latency': 5.0
                    }
            
            logger.info(f"  Loaded {len(self.proxies)} proxies from {self.proxies_file}")
            
            # Shuffle proxies for randomization
            random.shuffle(self.proxies)
            
        except Exception as e:
            logger.error(f"Error loading proxies: {e}")
    
    def _parse_proxy(self, proxy_str: str) -> Optional[Dict[str, str]]:
        """
        Parse proxy string into dict format
        Supports formats:
        - http://ip:port
        - socks5://ip:port
        - ip:port (assumes http)
        - user:pass@ip:port
        """
        try:
            proxy_str = proxy_str.strip()
            
            # Check if protocol is specified
            if '://' in proxy_str:
                protocol, rest = proxy_str.split('://', 1)
            else:
                protocol = 'http'
                rest = proxy_str
            
            # Check for authentication
            if '@' in rest:
                auth, address = rest.split('@', 1)
                username, password = auth.split(':', 1)
                proxy_url = f"{protocol}://{username}:{password}@{address}"
            else:
                proxy_url = f"{protocol}://{rest}"
            
            return {
                'http': proxy_url,
                'https': proxy_url,
                'url': proxy_url
            }
        except Exception as e:
            logger.warning(f"Failed to parse proxy '{proxy_str}': {e}")
            return None
    
    def _initialize_tor(self):
        """Initialize Tor service"""
        try:
            # Check if Tor is already running
            if self._check_tor_running():
                logger.info("  Tor is already running")
                return
            
            # Try to start Tor
            logger.info("Starting Tor service...")
            
            # Try systemctl first (Linux)
            try:
                subprocess.run(['sudo', 'systemctl', 'start', 'tor'], 
                             check=False, capture_output=True)
                time.sleep(3)
            except:
                pass
            
            # Check if Tor is now running
            if self._check_tor_running():
                logger.info("  Tor service started successfully")
            else:
                logger.warning("  Could not start Tor automatically")
                logger.info("Please start Tor manually: sudo systemctl start tor")
        
        except Exception as e:
            logger.error(f"Error initializing Tor: {e}")
    
    def _check_tor_running(self) -> bool:
        """Check if Tor is running on default port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('127.0.0.1', self.tor_port))
            sock.close()
            return result == 0
        except:
            return False
    
    def get_next_proxy(self) -> Optional[Dict[str, str]]:
        """Get next proxy from rotation"""
        if not self.proxies:
            return None
        
        proxy = self.proxies[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxies)
        
        return proxy
    
    def get_random_proxy(self) -> Optional[Dict[str, str]]:
        """Get random proxy from list"""
        if not self.proxies:
            return None
        
        return random.choice(self.proxies)
    
    def get_tor_proxy(self) -> Dict[str, str]:
        """Get Tor SOCKS5 proxy configuration"""
        return {
            'http': f'socks5h://127.0.0.1:{self.tor_port}',
            'https': f'socks5h://127.0.0.1:{self.tor_port}'
        }
    
    def renew_tor_identity(self):
        """Request new Tor identity (new circuit)"""
        if not self.use_tor:
            return
        
        try:
            # Connect to Tor control port
            from stem import Signal
            from stem.control import Controller
            
            with Controller.from_port(port=self.tor_control_port) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                logger.info("  Tor identity renewed (new circuit)")
                time.sleep(5)  # Wait for new circuit
        
        except ImportError:
            logger.warning("stem library not installed. Install: pip install stem")
        except Exception as e:
            logger.warning(f"Could not renew Tor identity: {e}")
    
    def get_current_proxy(self, strategy: str = None) -> Optional[Dict[str, str]]:
        """
        Get proxy based on strategy
        
        Args:
            strategy: 'rotate', 'random', 'weighted', 'tor', 'tor_fallback', 'tor_only'
        """
        strategy = strategy or self.rotation_strategy
        
        if strategy == 'tor' or strategy == 'tor_only':
            if self.use_tor:
                return self.get_tor_proxy()
            else:
                logger.warning("[Proxy] Tor requested but not enabled")
                return self.get_next_proxy()
        
        elif strategy == 'tor_fallback':
            if self.use_tor and self._check_tor_running():
                return self.get_tor_proxy()
            else:
                return self._weighted_selection() if self.proxies else None
        
        elif strategy == 'weighted':
            return self._weighted_selection()
        
        elif strategy == 'random':
            return self.get_random_proxy()
        
        else:  # rotate
            return self.get_next_proxy()
    
    def _get_proxy_id(self, proxy: Dict[str, str]) -> str:
        """Generate unique ID for proxy"""
        return proxy.get('url', proxy.get('http', 'unknown'))
    
    def _weighted_selection(self) -> Optional[Dict[str, str]]:
        """
        Select proxy based on performance metrics (success rate and latency)
        Better performing proxies have higher probability of selection
        """
        if not self.proxies:
            return None
        
        weights = []
        for proxy in self.proxies:
            proxy_id = proxy.get('id', self._get_proxy_id(proxy))
            stats = self.proxy_stats.get(proxy_id, {})
            
            success_rate = stats.get('success_rate', 1.0)
            avg_latency = stats.get('avg_latency', 5.0)
            
            # Calculate weight: higher success rate and lower latency = higher weight
            # Avoid division by zero
            weight = success_rate / (avg_latency + 0.1)
            weights.append(max(0.01, weight))  # Minimum weight to give all proxies a chance
        
        # Weighted random selection
        selected = random.choices(self.proxies, weights=weights, k=1)[0]
        return selected
    
    def update_proxy_stats(self, proxy: Dict[str, str], success: bool, latency: float = 0):
        """
        Update proxy performance statistics
        
        Args:
            proxy: Proxy dictionary
            success: Whether the request was successful
            latency: Request latency in seconds
        """
        proxy_id = proxy.get('id', self._get_proxy_id(proxy))
        
        if proxy_id not in self.proxy_stats:
            self.proxy_stats[proxy_id] = {
                'total_requests': 0,
                'successful_requests': 0,
                'failed_requests': 0,
                'latencies': [],
                'last_used': time.time(),
                'success_rate': 1.0,
                'avg_latency': 5.0
            }
        
        stats = self.proxy_stats[proxy_id]
        stats['total_requests'] += 1
        stats['last_used'] = time.time()
        
        if success:
            stats['successful_requests'] += 1
            if latency > 0:
                stats['latencies'].append(latency)
                # Keep only last 100 latencies
                if len(stats['latencies']) > 100:
                    stats['latencies'] = stats['latencies'][-100:]
        else:
            stats['failed_requests'] += 1
        
        # Update metrics
        stats['success_rate'] = stats['successful_requests'] / stats['total_requests']
        if stats['latencies']:
            stats['avg_latency'] = sum(stats['latencies']) / len(stats['latencies'])
    
    def remove_dead_proxies(self, min_success_rate: float = 0.3):
        """
        Remove proxies with low success rate
        
        Args:
            min_success_rate: Minimum success rate to keep proxy (default: 0.3)
        """
        initial_count = len(self.proxies)
        
        # Filter proxies
        self.proxies = [
            proxy for proxy in self.proxies
            if self.proxy_stats.get(
                proxy.get('id', self._get_proxy_id(proxy)), {}
            ).get('success_rate', 1.0) >= min_success_rate
        ]
        
        removed = initial_count - len(self.proxies)
        if removed > 0:
            logger.info(f"[Proxy] Removed {removed} dead proxies (success rate < {min_success_rate})")
            logger.info(f"[Proxy] Remaining proxies: {len(self.proxies)}")
    
    def get_proxy_stats_summary(self) -> Dict:
        """Get summary of proxy performance"""
        if not self.proxy_stats:
            return {}
        
        total_requests = sum(s['total_requests'] for s in self.proxy_stats.values())
        total_successful = sum(s['successful_requests'] for s in self.proxy_stats.values())
        
        return {
            'total_proxies': len(self.proxies),
            'total_requests': total_requests,
            'total_successful': total_successful,
            'overall_success_rate': total_successful / total_requests if total_requests > 0 else 0,
            'best_proxy': self._get_best_proxy(),
            'worst_proxy': self._get_worst_proxy()
        }
    
    def _get_best_proxy(self) -> Optional[str]:
        """Get best performing proxy ID"""
        if not self.proxy_stats:
            return None
        
        best = max(
            self.proxy_stats.items(),
            key=lambda x: x[1].get('success_rate', 0) if x[1].get('total_requests', 0) > 5 else 0
        )
        return best[0] if best[1].get('total_requests', 0) > 5 else None
    
    def _get_worst_proxy(self) -> Optional[str]:
        """Get worst performing proxy ID"""
        if not self.proxy_stats:
            return None
        
        worst = min(
            self.proxy_stats.items(),
            key=lambda x: x[1].get('success_rate', 1.0) if x[1].get('total_requests', 0) > 5 else 1.0
        )
        return worst[0] if worst[1].get('total_requests', 0) > 5 else None
    
    def test_proxy(self, proxy: Dict[str, str], timeout: int = 10) -> bool:
        """Test if proxy is working"""
        try:
            # If using TorSession, we use it for proxy testing as well
            if self.tor_session:
                response = self.tor_session.get(
                    'http://httpbin.org/ip',
                    proxies=proxy,
                    timeout=timeout
                )
            else:
                response = requests.get(
                    'http://httpbin.org/ip',
                    proxies=proxy,
                    timeout=timeout
                )
                
            if response and response.status_code == 200:
                ip_info = response.json()
                logger.info(f"[Success] Proxy working - IP: {ip_info.get('origin', 'unknown')}")
                return True
        except Exception as e:
            logger.warning(f"[Error] Proxy test failed: {e}")
        
        return False
    
    def validate_all_proxies(self):
        """Test all proxies and remove dead ones"""
        logger.info("Validating all proxies...")
        
        valid_proxies = []
        for i, proxy in enumerate(self.proxies):
            logger.info(f"Testing proxy {i+1}/{len(self.proxies)}...")
            if self.test_proxy(proxy, timeout=5):
                valid_proxies.append(proxy)
            time.sleep(0.5)  # Rate limiting
        
        removed = len(self.proxies) - len(valid_proxies)
        self.proxies = valid_proxies
        
        logger.info(f"[Success] Validation complete: {len(valid_proxies)} valid, {removed} removed")
    
    def get_public_ip(self, use_proxy: bool = True) -> str:
        """Get current public IP (useful for verification)"""
        try:
            proxy = self.get_current_proxy() if use_proxy else None
            
            if self.tor_session and use_proxy:
                response = self.tor_session.get(
                    'http://httpbin.org/ip',
                    proxies=proxy,
                    timeout=10
                )
            else:
                response = requests.get(
                    'http://httpbin.org/ip',
                    proxies=proxy,
                    timeout=10
                )
            
            if response:
                current_ip = response.json().get('origin', 'unknown')
                
                # Fail-safe check: detect IP leaks
                if use_proxy and (self.use_tor or self.proxies):
                    if current_ip == self.real_ip and self.real_ip != 'unknown':
                        logger.critical("🚨 PRIVACY LEAK DETECTED: Proxy/Tor is active but your real IP is visible!")
                        logger.critical(f"   Real IP: {self.real_ip} | Visible IP: {current_ip}")
                        raise SystemExit("Terminating scan to prevent identity exposure.")
                
                return current_ip
            return 'unknown'
        except Exception as e:
            logger.error(f"Error getting public IP: {e}")
            return 'unknown'


class StealthScanner:
    """  scanner with stealth capabilities"""
    
    def __init__(self, proxy_manager: ProxyManager):
        self.proxy_manager = proxy_manager
        self.request_count = 0
        self.last_request_time = 0
        self.min_request_interval = 1.0  # seconds
    
    def _apply_rate_limiting(self):
        """Apply adaptive rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            # Add random jitter
            sleep_time += random.uniform(0, 0.5)
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        """
        Make HTTP request with proxy rotation and rate limiting
        """
        self._apply_rate_limiting()
        
        # Get proxy
        proxy = self.proxy_manager.get_current_proxy(strategy='tor-fallback')
        
        # Add randomized User-Agent
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        
        if 'User-Agent' not in kwargs['headers']:
            kwargs['headers']['User-Agent'] = self._get_random_user_agent()
        
        # Make request with retry logic
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if self.proxy_manager.use_tor and self.proxy_manager.tor_session:
                    response = self.proxy_manager.tor_session.session.request(
                        method, url, proxies=proxy, **kwargs
                    )
                else:
                    response = requests.request(method, url, proxies=proxy, **kwargs)
                
                if response:
                    self.request_count += 1
                    
                    # Rotate proxy after every 10 requests
                    if self.request_count % 10 == 0:
                        logger.info("Rotating proxy after 10 requests...")
                        if self.proxy_manager.use_tor:
                            self.proxy_manager.renew_tor_identity()
                    
                    return response
                return None
            
            except Exception as e:
                logger.warning(f"Request failed (attempt {attempt+1}/{max_retries}): {e}")
                
                if attempt < max_retries - 1:
                    # Try next proxy
                    proxy = self.proxy_manager.get_next_proxy()
                    time.sleep(2)
                else:
                    logger.error(f"All retry attempts failed for {url}")
                    return None
    
    def _get_random_user_agent(self) -> str:
        """Get random User-Agent to avoid fingerprinting"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
        ]
        return random.choice(user_agents)

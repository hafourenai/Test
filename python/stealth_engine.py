"""
Stealth Engine - Advanced Anti-Detection System
Implements sophisticated techniques to avoid WAF/IDS detection
"""

import random
import time
import logging
from typing import Dict, Optional, List
from urllib.parse import urlparse
from datetime import datetime

try:
    from .config import (
        STEALTH_LEVELS, WAF_SIGNATURES, USER_AGENTS,
        ACCEPT_LANGUAGES, REFERRER_DOMAINS
    )
except ImportError:
    from config import (
        STEALTH_LEVELS, WAF_SIGNATURES, USER_AGENTS,
        ACCEPT_LANGUAGES, REFERRER_DOMAINS
    )

logger = logging.getLogger(__name__)


class StealthEngine:
    """Advanced stealth engine for undetectable scanning"""
    
    def __init__(self, stealth_level: str = 'ninja'):
        """
        Initialize stealth engine
        
        Args:
            stealth_level: One of 'ghost', 'ninja', 'balanced', 'fast', ' '
        """
        if stealth_level not in STEALTH_LEVELS:
            logger.warning(f"Unknown stealth level '{stealth_level}', using 'ninja'")
            stealth_level = 'ninja'
        
        self.level = stealth_level
        self.config = STEALTH_LEVELS[stealth_level]
        self.waf_detected = False
        self.waf_type = None
        self.request_history = []
        self.last_request_time = 0
        
        logger.info(f"[Stealth] Initialized with level: {stealth_level}")
        logger.info(f"[Stealth] {self.config['description']}")
        logger.info(f"[Stealth] Workers: {self.config['workers']}, "
                   f"Delay: {self.config['delay_min']}-{self.config['delay_max']}s")
    
    def prepare_request(self, url: str, method: str = 'GET') -> Dict:
        """
        Prepare stealth request with randomized fingerprint
        
        Args:
            url: Target URL
            method: HTTP method
            
        Returns:
            Dictionary with headers, cookies, delay, and timeout
        """
        headers = self._generate_headers(url)
        cookies = self._generate_cookies()
        delay = self._calculate_delay()
        
        return {
            'headers': headers,
            'cookies': cookies,
            'delay': delay,
            'timeout': self.config['request_timeout']
        }
    
    def _generate_headers(self, url: str) -> Dict:
        """Generate realistic browser headers with randomization"""
        parsed = urlparse(url)
        
        headers = {
            'User-Agent': self._random_user_agent(),
            'Accept': self._random_accept(),
            'Accept-Language': random.choice(ACCEPT_LANGUAGES),
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': random.choice(['1', '0']),
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': random.choice(['document', 'empty', 'script']),
            'Sec-Fetch-Mode': random.choice(['navigate', 'cors', 'no-cors']),
            'Sec-Fetch-Site': random.choice(['none', 'same-origin', 'cross-site']),
            'Cache-Control': random.choice(['no-cache', 'max-age=0', 'no-store']),
        }
        
        # Add referrer spoofing (70% chance)
        if random.random() > 0.3:
            headers['Referer'] = self._generate_referrer(parsed.netloc)
        
        # Add origin header for POST requests
        if random.random() > 0.5:
            headers['Origin'] = f"{parsed.scheme}://{parsed.netloc}"
        
        # Randomly add some optional headers
        if random.random() > 0.5:
            headers['Sec-CH-UA'] = self._generate_sec_ch_ua()
        
        if random.random() > 0.5:
            headers['Sec-CH-UA-Platform'] = random.choice(['"Windows"', '"macOS"', '"Linux"'])
        
        return headers
    
    def _random_user_agent(self) -> str:
        """Get random User-Agent from pool"""
        return random.choice(USER_AGENTS)
    
    def _random_accept(self) -> str:
        """Generate random Accept header"""
        accepts = [
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        ]
        return random.choice(accepts)
    
    def _generate_referrer(self, target_domain: str) -> str:
        """Generate realistic referrer"""
        strategies = [
            # Search engine referrer
            lambda: f"{random.choice(REFERRER_DOMAINS)}/search?q={target_domain}",
            # Direct domain referrer
            lambda: f"https://{target_domain}",
            # Random popular site
            lambda: random.choice(REFERRER_DOMAINS),
        ]
        
        return random.choice(strategies)()
    
    def _generate_sec_ch_ua(self) -> str:
        """Generate Sec-CH-UA header"""
        versions = [
            '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            '"Not_A Brand";v="8", "Chromium";v="121", "Google Chrome";v="121"',
            '"Not_A Brand";v="99", "Chromium";v="120", "Google Chrome";v="120"',
        ]
        return random.choice(versions)
    
    def _generate_cookies(self) -> Dict:
        """Generate realistic cookies"""
        cookies = {}
        
        # Add some random session-like cookies (30% chance)
        if random.random() > 0.7:
            cookies['session_id'] = self._random_string(32)
        
        # Add tracking cookies (20% chance)
        if random.random() > 0.8:
            cookies['_ga'] = f"GA1.2.{random.randint(100000000, 999999999)}.{int(time.time())}"
        
        return cookies
    
    def _random_string(self, length: int) -> str:
        """Generate random alphanumeric string"""
        import string
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def _calculate_delay(self) -> float:
        """Calculate adaptive delay with jitter"""
        base_delay = random.uniform(
            self.config['delay_min'],
            self.config['delay_max']
        )
        
        # Add jitter (±20%)
        jitter = random.uniform(-0.2, 0.2) * base_delay
        
        # Increase delay if WAF detected
        if self.waf_detected:
            base_delay *= 2
            logger.debug(f"[Stealth] WAF detected, doubling delay to {base_delay:.2f}s")
        
        return max(0.1, base_delay + jitter)
    
    def apply_delay(self):
        """Apply rate limiting delay"""
        delay = self._calculate_delay()
        
        # Ensure minimum time between requests
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < delay:
            sleep_time = delay - time_since_last
            logger.debug(f"[Stealth] Sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def detect_waf(self, response) -> bool:
        """
        Detect if WAF is present in response
        
        Args:
            response: requests.Response object
            
        Returns:
            True if WAF detected, False otherwise
        """
        # Check status code
        if response.status_code in WAF_SIGNATURES['status_codes']:
            self.waf_detected = True
            logger.warning(f"[WAF] Detected via status code: {response.status_code}")
            return True
        
        # Check headers
        for header, value in response.headers.items():
            header_lower = header.lower()
            value_lower = str(value).lower()
            
            for signature in WAF_SIGNATURES['headers']:
                if signature in header_lower or signature in value_lower:
                    self.waf_detected = True
                    self.waf_type = signature
                    logger.warning(f"[WAF] Detected via header: {header}: {value}")
                    return True
        
        # Check response content
        try:
            content = response.text.lower()
            for signature in WAF_SIGNATURES['content']:
                if signature in content:
                    self.waf_detected = True
                    self.waf_type = signature
                    logger.warning(f"[WAF] Detected via content: {signature}")
                    return True
        except:
            pass
        
        return False
    
    def get_waf_info(self) -> Dict:
        """Get WAF detection information"""
        return {
            'detected': self.waf_detected,
            'type': self.waf_type,
            'timestamp': datetime.now().isoformat() if self.waf_detected else None
        }
    
    def adjust_for_waf(self):
        """Adjust stealth settings when WAF is detected"""
        if not self.waf_detected:
            return
        
        logger.info("[Stealth] Adjusting settings for WAF detection...")
        
        # Increase delays
        self.config['delay_min'] *= 1.5
        self.config['delay_max'] *= 1.5
        
        # Reduce workers
        self.config['workers'] = max(5, self.config['workers'] // 2)
        
        # Increase proxy rotation
        self.config['rotate_proxy_every'] = max(1, self.config['rotate_proxy_every'] // 2)
        
        logger.info(f"[Stealth] New settings - Workers: {self.config['workers']}, "
                   f"Delay: {self.config['delay_min']:.1f}-{self.config['delay_max']:.1f}s")
    
    def get_config(self) -> Dict:
        """Get current stealth configuration"""
        return self.config.copy()
    
    def reset_waf_detection(self):
        """Reset WAF detection state"""
        self.waf_detected = False
        self.waf_type = None
        logger.info("[Stealth] WAF detection state reset")


# Example usage
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s - %(message)s'
    )
    
    print("="*60)
    print("Stealth Engine Test")
    print("="*60)
    
    # Test each stealth level
    for level in ['ghost', 'ninja', 'balanced', 'fast', ' ']:
        print(f"\n[{level.upper()}]")
        engine = StealthEngine(stealth_level=level)
        
        # Prepare request
        request_params = engine.prepare_request('https://example.com')
        
        print(f"  User-Agent: {request_params['headers']['User-Agent'][:50]}...")
        print(f"  Delay: {request_params['delay']:.2f}s")
        print(f"  Timeout: {request_params['timeout']}s")
        print(f"  Headers count: {len(request_params['headers'])}")

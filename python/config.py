"""
Centralized Configuration Management
Handles environment variables, NVD API settings, and Tor configuration
"""

import os
from pathlib import Path
from typing import Optional

# Load environment variables from .env file
def load_env(env_path: Optional[Path] = None):
    """
    Simple .env loader to avoid extra dependencies
    
    Args:
        env_path: Path to .env file (defaults to project root)
    """
    if env_path is None:
        # Look for .env in project root
        env_path = Path(__file__).parent.parent / '.env'
    
    if env_path.exists():
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()


# Load environment on import
load_env()

NVD_API_KEY = os.getenv('NVD_API_KEY', None)
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate Limiting
NVD_RATE_LIMIT_WITH_KEY = 50      # requests per 30 seconds with API key
NVD_RATE_LIMIT_WITHOUT_KEY = 5    # requests per 30 seconds without API key

# Request Configuration
NVD_REQUEST_TIMEOUT = 30          # seconds
NVD_MAX_RESULTS_PER_PAGE = 2000  


TOR_SOCKS_PROXY = os.getenv('TOR_SOCKS_PROXY', 'socks5h://127.0.0.1:9050')
TOR_CONTROL_PORT = int(os.getenv('TOR_CONTROL_PORT', '9051'))
TOR_REQUEST_TIMEOUT = int(os.getenv('TOR_REQUEST_TIMEOUT', '30'))
TOR_MAX_RETRIES = int(os.getenv('TOR_MAX_RETRIES', '3'))




ENABLE_CACHE = True
CACHE_DIR = Path.home() / '.vulnerability_scanner' / 'cache'
CACHE_EXPIRY_HOURS = 24




LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')  # DEBUG, INFO, WARNING, ERROR, CRITICAL




SERVICE_VENDOR_MAP = {
    'nginx': ['nginx', 'f5'],
    'openssh': ['openbsd', 'openssh'],
    'apache': ['apache'],
    'httpd': ['apache'],
    'mysql': ['mysql', 'oracle'],
    'mariadb': ['mariadb'],
    'postgresql': ['postgresql'],
    'mongodb': ['mongodb'],
    'redis': ['redis'],
    'vsftpd': ['vsftpd_project'],
    'proftpd': ['proftpd'],
    'dovecot': ['dovecot'],
    'postfix': ['postfix'],
    'bind': ['isc'],
    'named': ['isc'],
    'tomcat': ['apache'],
    'jetty': ['eclipse'],
    'iis': ['microsoft'],
    'php': ['php'],
    'python': ['python'],
    'node': ['nodejs'],
    'nodejs': ['nodejs'],
}



CVSS_V3_CRITICAL = 9.0
CVSS_V3_HIGH = 7.0
CVSS_V3_MEDIUM = 4.0

CVSS_V2_HIGH = 7.0
CVSS_V2_MEDIUM = 4.0



DEFAULT_EXPORT_FORMAT = 'json'  # json, csv, html
EXPORT_DIR = Path('./reports')



USER_AGENT = 'VulnerabilityScanner/2.0 (Educational Purpose; +https://github.com/hafourenai)'


# ============================================================================
# DISCOVERY & CRAWLING CONFIGURATION
# ============================================================================
DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_PAGES = 50
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 
    1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9000
]
# Common paths for brute-force discovery
CORE_DISCOVERY_PATHS = [
    '/robots.txt', '/sitemap.xml', '/.git/', '/.env', '/config.php', 
    '/admin/', '/login.php', '/wp-admin/', '/phpinfo.php', '/backup/',
    '/images/', '/css/', '/js/', '/api/', '/v1/', '/xmlrpc.php'
]


# ============================================================================
# STEALTH MODE CONFIGURATION
# ============================================================================

# Stealth Mode Levels - From Ghost (most stealth) to   (fastest)
STEALTH_LEVELS = {
    'ghost': {
        'workers': 5,
        'delay_min': 5.0,
        'delay_max': 15.0,
        'batch_size': 1,
        'rate_limit': 1,  # requests per second
        'rotate_proxy_every': 3,  # requests
        'rotate_identity_every': 10,  # requests (Tor circuit)
        'request_timeout': 30,
        'description': 'Maximum stealth - slowest but undetectable'
    },
    'ninja': {
        'workers': 10,
        'delay_min': 3.0,
        'delay_max': 8.0,
        'batch_size': 2,
        'rate_limit': 2,
        'rotate_proxy_every': 5,
        'rotate_identity_every': 15,
        'request_timeout': 25,
        'description': 'High stealth - balanced stealth and speed (DEFAULT)'
    },
    'balanced': {
        'workers': 20,
        'delay_min': 1.0,
        'delay_max': 4.0,
        'batch_size': 5,
        'rate_limit': 5,
        'rotate_proxy_every': 10,
        'rotate_identity_every': 20,
        'request_timeout': 20,
        'description': 'Balanced - good stealth with reasonable speed'
    },
    'fast': {
        'workers': 50,
        'delay_min': 0.5,
        'delay_max': 2.0,
        'batch_size': 10,
        'rate_limit': 10,
        'rotate_proxy_every': 20,
        'rotate_identity_every': 30,
        'request_timeout': 15,
        'description': 'Fast mode - minimal stealth, higher speed'
    },
    ' ': {
        'workers': 200,
        'delay_min': 0.1,
        'delay_max': 0.5,
        'batch_size': 50,
        'rate_limit': 50,
        'rotate_proxy_every': 50,
        'rotate_identity_every': 100,
        'request_timeout': 10,
        'description': '  fast - no stealth, maximum speed'
    }
}

# Default stealth level
DEFAULT_STEALTH_LEVEL = 'ninja'


# ============================================================================
# WAF/IDS DETECTION SIGNATURES
# ============================================================================

# Known WAF signatures to detect in responses
WAF_SIGNATURES = {
    'headers': [
        'cf-ray',           # Cloudflare
        'x-sucuri-id',      # Sucuri
        'x-akamai',         # Akamai
        'x-cdn',            # Generic CDN
        'server: cloudflare',
        'server: incapsula',
        'x-iinfo',          # Incapsula
        'x-protected-by',   # Generic protection
        'x-fw-',            # Firewall headers
    ],
    'content': [
        'cloudflare',
        'incapsula',
        'imperva',
        'barracuda',
        'fortiweb',
        'modsecurity',
        'wordfence',
        'sucuri',
        'akamai',
        'access denied',
        'blocked by',
        'security check',
        'captcha',
    ],
    'status_codes': [403, 406, 429, 503]  # Common WAF response codes
}


# ============================================================================
# PAYLOAD ENCODING CONFIGURATION
# ============================================================================

# Payload encoding options for WAF bypass
PAYLOAD_ENCODING = {
    'url_encode': True,         # Standard URL encoding
    'double_encode': True,      # Double URL encoding
    'unicode_encode': True,     # Unicode escape sequences
    'base64_encode': False,     # Base64 encoding (limited use)
    'hex_encode': True,         # Hex encoding (SQL contexts)
    'mixed_case': True,         # Case variation
    'comment_injection': True,  # SQL comment injection
    'null_byte': False,         # Null byte injection (risky)
}

# Payload mutation strategies
PAYLOAD_MUTATIONS = {
    'case_variation': True,     # Upper/lower/mixed case
    'space_variation': True,    # Different space representations
    'encoding_variation': True, # Multiple encoding types
    'comment_variation': True,  # Different comment styles
}


# ============================================================================
# PROXY ROTATION CONFIGURATION
# ============================================================================

# Proxy rotation strategies
PROXY_STRATEGIES = {
    'round_robin': 'Rotate proxies in sequential order',
    'random': 'Select random proxy for each request',
    'weighted': 'Select based on performance metrics (success rate, latency)',
    'tor_fallback': 'Try Tor first, fallback to proxies on failure',
    'tor_only': 'Use only Tor network',
    'proxy_only': 'Use only proxy pool'
}

# Default proxy strategy
DEFAULT_PROXY_STRATEGY = 'weighted'

# Proxy health check settings
PROXY_HEALTH_CHECK = {
    'enabled': True,
    'interval': 300,            # Check every 5 minutes
    'timeout': 10,              # Health check timeout
    'test_url': 'https://httpbin.org/ip',
    'min_success_rate': 0.5,    # Minimum 50% success rate
    'max_latency': 10.0,        # Maximum 10s average latency
}


# ============================================================================
# ADVANCED REQUEST FINGERPRINTING
# ============================================================================

# User-Agent pool for rotation
USER_AGENTS = [
    # Chrome on Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    
    # Firefox on Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
    
    # Chrome on macOS
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    
    # Safari on macOS
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',
    
    # Chrome on Linux
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
]

# Accept-Language pool
ACCEPT_LANGUAGES = [
    'en-US,en;q=0.9',
    'en-GB,en;q=0.9',
    'en-US,en;q=0.9,es;q=0.8',
    'en-US,en;q=0.9,fr;q=0.8',
]

# Referrer spoofing domains
REFERRER_DOMAINS = [
    'https://www.google.com',
    'https://www.bing.com',
    'https://duckduckgo.com',
    'https://www.yahoo.com',
    'https://github.com',
]


def setup_config():
    """
    Initialize configuration and create necessary directories
    """
   
    if ENABLE_CACHE:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
    
 
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Check for API key
    if not NVD_API_KEY:
        print("[!] WARNING: NVD_API_KEY not set in environment")
        print("   Running without API key limits you to 5 requests per 30 seconds")
        print("   Get a free API key: https://nvd.nist.gov/developers/request-an-api-key")
        print("   Set it in .env file: NVD_API_KEY=your-key-here")
        print()
    
    return True



def validate_config() -> bool:
    """
    Validate configuration settings
    
    Returns:
        True if configuration is valid, False otherwise
    """
    issues = []
    
    # Check Tor configuration
    if not TOR_SOCKS_PROXY.startswith('socks5h://'):
        issues.append("[!] TOR_SOCKS_PROXY should use 'socks5h://' to prevent DNS leaks")
    
    # Check directories
    if not EXPORT_DIR.exists():
        issues.append(f"[!] Export directory does not exist: {EXPORT_DIR}")
    
    if issues:
        print("Configuration Issues:")
        for issue in issues:
            print(f"  {issue}")
        return False
    
    return True


if __name__ == "__main__":
    print("="*60)
    print("Configuration Status")
    print("="*60)
    
    setup_config()
    
    print(f"\n[Dir] Directories:")
    print(f"   Cache dir: {CACHE_DIR}")
    print(f"   Export dir: {EXPORT_DIR}")
    
    print(f"\n[Key] API Keys:")
    print(f"   NVD API Key: {'Set [OK]' if NVD_API_KEY else 'Not set [Fail]'}")
    
    print(f"\n[Tor] Tor Configuration:")
    print(f"   SOCKS Proxy: {TOR_SOCKS_PROXY}")
    print(f"   Control Port: {TOR_CONTROL_PORT}")
    print(f"   Timeout: {TOR_REQUEST_TIMEOUT}s")
    print(f"   Max Retries: {TOR_MAX_RETRIES}")
    
    print(f"\n[Rate] Rate Limits:")
    print(f"   With API key: {NVD_RATE_LIMIT_WITH_KEY} req/30s")
    print(f"   Without key: {NVD_RATE_LIMIT_WITHOUT_KEY} req/30s")
    
    print(f"\n[Success] Configuration validation: {'PASSED' if validate_config() else 'FAILED'}")

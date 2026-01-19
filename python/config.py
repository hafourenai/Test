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


# ============================================================================
# NVD API Configuration
# ============================================================================

NVD_API_KEY = os.getenv('NVD_API_KEY', None)
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate Limiting
NVD_RATE_LIMIT_WITH_KEY = 50      # requests per 30 seconds with API key
NVD_RATE_LIMIT_WITHOUT_KEY = 5    # requests per 30 seconds without API key

# Request Configuration
NVD_REQUEST_TIMEOUT = 30          # seconds
NVD_MAX_RESULTS_PER_PAGE = 2000   # NVD API maximum


# ============================================================================
# Tor Configuration
# ============================================================================

TOR_SOCKS_PROXY = os.getenv('TOR_SOCKS_PROXY', 'socks5h://127.0.0.1:9050')
TOR_CONTROL_PORT = int(os.getenv('TOR_CONTROL_PORT', '9051'))
TOR_REQUEST_TIMEOUT = int(os.getenv('TOR_REQUEST_TIMEOUT', '30'))
TOR_MAX_RETRIES = int(os.getenv('TOR_MAX_RETRIES', '3'))


# ============================================================================
# Cache Configuration
# ============================================================================

ENABLE_CACHE = True
CACHE_DIR = Path.home() / '.vulnerability_scanner' / 'cache'
CACHE_EXPIRY_HOURS = 24


# ============================================================================
# Logging Configuration
# ============================================================================

LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')  # DEBUG, INFO, WARNING, ERROR, CRITICAL


# ============================================================================
# Service to Vendor Mapping (for CPE generation)
# ============================================================================

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


# ============================================================================
# CVSS Severity Thresholds
# ============================================================================

CVSS_V3_CRITICAL = 9.0
CVSS_V3_HIGH = 7.0
CVSS_V3_MEDIUM = 4.0

CVSS_V2_HIGH = 7.0
CVSS_V2_MEDIUM = 4.0


# ============================================================================
# Export Configuration
# ============================================================================

DEFAULT_EXPORT_FORMAT = 'json'  # json, csv, html
EXPORT_DIR = Path('./reports')


# ============================================================================
# User Agent
# ============================================================================

USER_AGENT = 'VulnerabilityScanner/2.0 (Educational Purpose; +https://github.com/yourusername/scanner)'


# ============================================================================
# Setup Function
# ============================================================================

def setup_config():
    """
    Initialize configuration and create necessary directories
    """
    # Create cache directory
    if ENABLE_CACHE:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
    
    # Create export directory
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Check for API key
    if not NVD_API_KEY:
        print("[!] WARNING: NVD_API_KEY not set in environment")
        print("   Running without API key limits you to 5 requests per 30 seconds")
        print("   Get a free API key: https://nvd.nist.gov/developers/request-an-api-key")
        print("   Set it in .env file: NVD_API_KEY=your-key-here")
        print()
    
    return True


# ============================================================================
# Configuration Validation
# ============================================================================

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

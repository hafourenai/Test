"""
Active Service Fingerprinting Engine
Actively interrogates open ports to extract real software identity.

This module implements protocol-level fingerprinting to convert:
    Port 22 → "OpenSSH 8.9p1"
    Port 80 → "Apache httpd 2.4.58"

Instead of:
    Port 22 → unknown
"""

import socket
import ssl
import re
import logging
import time
from typing import Dict, Any, Optional

try:
    from tor_session import TorSession
    TOR_AVAILABLE = True
except ImportError:
    TOR_AVAILABLE = False
    import requests

logger = logging.getLogger(__name__)


class ServiceFingerprinter:
    """Active service fingerprinting engine for real software identification"""
    
    TIMEOUT = 5
    
    def __init__(self, use_tor: bool = False):
        """
        Initialize fingerprinter
        
        Args:
            use_tor: Whether to route all fingerprinting through Tor (default: False)
        """
        self.use_tor = use_tor
        self.tor_session = TorSession() if use_tor and TOR_AVAILABLE else None
        
        if use_tor:
            if TOR_AVAILABLE:
                logger.info("[Tor] ServiceFingerprinter using Tor for all active discovery")
            else:
                logger.warning("[!] Tor requested for fingerprinting but modules not loaded")
    
    # Protocol-specific patterns for banner parsing
    BANNER_PATTERNS = {
        "apache": r"apache/?([\\d\\.]+)?",
        "nginx": r"nginx/?([\\d\\.]+)?",
        "openssh": r"openssh[_\\- ]([\\d\\.p]+)",
        "vsftpd": r"vsftpd ?([\\d\\.]+)",
        "proftpd": r"proftpd[_\\- ]?([\\d\\.]+)?",
        "mysql": r"mysql[_\\- ]?([\\d\\.]+)?",
        "mariadb": r"mariadb[_\\- ]?([\\d\\.]+)?",
        "postgresql": r"postgresql[_\\- ]?([\\d\\.]+)?",
        "redis": r"redis[_\\- ]?([\\d\\.]+)?",
        "iis": r"microsoft-iis/?([\\d\\.]+)?",
        "lighttpd": r"lighttpd/?([\\d\\.]+)?",
        "tomcat": r"tomcat/?([\\d\\.]+)?",
    }
    
    def fingerprint(self, host: str, port: int) -> Dict[str, Any]:
        """
        Main fingerprinting dispatcher based on port number.
        
        Args:
            host: Target hostname or IP
            port: Target port number
            
        Returns:
            Dictionary with service, product, and version information
        """
        logger.debug(f"Fingerprinting {host}:{port}")
        
        # HTTP/HTTPS services
        if port in (80, 8080, 8000, 8008, 8888):
            return self._fingerprint_http(host, port, False)
        if port in (443, 8443):
            return self._fingerprint_http(host, port, True)
        
        # SSH
        if port == 22:
            return self._fingerprint_ssh(host, port)
        
        # FTP
        if port in (21, 2121):
            return self._fingerprint_ftp(host, port)
        
        # SMTP
        if port in (25, 587):
            return self._fingerprint_smtp(host, port)
        
        # MySQL/MariaDB
        if port == 3306:
            return self._fingerprint_mysql(host, port)
        
        # PostgreSQL
        if port == 5432:
            return self._fingerprint_postgresql(host, port)
        
        # Redis
        if port == 6379:
            return self._fingerprint_redis(host, port)
        
        # Generic TCP banner grab
        return self._fingerprint_generic(host, port)
    
    def _fingerprint_http(self, host: str, port: int) -> Dict[str, Any]:
        """
        Fingerprint HTTP/HTTPS services by analyzing headers.
        
        Args:
            host: Target hostname
            port: Target port
            
        Returns:
            Service fingerprint dictionary
        """
        if not TOR_AVAILABLE: # requests is imported in the except block for TorSession
            import requests
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{host}:{port}"
        
        try:
            if self.use_tor and self.tor_session:
                r = self.tor_session.get(
                    url, 
                    timeout=self.TIMEOUT, 
                    verify=False,
                    allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
            else:
                r = requests.get(
                    url, 
                    timeout=self.TIMEOUT, 
                    verify=False,
                    allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
            
            # Extract server header
            server = r.headers.get("Server", "")
            x_powered_by = r.headers.get("X-Powered-By", "")
            
            # Combine headers for better detection
            combined_banner = f"{server} {x_powered_by}".strip()
            
            if combined_banner:
                logger.info(f"HTTP banner from {host}:{port} - {combined_banner}")
                return self._parse_banner(combined_banner, "http")
            else:
                logger.debug(f"No server header from {host}:{port}")
                return {"service": "http", "product": "unknown", "version": "unknown"}
                
        except requests.exceptions.SSLError:
            logger.debug(f"SSL error on {host}:{port}, service likely HTTPS")
            return {"service": "https", "product": "unknown", "version": "unknown"}
        except requests.exceptions.Timeout:
            logger.debug(f"Timeout connecting to {host}:{port}")
            return {"service": "http", "product": "unknown", "version": "unknown"}
        except Exception as e:
            logger.debug(f"HTTP fingerprint failed for {host}:{port}: {e}")
            return {"service": "http", "product": "unknown", "version": "unknown"}
    
    def _fingerprint_ssh(self, host: str, port: int) -> Dict[str, Any]:
        """
        Fingerprint SSH service by reading the banner.
        
        SSH servers send their version string immediately upon connection.
        """
        try:
            banner = self._grab_banner(host, port)
            
            if banner:
                logger.info(f"SSH banner from {host}:{port} - {banner}")
                return self._parse_banner(banner, "ssh")
            
            return {"service": "ssh", "product": "unknown", "version": "unknown"}
            
        except Exception as e:
            logger.debug(f"SSH fingerprint failed for {host}:{port}: {e}")
            return {"service": "ssh", "product": "unknown", "version": "unknown"}
    
    def _fingerprint_ftp(self, host: str, port: int) -> Dict[str, Any]:
        """
        Fingerprint FTP service by reading the welcome banner.
        """
        try:
            banner = self._grab_banner(host, port)
            
            if banner:
                logger.info(f"FTP banner from {host}:{port} - {banner}")
                return self._parse_banner(banner, "ftp")
            
            return {"service": "ftp", "product": "unknown", "version": "unknown"}
            
        except Exception as e:
            logger.debug(f"FTP fingerprint failed for {host}:{port}: {e}")
            return {"service": "ftp", "product": "unknown", "version": "unknown"}
    
    def _fingerprint_smtp(self, host: str, port: int) -> Dict[str, Any]:
        """
        Fingerprint SMTP service by reading the banner.
        """
        try:
            banner = self._grab_banner(host, port)
            
            if banner:
                logger.info(f"SMTP banner from {host}:{port} - {banner}")
                return self._parse_banner(banner, "smtp")
            
            return {"service": "smtp", "product": "unknown", "version": "unknown"}
            
        except Exception as e:
            logger.debug(f"SMTP fingerprint failed for {host}:{port}: {e}")
            return {"service": "smtp", "product": "unknown", "version": "unknown"}
    
    def _fingerprint_mysql(self, host: str, port: int) -> Dict[str, Any]:
        """
        Fingerprint MySQL/MariaDB by attempting connection.
        """
        try:
            # MySQL sends server greeting immediately
            banner = self._grab_banner(host, port)
            
            if banner:
                logger.info(f"MySQL banner from {host}:{port} - {banner}")
                return self._parse_banner(banner, "mysql")
            
            return {"service": "mysql", "product": "unknown", "version": "unknown"}
            
        except Exception as e:
            logger.debug(f"MySQL fingerprint failed for {host}:{port}: {e}")
            return {"service": "mysql", "product": "unknown", "version": "unknown"}
    
    def _grab_banner(self, host: str, port: int, send_data: bytes = None) -> str:
        """Helper to grab raw banner from a socket"""
        s = None
        try:
            # Use Tor proxy socket if enabled
            if self.use_tor and self.tor_session:
                s = self.tor_session.get_proxy_socket(timeout=self.TIMEOUT)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.TIMEOUT)
            
            if not s:
                return ""
                
            s.connect((host, port))
            
            if send_data:
                s.send(send_data)
                
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner
        except Exception as e:
            logger.debug(f"Banner grab failed for {host}:{port} - {e}")
            return ""
        finally:
            if s:
                s.close()
    
    def _fingerprint_postgresql(self, host: str, port: int) -> Dict[str, Any]:
        """
        Fingerprint PostgreSQL service.
        """
        try:
            # PostgreSQL doesn't send banner without proper handshake, just check if connection is possible
            s = self._grab_banner(host, port) # Just try to connect and close
            
            return {"service": "postgresql", "product": "postgresql", "version": "unknown"}
            
        except Exception as e:
            logger.debug(f"PostgreSQL fingerprint failed for {host}:{port}: {e}")
            return {"service": "postgresql", "product": "unknown", "version": "unknown"}
    
    def _fingerprint_redis(self, host: str, port: int) -> Dict[str, Any]:
        """
        Fingerprint Redis by sending INFO command.
        """
        try:
            s = socket.create_connection((host, port), timeout=self.TIMEOUT)
            s.send(b"INFO\r\n")
            response = s.recv(4096).decode('utf-8', errors='ignore')
            s.close()
            
            # Parse Redis version from INFO response
            version_match = re.search(r'redis_version:([\\d\\.]+)', response)
            if version_match:
                version = version_match.group(1)
                logger.info(f"Redis version from {host}:{port} - {version}")
                return {"service": "redis", "product": "redis", "version": version}
            
            return {"service": "redis", "product": "redis", "version": "unknown"}
            
        except Exception as e:
            logger.debug(f"Redis fingerprint failed for {host}:{port}: {e}")
            return {"service": "redis", "product": "unknown", "version": "unknown"}
    
    def _fingerprint_generic(self, host: str, port: int) -> Dict[str, Any]:
        """
        Generic TCP banner grabbing for unknown services.
        """
        try:
            s = socket.create_connection((host, port), timeout=self.TIMEOUT)
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            s.close()
            
            if banner:
                logger.info(f"Generic banner from {host}:{port} - {banner}")
                return self._parse_banner(banner, "unknown")
            
            return {"service": "unknown", "product": "unknown", "version": "unknown"}
            
        except Exception as e:
            logger.debug(f"Generic fingerprint failed for {host}:{port}: {e}")
            return {"service": "unknown", "product": "unknown", "version": "unknown"}
    
    def _parse_banner(self, banner: str, service: str) -> Dict[str, Any]:
        """
        Parse banner string to extract product and version.
        
        Args:
            banner: Raw banner string
            service: Service type (http, ssh, ftp, etc.)
            
        Returns:
            Dictionary with service, product, and version
        """
        banner_lower = banner.lower()
        
        # Try to match against known patterns
        for product, regex in self.BANNER_PATTERNS.items():
            match = re.search(regex, banner_lower)
            if match:
                version = match.group(1) if match.lastindex and match.lastindex >= 1 else "*"
                logger.debug(f"Matched {product} version {version}")
                return {
                    "service": service,
                    "product": product,
                    "version": version or "*",
                    "banner": banner
                }
        
        # If no pattern matched, return unknown with banner for reference
        logger.debug(f"No pattern matched for banner: {banner}")
        return {
            "service": service,
            "product": "unknown",
            "version": "unknown",
            "banner": banner
        }

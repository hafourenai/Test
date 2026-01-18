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
from typing import Dict, Any, Optional

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    requests = None

logger = logging.getLogger(__name__)


class ServiceFingerprinter:
    """Active service fingerprinting engine for real software identification"""
    
    TIMEOUT = 4
    
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
    
    def _fingerprint_http(self, host: str, port: int, https: bool) -> Dict[str, Any]:
        """
        Fingerprint HTTP/HTTPS services by analyzing headers.
        
        Args:
            host: Target hostname
            port: Target port
            https: Whether to use HTTPS
            
        Returns:
            Service fingerprint dictionary
        """
        if not requests:
            logger.warning("requests library not available, skipping HTTP fingerprinting")
            return {"service": "http", "product": "unknown", "version": "unknown"}
        
        scheme = "https" if https else "http"
        url = f"{scheme}://{host}:{port}"
        
        try:
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
            s = socket.create_connection((host, port), timeout=self.TIMEOUT)
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            s.close()
            
            logger.info(f"SSH banner from {host}:{port} - {banner}")
            return self._parse_banner(banner, "ssh")
            
        except socket.timeout:
            logger.debug(f"Timeout connecting to SSH on {host}:{port}")
            return {"service": "ssh", "product": "unknown", "version": "unknown"}
        except Exception as e:
            logger.debug(f"SSH fingerprint failed for {host}:{port}: {e}")
            return {"service": "ssh", "product": "unknown", "version": "unknown"}
    
    def _fingerprint_ftp(self, host: str, port: int) -> Dict[str, Any]:
        """
        Fingerprint FTP service by reading the welcome banner.
        """
        try:
            s = socket.create_connection((host, port), timeout=self.TIMEOUT)
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            s.close()
            
            logger.info(f"FTP banner from {host}:{port} - {banner}")
            return self._parse_banner(banner, "ftp")
            
        except socket.timeout:
            logger.debug(f"Timeout connecting to FTP on {host}:{port}")
            return {"service": "ftp", "product": "unknown", "version": "unknown"}
        except Exception as e:
            logger.debug(f"FTP fingerprint failed for {host}:{port}: {e}")
            return {"service": "ftp", "product": "unknown", "version": "unknown"}
    
    def _fingerprint_smtp(self, host: str, port: int) -> Dict[str, Any]:
        """
        Fingerprint SMTP service by reading the banner.
        """
        try:
            s = socket.create_connection((host, port), timeout=self.TIMEOUT)
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            s.close()
            
            logger.info(f"SMTP banner from {host}:{port} - {banner}")
            return self._parse_banner(banner, "smtp")
            
        except Exception as e:
            logger.debug(f"SMTP fingerprint failed for {host}:{port}: {e}")
            return {"service": "smtp", "product": "unknown", "version": "unknown"}
    
    def _fingerprint_mysql(self, host: str, port: int) -> Dict[str, Any]:
        """
        Fingerprint MySQL/MariaDB by attempting connection.
        """
        try:
            s = socket.create_connection((host, port), timeout=self.TIMEOUT)
            # MySQL sends server greeting immediately
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            s.close()
            
            logger.info(f"MySQL banner from {host}:{port} - {banner}")
            return self._parse_banner(banner, "mysql")
            
        except Exception as e:
            logger.debug(f"MySQL fingerprint failed for {host}:{port}: {e}")
            return {"service": "mysql", "product": "unknown", "version": "unknown"}
    
    def _fingerprint_postgresql(self, host: str, port: int) -> Dict[str, Any]:
        """
        Fingerprint PostgreSQL service.
        """
        try:
            s = socket.create_connection((host, port), timeout=self.TIMEOUT)
            s.close()
            
            # PostgreSQL doesn't send banner without proper handshake
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

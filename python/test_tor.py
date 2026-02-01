#!/usr/bin/env python3
"""
Tor Connection Test Script
Verifies that Python traffic is routing through Tor SOCKS5 proxy
"""

import sys
import logging
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from tor_session import TorSession
import requests

logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def test_direct_connection():
    """Test direct connection (without Tor)"""
    print("\n" + "="*60)
    print("TEST 1: Direct Connection (WITHOUT Tor)")
    print("="*60)
    
    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=10)
        if response.status_code == 200:
            direct_ip = response.json().get('ip', 'unknown')
            print(f"[Success] Direct IP: {direct_ip}")
            return direct_ip
        else:
            print(f"[Error] Failed to get direct IP - Status: {response.status_code}")
            return None
    except Exception as e:
        print(f"[Error] Direct connection failed: {e}")
        return None


def test_tor_connection():
    """Test connection through Tor"""
    print("\n" + "="*60)
    print("TEST 2: Tor Connection (WITH Tor)")
    print("="*60)
    
    try:
        with TorSession() as tor:
            # Verify Tor connection
            if not tor.verify_tor_connection():
                print("\n[Error] CRITICAL: Tor verification failed!")
                print("   Your traffic is NOT going through Tor!")
                return None, False
            
            # Get Tor exit IP
            tor_ip = tor.get_current_ip()
            
            return tor_ip, True
            
    except Exception as e:
        print(f"[Error] Tor connection failed: {e}")
        print("\nTroubleshooting:")
        print("  1. Check if Tor is running:")
        print("     curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip")
        print("  2. Start Tor if needed:")
        print("     sudo systemctl start tor")
        print("  3. Check Tor logs:")
        print("     sudo journalctl -u tor -f")
        return None, False


def test_dns_leak():
    """Test for DNS leaks"""
    print("\n" + "="*60)
    print("TEST 3: DNS Leak Test")
    print("="*60)
    
    try:
        with TorSession() as tor:
            # Test DNS resolution through Tor
            response = tor.get('https://www.dnsleaktest.com/api/dns', timeout=15)
            
            if response and response.status_code == 200:
                dns_servers = response.json()
                print(f"[Success] DNS servers detected: {len(dns_servers)}")
                
                for i, server in enumerate(dns_servers[:3], 1):
                    print(f"   {i}. {server.get('ip', 'unknown')} - {server.get('country_name', 'unknown')}")
                
                # Check if DNS is leaking (should not be your ISP's DNS)
                print("\n[Info] If you see your ISP's DNS servers above, you have a DNS leak!")
                return True
            else:
                print("[Warning] Could not perform DNS leak test")
                return False
                
    except Exception as e:
        print(f"[Warning] DNS leak test failed: {e}")
        return False


def compare_ips(direct_ip, tor_ip):
    """Compare direct and Tor IPs"""
    print("\n" + "="*60)
    print("COMPARISON RESULTS")
    print("="*60)
    
    if not direct_ip or not tor_ip:
        print("[Error] Cannot compare - missing IP addresses")
        return False
    
    print(f"\n[IP] Direct IP:  {direct_ip}")
    print(f"[Tor] Tor IP:     {tor_ip}")
    
    if direct_ip == tor_ip:
        print("\n[Error] CRITICAL FAILURE!")
        print("   IPs are the SAME - Tor is NOT working!")
        print("   Your traffic is leaking directly to ISP!")
        return False
    else:
        print("\n[Success] SUCCESS!")
        print("   IPs are DIFFERENT - Tor is working correctly!")
        print("   Your Python traffic is routing through Tor!")
        return True


def main():
    print("""
╔═══════════════════════════════════════════════════════╗
║         TOR CONNECTION VERIFICATION TEST              ║
║   Verifies Python traffic routes through Tor         ║
╚═══════════════════════════════════════════════════════╝
    """)
    
    # Test 1: Direct connection
    direct_ip = test_direct_connection()
    
    # Test 2: Tor connection
    tor_ip, tor_verified = test_tor_connection()
    
    # Test 3: DNS leak test
    test_dns_leak()
    
    # Compare results
    success = compare_ips(direct_ip, tor_ip)
    
    # Final verdict
    print("\n" + "="*60)
    print("FINAL VERDICT")
    print("="*60)
    
    if success and tor_verified:
        print("\n[Success] ALL TESTS PASSED!")
        print("   Your Python application is correctly routing through Tor")
        print("   No DNS leaks detected")
        print("\n[Done] You can now use the scanner with --use-tor flag")
        return 0
    else:
        print("\n[Error] TESTS FAILED!")
        print("   Your Python application is NOT using Tor correctly")
        print("\n[Info] Troubleshooting steps:")
        print("   1. Ensure Tor is running: sudo systemctl status tor")
        print("   2. Check Tor SOCKS port: netstat -tlnp | grep 9050")
        print("   3. Test Tor manually:")
        print("      curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip")
        print("   4. Check firewall rules")
        print("   5. Verify PySocks is installed: pip install PySocks")
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n  Test interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

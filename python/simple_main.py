"""
Vulnerability Scanner - Love U N
  High-Speed Vulnerability Detection with Custom Payloads
"""

import argparse
import sys
import logging
import asyncio
from pathlib import Path

try:
    from .unified_scanner import UnifiedScanner
    from .config import NVD_API_KEY
except ImportError:
    from unified_scanner import UnifiedScanner
    from config import NVD_API_KEY

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def print_banner():
    """Display scanner banner"""
    banner = """
+===============================================+
|                  LOVE U N                     |
|   Amateurs Vulnerability Scanner              |
|   Just For Education                          |
+===============================================+
    """
    print(banner)

def print_disclaimer():
    """Display legal disclaimer"""
    disclaimer = """
⚖️  LEGAL DISCLAIMER:
   • Only scan systems you own or have written permission to test
   • Unauthorized scanning may be illegal in your jurisdiction
   • User assumes all responsibility for scanner usage
   
 PRIVACY NOTICE:
   • Results are for authorized security testing only
   • Vulnerability presence does not imply exploitability
    """
    print(disclaimer)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='Amateurs Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Target arguments
    parser.add_argument('target', help='Target IP or domain')
    parser.add_argument('-o', '--output', help='Output file (JSON format)')
    parser.add_argument('-w', '--workers', type=int, default=100,
                       help='Number of concurrent workers (default: 100)')
    parser.add_argument('-t', '--timeout', type=int, default=3,
                       help='Request timeout in seconds (default: 3)')
    
    # Payload options
    parser.add_argument('-x', '--xss-file', help='XSS payloads file')
    parser.add_argument('-s', '--sqli-file', help='SQL injection payloads file')
    parser.add_argument('-l', '--lfi-file', help='LFI payloads file')
    
    # Scanning options
    parser.add_argument('--stealth', default='ninja',
                       help='Stealth level (ghost, ninja, balanced, fast)')
    parser.add_argument('--tor', action='store_true',
                       help='Route traffic through Tor')
    parser.add_argument('--proxies', action='store_true',
                       help='Enable proxy rotation')
    
    # Other options
    parser.add_argument('--accept-disclaimer', action='store_true',
                       help='Accept legal disclaimer')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Show disclaimer
    if not args.accept_disclaimer:
        print_disclaimer()
        response = input("\nDo you accept these terms? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("Disclaimer not accepted. Exiting.")
            sys.exit(1)
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    print(f"\n[+] Starting   Vulnerability Scan")
    print(f"[+] Target: {args.target}")
    print(f"[+] Workers: {args.workers} | Timeout: {args.timeout}s")
    print(f"[+] Stealth: {args.stealth}")
    
    
    scanner = UnifiedScanner(
        stealth_level=args.stealth,
        use_tor=args.tor,
        use_proxies=args.proxies,
        nvd_api_key=NVD_API_KEY,
        enable_cve_matching=True
    )
    
    
    if args.xss_file and Path(args.xss_file).exists():
        scanner.payload_manager.load_payloads('xss', args.xss_file)
    
    if args.sqli_file and Path(args.sqli_file).exists():
        scanner.payload_manager.load_payloads('sqli', args.sqli_file)
    
    if args.lfi_file and Path(args.lfi_file).exists():
        scanner.payload_manager.load_payloads('lfi', args.lfi_file)
    
    
    results = asyncio.run(scanner.scan_target(target=args.target))
    
    if results:
        
        stats = results.get('statistics', {})
        total_vulns = stats.get('vulnerabilities_found', 0)
        
        print(f"\n[+] Scan Complete")
        print(f"[+] Duration: {stats.get('duration', 0):.2f}s")
        print(f"[+] Vulnerabilities Found: {total_vulns}")
        
        
        cve_findings = results.get('cve_findings', [])
        dast_findings = results.get('dast_findings', [])
        
        has_critical = any(
            f.get('confidence') == 'High' for f in dast_findings
        ) or any(
            f.get('severity', '').lower() == 'critical' for f in cve_findings
        )
        
        if has_critical:
            sys.exit(2)
        elif total_vulns > 0:
            sys.exit(1)
        else:
            sys.exit(0)
    else:
        print("[!] Scan failed")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
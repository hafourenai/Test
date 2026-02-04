"""
Vulnerability Scanner - Love U N
  High-Speed Vulnerability Detection with Custom Payloads
"""

import argparse
import json
import sys
import logging
import os
import asyncio
from pathlib import Path
from datetime import datetime

try:
    from .simple_ _scanner import CustomPayloadScanner
except ImportError:
    from simple_ _scanner import CustomPayloadScanner

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
|   High-Speed Vulnerability Scanner          |
|   Custom Payloads • High-Accuracy          |
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
   
🔒 PRIVACY NOTICE:
   • Results are for authorized security testing only
   • Vulnerability presence does not imply exploitability
    """
    print(disclaimer)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='High-Speed Vulnerability Scanner with Custom Payloads',
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
    
    print(f"\n[+] Starting   Vulnerability Scan")
    print(f"[+] Target: {args.target}")
    print(f"[+] Workers: {args.workers} | Timeout: {args.timeout}s")
    
    # Load custom payloads
    scanner = CustomPayloadScanner()
    
    if args.xss_file and Path(args.xss_file).exists():
        scanner.load_payloads_from_file(args.xss_file)
    
    if args.sqli_file and Path(args.sqli_file).exists():
        scanner.load_payloads_from_file(args.sqli_file)
    
    if args.lfi_file and Path(args.lfi_file).exists():
        scanner.load_payloads_from_file(args.lfi_file)
    
    # Execute scanner
    results = asyncio.run(
        scanner.run_scan(
            target=args.target,
            output_file=args.output,
            max_workers=args.workers,
            timeout=args.timeout,
            xss_file=args.xss_file,
            sqli_file=args.sqli_file,
            lfi_file=args.lfi_file
        )
    )
    
    if results:
        print(scanner.format_results(results))
        
        stats = results['statistics']
        if stats['critical'] > 0 or stats['high'] > 0:
            sys.exit(2)
        elif stats['total_vulnerabilities'] > 0:
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
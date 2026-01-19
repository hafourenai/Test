"""
Vulnerability Scanner - Love U N
Enhanced with Proxy Rotation and Tor Integration
"""

import argparse
import json
import sys
import logging
import os
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

def load_env(env_path: Path):
    """Simple .env loader to avoid extra dependencies"""
    if env_path.exists():
        with open(env_path, 'r') as f:
            for line in f:
                if '=' in line and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    os.environ[key.strip()] = value.strip()

from stealth_orchestrator import StealthOrchestrator
from orchestrator import ScanOrchestrator
from plugin_loader import PluginLoader
from output_handler import OutputHandler
from proxy_manager import ProxyManager

# Import NVD components
try:
    from modules.cve_matcher import CVEMatcher
    NVD_AVAILABLE = True
except ImportError:
    NVD_AVAILABLE = False
    print("⚠️  Warning: NVD modules not available")

# Import config
try:
    from config import setup_config
    setup_config()
except ImportError:
    pass

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def print_banner():
    """Display scanner banner"""
    banner = """
╔═══════════════════════════════════════════════════╗
║                  LOVE U N - v2.0                  ║
║   Python + Go + Tor + Proxy Rotation              ║
║   Tor Support | Proxy Rotation                    ║
║   For Educational & Research Use Only             ║
╚═══════════════════════════════════════════════════╝
    """
    print(banner)


def print_disclaimer():
    """Display legal disclaimer"""
    disclaimer = """
⚖️  LEGAL DISCLAIMER:
   • Only scan systems you own or have written permission to test
   • Unauthorized scanning may be illegal in your jurisdiction
   • Using proxies/Tor does not make illegal activity legal
   • Proxy/Tor usage may be monitored or restricted
   • User assumes all responsibility for scanner usage
   • This tool is for security research and education only
   
🔒 PRIVACY NOTICE:
   • Proxies may log your traffic
   • Use trusted proxy providers only
   • Tor provides anonymity but not legal immunity
   • Your ISP may detect Tor usage
    """
    print(disclaimer)


def test_proxy_setup(proxy_manager: ProxyManager):
    """Test proxy configuration"""
    print("\n🧪 Testing Proxy Setup...")
    
    if not proxy_manager:
        print("   ❌ No proxy manager initialized")
        return
    
    # Test without proxy
    print("   📡 Your real IP:")
    real_ip = proxy_manager.get_public_ip(use_proxy=False)
    print(f"      {real_ip}")
    
    # Test with proxy
    if proxy_manager.proxies or proxy_manager.use_tor:
        print("   🔄 IP through proxy/Tor:")
        proxy_ip = proxy_manager.get_public_ip(use_proxy=True)
        print(f"      {proxy_ip}")
        
        if proxy_ip != real_ip:
            print("     Proxy/Tor is working correctly!")
        else:
            print("   ⚠️  Warning: IP not changed, proxy may not be working")
    else:
        print("   ⚠️  No proxies loaded and Tor not enabled")


def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='Vulnerability Scanner with Stealth Features (Python + Go)',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Target arguments
    parser.add_argument('target', help='Target IP or domain')
    parser.add_argument('-s', '--start-port', type=int, default=1,
                       help='Start port (default: 1)')
    parser.add_argument('-e', '--end-port', type=int, default=1000,
                       help='End port (default: 1000)')
    parser.add_argument('-t', '--timeout', type=int, default=2,
                       help='Timeout in seconds (default: 2)')
    parser.add_argument('-T', '--threads', type=int, default=100,
                       help='Number of threads (default: 100)')
    
    # Stealth features
    stealth_group = parser.add_argument_group('Stealth Options')
    stealth_group.add_argument('--use-proxies', action='store_true',
                              help='Enable proxy rotation from proxies.txt')
    stealth_group.add_argument('--use-tor', action='store_true',
                              help='Use Tor network (requires Tor installed)')
    stealth_group.add_argument('--proxies-file', default='proxies.txt',
                              help='Path to proxies file (default: proxies.txt)')
    stealth_group.add_argument('--test-proxies', action='store_true',
                              help='Test proxy configuration and exit')
    stealth_group.add_argument('--validate-proxies', action='store_true',
                              help='Validate all proxies before scanning')
    stealth_group.add_argument('--rotate-interval', type=int, default=10,
                              help='Rotate proxy every N requests (default: 10)')
    
    # Scanner options
    parser.add_argument('-o', '--output', help='Output file (JSON)')
    parser.add_argument('--no-cve', action='store_true',
                       help='Skip CVE matching')
    parser.add_argument('--no-plugins', action='store_true',
                       help='Skip plugin execution')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--accept-disclaimer', action='store_true',
                       help='Accept legal disclaimer')
    
    args = parser.parse_args()
    
    # Test proxies mode
    if args.test_proxies:
        print("🧪 Proxy Test Mode")
        proxy_mgr = ProxyManager(
            proxies_file=args.proxies_file,
            use_tor=args.use_tor
        )
        test_proxy_setup(proxy_mgr)
        
        if args.validate_proxies and proxy_mgr.proxies:
            proxy_mgr.validate_all_proxies()
        
        sys.exit(0)
    
    # Show disclaimer
    if not args.accept_disclaimer:
        print_disclaimer()
        response = input("\nDo you accept this disclaimer? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("❌ Disclaimer not accepted. Exiting.")
            sys.exit(1)
    
    # Initialize stealth orchestrator
    use_stealth = args.use_proxies or args.use_tor
    
    if use_stealth:
        logger.info("[!] Stealth mode enabled")
        orchestrator = StealthOrchestrator(
            use_proxies=args.use_proxies,
            use_tor=args.use_tor,
            proxies_file=args.proxies_file
        )
        
        # Test proxy setup
        if orchestrator.proxy_manager:
            test_proxy_setup(orchestrator.proxy_manager)
            
            # Validate proxies if requested
            if args.validate_proxies and orchestrator.proxy_manager.proxies:
                orchestrator.proxy_manager.validate_all_proxies()
    else:
        logger.info("[*] Standard mode (no stealth features)")
        orchestrator = ScanOrchestrator()
    
    # Initialize other components
    # Load environment from project root
    load_env(Path(__file__).parent.parent / '.env')
    
    nvd_key = os.getenv("NVD_API_KEY")
    
    # Initialize CVE matcher with Tor support if enabled
    if NVD_AVAILABLE:
        cve_matcher = CVEMatcher(api_key=nvd_key, use_tor=use_stealth)
        if use_stealth:
            logger.info("[Tor] NVD API will use Tor network")
    else:
        cve_matcher = None
        logger.warning("[!] CVE matching disabled (NVD modules not available)")
    
    plugin_loader = PluginLoader()
    output_handler = OutputHandler()
    
    # Validate target
    if not orchestrator.validate_target(args.target):
        print(f"❌ Invalid target: {args.target}")
        sys.exit(1)
    
    # Execute scanner
    scan_results = orchestrator.execute_go_scanner(
        target=args.target,
        start_port=args.start_port,
        end_port=args.end_port,
        timeout=args.timeout,
        threads=args.threads,
        use_proxy=use_stealth
    )
    
    if not scan_results:
        print("❌ Scan failed or returned no results")
        sys.exit(1)
    
    vulnerabilities = []
    if not args.no_cve and cve_matcher:
        print("\n[Scan] Correlating with Real-Time NVD Intelligence Engine...")
        
        # Convert services to format expected by CVE matcher
        service_list = []
        for svc in scan_results.get('services', []):
            service_list.append({
                'name': svc.get('service', 'unknown'),
                'version': svc.get('version'),
                'port': svc.get('port'),
                'product': svc.get('product')
            })
        
        if service_list:
            findings = cve_matcher.match_vulnerabilities(service_list)
            
            if findings:
                print(f"[Success] Found {sum(f['total_cves'] for f in findings)} potential vulnerabilities")
                print(cve_matcher.format_findings(findings))
                
                # Export reports
                timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                reports_dir = Path(__file__).parent / 'reports'
                reports_dir.mkdir(exist_ok=True)
                
                json_file = reports_dir / f'vulns_{timestamp}.json'
                csv_file = reports_dir / f'vulns_{timestamp}.csv'
                
                cve_matcher.export_json(findings, str(json_file))
                cve_matcher.export_csv(findings, str(csv_file))
                
                vulnerabilities = findings
            else:
                print("  No known vulnerabilities found")
        else:
            print("⚠️  No services detected for CVE matching")
    elif args.no_cve:
        print("\n⏭️  CVE matching skipped (--no-cve flag)")
    else:
        print("\n⚠️  CVE matching unavailable (NVD modules not loaded)")
    
    # Plugin execution
    plugin_results = []
    if not args.no_plugins:
        print("\n🔌 Running security plugins...")
        plugins = plugin_loader.load_all_plugins()
        for plugin in plugins:
            findings = plugin.analyze(scan_results)
            if findings:
                plugin_results.extend(findings)
        
        print(f"  Plugins generated {len(plugin_results)} findings")
    
    # Compile final report
    final_report = {
        "metadata": {
            "scanner_version": "2.0-stealth",
            "timestamp": datetime.utcnow().isoformat(),
            "target": args.target,
            "stealth_mode": {
                "proxies_enabled": args.use_proxies,
                "tor_enabled": args.use_tor,
                "proxy_count": len(orchestrator.proxy_manager.proxies) if hasattr(orchestrator, 'proxy_manager') and orchestrator.proxy_manager else 0
            },
            "scan_parameters": {
                "port_range": f"{args.start_port}-{args.end_port}",
                "timeout": args.timeout,
                "threads": args.threads
            }
        },
        "scan_results": scan_results,
        "vulnerabilities": vulnerabilities,
        "plugin_findings": plugin_results,
        "statistics": {
            "open_ports": len(scan_results.get('open_ports', [])),
            "services_detected": len(scan_results.get('services', [])),
            "vulnerabilities_found": len(vulnerabilities),
            "plugin_findings": len(plugin_results)
        }
    }
    
    # Output results
    if args.output:
        output_handler.save_json(final_report, args.output)
        print(f"\n💾 Report saved to: {args.output}")
    else:
        output_handler.print_summary(final_report)
    
    if args.verbose:
        print("\n" + "="*60)
        print(json.dumps(final_report, indent=2))
    
    # Stealth mode summary
    if use_stealth and hasattr(orchestrator, 'proxy_manager'):
        print("\n🔒 Stealth Mode Summary:")
        if args.use_tor:
            print("     Tor: ENABLED")
        if args.use_proxies:
            print(f"   🔄 Proxies: {len(orchestrator.proxy_manager.proxies)} loaded")
        
        # Show final IP
        if orchestrator.proxy_manager:
            final_ip = orchestrator.proxy_manager.get_public_ip(use_proxy=True)
            print(f"   📡 Exit IP: {final_ip}")
    
    print("\n  Scan completed successfully")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

# update_cve_database.py
"""
Standalone script to update CVE database from NVD API
Run this script to fetch latest CVEs
"""

import sys
import os
from pathlib import Path

# Add python directory to path
sys.path.insert(0, str(Path(__file__).parent))

from nvd_fetcher import NVDFetcher
import json
from datetime import datetime
import re


def load_api_key():
    """Load API key from .env file"""
    env_file = Path(__file__).parent.parent / '.env'
    
    if env_file.exists():
        with open(env_file, 'r') as f:
            content = f.read()
            # Try different formats
            patterns = [
                r'NVD_API_KEY\s*=\s*([a-f0-9-]+)',
                r'NVD_API_KEY\s*=\s*"([a-f0-9-]+)"',
                r'NVD_API_KEY\s*=\s*\'([a-f0-9-]+)\'',
            ]
            for pattern in patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    api_key = match.group(1).strip()
                    print(f"✅ Loaded API key: {api_key[:8]}...{api_key[-4:]}")
                    return api_key
    
    print("⚠️  No API key found in .env file")
    return None


def fetch_popular_service_cves(fetcher, services, max_per_service=20):
    """Fetch CVEs for popular services"""
    all_cves = []
    
    for service in services:
        print(f"\n🔍 Searching CVEs for: {service}")
        cves = fetcher.fetch_cves_by_keyword(service, max_results=max_per_service)
        all_cves.extend(cves)
        print(f"   Found {len(cves)} CVEs")
    
    return all_cves


def main():
    print("="*60)
    print("🔄 CVE Database Updater")
    print("="*60)
    
    # Load API key
    api_key = load_api_key()
    
    if not api_key:
        print("\n❌ No API key found!")
        print("   Please add NVD_API_KEY to .env file")
        print("   Example: NVD_API_KEY = your-api-key-here")
        return
    
    # Initialize fetcher
    fetcher = NVDFetcher(api_key=api_key)
    
    print("\n" + "="*60)
    print("📥 Fetching CVEs from NVD...")
    print("="*60)
    
    all_cves = []
    
    # Strategy 1: Fetch recent critical CVEs
    try:
        print("\n1️⃣  Fetching CRITICAL CVEs from last 90 days...")
        critical_cves = fetcher.fetch_recent_cves(days=90, severity='CRITICAL')
        all_cves.extend(critical_cves)
        print(f"   ✅ Found {len(critical_cves)} CRITICAL CVEs")
    except Exception as e:
        print(f"   ⚠️  Error: {e}")
    
    # Strategy 2: Fetch high severity CVEs
    try:
        print("\n2️⃣  Fetching HIGH severity CVEs from last 90 days...")
        high_cves = fetcher.fetch_recent_cves(days=90, severity='HIGH')
        all_cves.extend(high_cves)
        print(f"   ✅ Found {len(high_cves)} HIGH CVEs")
    except Exception as e:
        print(f"   ⚠️  Error: {e}")
    
    # Strategy 3: Fetch CVEs for popular services
    popular_services = [
        'apache', 'nginx', 'openssh', 'mysql', 'postgresql',
        'redis', 'mongodb', 'windows', 'linux', 'php'
    ]
    
    try:
        print("\n3️⃣  Fetching CVEs for popular services...")
        service_cves = fetch_popular_service_cves(fetcher, popular_services, max_per_service=10)
        all_cves.extend(service_cves)
        print(f"   ✅ Found {len(service_cves)} service-specific CVEs")
    except Exception as e:
        print(f"   ⚠️  Error: {e}")
    
    # Deduplicate by CVE ID
    unique_cves = {cve['cve_id']: cve for cve in all_cves}
    cve_list = list(unique_cves.values())
    
    # Sort by CVSS score (highest first)
    cve_list.sort(key=lambda x: x.get('cvss_score', 0), reverse=True)
    
    print("\n" + "="*60)
    print("📊 CVE Statistics")
    print("="*60)
    print(f"Total CVEs fetched: {len(cve_list)}")
    
    # Count by severity
    severity_counts = {}
    for cve in cve_list:
        severity = cve.get('severity', 'Unknown')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    for severity, count in sorted(severity_counts.items()):
        print(f"   {severity}: {count}")
    
    # Save to file
    output_file = Path(__file__).parent.parent / 'config' / 'cve_feed.json'
    
    print("\n" + "="*60)
    print(f"💾 Saving to: {output_file}")
    print("="*60)
    
    data = {
        'cve_database': cve_list,
        'metadata': {
            'version': '2.0',
            'last_updated': datetime.now().isoformat(),
            'total_cves': len(cve_list),
            'sources': ['NVD - National Vulnerability Database'],
            'api_used': 'NVD API 2.0',
            'severity_breakdown': severity_counts
        }
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Successfully saved {len(cve_list)} CVEs!")
    print("\n" + "="*60)
    print("🎉 CVE Database Update Complete!")
    print("="*60)
    
    # Show top 10 CVEs
    if cve_list:
        print("\n📋 Top 10 Highest Severity CVEs:")
        print("-"*60)
        for i, cve in enumerate(cve_list[:10], 1):
            print(f"{i}. {cve['cve_id']} - {cve['severity']} (CVSS: {cve.get('cvss_score', 0)})")
            print(f"   {cve['description'][:80]}...")
            print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Update cancelled by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

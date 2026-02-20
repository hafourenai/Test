"""
CVE Matcher - Enhanced with Confidence Scoring Engine
Matches detected services with known vulnerabilities using  
confidence scoring and risk assessment.

Phase 1 Enhancement: Integrated confidence scoring for verified findings.
"""

import logging
from typing import List, Dict, Optional
from .nvd_client import NVDClient

try:
    from confidence_engine import ConfidenceEngine, ConfidenceLevel, RiskLevel
except ImportError:
    try:
        from ...confidence_engine import ConfidenceEngine, ConfidenceLevel, RiskLevel
    except (ImportError, ValueError):
        import sys
        import os
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
        from confidence_engine import ConfidenceEngine, ConfidenceLevel, RiskLevel

logger = logging.getLogger(__name__)


class CVEMatcher:
    """Matches services with CVEs from NVD with   relevance filtering"""
    
    def __init__(self, nvd_api_key: Optional[str] = None, use_tor: bool = False, scoring: bool = True, verification: bool = False):
        """
        Initialize Enhanced CVE Matcher with confidence scoring
        
        Args:
            nvd_api_key: Optional NVD API key for better rate limits
            use_tor: Whether to route NVD API traffic through Tor
            scoring: Enable confidence scoring (default: True for Phase 1)
            verification: Enable safe vulnerability verification (default: False for Phase 2)
        """
        self.nvd_client = NVDClient(api_key=nvd_api_key, use_tor=use_tor)
        self.scoring = scoring
        self.verification = verification
        self._cve_cache = {} 
        
        if self.scoring:
            self.confidence_engine = ConfidenceEngine()
            logger.info("[CONF] Confidence scoring engine enabled for CVE matching")
        else:
            self.confidence_engine = None
            logger.info("[CONF] Using legacy correlation-based scoring")
        
        if self.verification:
            try:
                from ...verification_integration import VulnerabilityVerifier
                self.verifier = VulnerabilityVerifier(use_tor=use_tor, enable_verification=True)
                logger.info("[VERIFY] Vulnerability verification integration enabled")
            except ImportError:
                try:
                    from verification_integration import VulnerabilityVerifier
                    self.verifier = VulnerabilityVerifier(use_tor=use_tor, enable_verification=True)
                    logger.info("[VERIFY] Vulnerability verification integration enabled")
                except ImportError:
                    self.verifier = None
                    logger.warning("[VERIFY] Could not import verification integration, falling back to correlation-only")
        else:
            self.verifier = None
            if self.scoring:
                logger.info("[VERIFY] Verification disabled - using correlation-based scoring only")
            else:
                logger.info("[VERIFY] Verification disabled - using legacy correlation scoring")
        
        self.vendor_alias_map = {
            "nginx": ["nginx", "f5"],
            "apache": ["apache", "httpd"], 
            "openssh": ["openssh", "openbsd"],
            "iis": ["iis", "microsoft"],
            "mysql": ["mysql", "oracle"],
            "postgresql": ["postgresql", "postgres"],
            "tomcat": ["tomcat", "apache"],
            "php": ["php"],
            "http": ["http", "web", "www"]
        }
        
        self.irrelevant_indicators = [
            'kaseya', 'vsa', 'zzcms', 'wordpress', 'joomla', 'drupal', 
            'sangfor', 'softnas', 'puppet discovery', 'asus', 'netgear',
            'asuswrt', 'linksys', 'dlink', 'tplink'
        ]
        
        logger.info("[Net] Real-Time NVD CVE Matcher Initialized")
        logger.info("[ ] Vendor validation enabled with explicit mapping")
        if use_tor:
            logger.info("[Tor] CVE Matcher will use Tor for NVD API requests")
            logger.info("[Tor] CVE Matcher will use Tor for NVD API requests")

    def _parse_products_from_banner(self, banner: str):
        """
        Extract products from banner:
        nginx/1.19.0 PHP/5.6.40-38+ubuntu...
        """
        if not banner:
            return []

        products = []
        import re
        patterns = [
            r'(nginx)/([\d\.]+)',
            r'(php)/([\d\.]+)'
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, banner, re.I):
                product, version = match.groups()
                products.append({
                    "vendor": product.lower(),
                    "product": product.lower(),
                    "version": version
                })

        return products

    def match_vulnerabilities(self, services: List[Dict]) -> List[Dict]:
        """
        Match detected services with known CVEs (Hardened Version 2.1)
        """
        findings = []
        
        service_count = len(services)
        logger.info(f"[Search] Matching {service_count} services against NVD database...")
        
        if self.verification and self.verifier:
            logger.info("[VERIFY] Safe verification enabled - will attempt evidence-based verification")
        elif self.verification:
            logger.warning("[VERIFY] Verification flag set but verifier not available - falling back to correlation")
        elif self.scoring:
            logger.info("[SEARCH] Using correlation-based scoring with confidence engine (Phase 1)")
        else:
            logger.info("[SEARCH] Using legacy correlation-based scoring (verification disabled)")
        
        for service in services:
            banner = service.get("banner", "")
            products = self._parse_products_from_banner(banner)

            if not products:
                 p_name = service.get('product', service.get('service', 'unknown'))
                 p_version = service.get('version', 'unknown')
                 
                 if p_name != 'unknown':
                     products.append({
                        "vendor": service.get('service', 'unknown'),
                        "product": p_name,
                        "version": p_version
                     })

            if not products:
                logger.debug(f"Skipping service on port {service.get('port')}: No product identified")
                continue

            for prod in products:
                p_product = prod.get('product', '').strip()
                p_version = prod.get('version', '').strip()
                
                if not p_product or p_product == 'unknown':
                    continue

                keyword = f"{p_product} {p_version}" if p_version != 'unknown' else p_product
                
                if keyword in self._cve_cache:
                    logger.debug(f"Cache hit for: {keyword}")
                    cves = self._cve_cache[keyword]
                else:
                    logger.info(f"Searching CVEs for: {keyword}")
                    version_param = p_version if p_version and p_version != 'unknown' else None
                    cves = self.nvd_client.get_cves_for_service(p_product, version_param)
                    self._cve_cache[keyword] = cves

                svc_findings_cves = []
                
                for cve in cves:
                    if self.confidence_engine:
                        #   confidence scoring
                        confidence_result = self.confidence_engine.calculate_cve_confidence(prod, cve)
                        
                        context = {
                            'exposure': 'internet', 
                            'authentication': False,
                            'port': service.get('port', 0)
                        }
                        risk_result = self.confidence_engine.calculate_risk_assessment(
                            cve, confidence_result.score, context
                        )
                        
                        analysis = {
                            "confidence_score": confidence_result.score,
                            "confidence_level": confidence_result.level.value,
                            "risk_score": risk_result.score,
                            "risk_level": risk_result.level.value,
                            "signals": confidence_result.signals,
                            "evidence": confidence_result.evidence,
                            "explanation": confidence_result.explanation,
                            "risk_explanation": risk_result.explanation
                        }
                        
                        if confidence_result.score >= 0.8 and risk_result.score >= 0.7:
                            severity = "HIGH_CONFIDENCE"
                        elif confidence_result.score >= 0.6 and risk_result.score >= 0.5:
                            severity = "MEDIUM_CONFIDENCE"
                        elif confidence_result.score >= 0.4:
                            severity = "POTENTIAL"
                        else:
                            severity = "INFORMATIONAL"
                            
                        score = int(confidence_result.score * 100)  # Convert to 0-100 scale
                        
                    else:
                        score, analysis = self._score_relevance_v2(cve, prod)
                        severity = "INFORMATIONAL"
                        if score >= 80:
                            severity = "HIGH"
                        elif score >= 60:
                            severity = "MEDIUM"

                    if "evidence" not in analysis:
                        analysis["evidence"] = f"vendor:{prod.get('vendor','')} product:{prod.get('product','')} version:{prod.get('version','')}"

                        cve_finding = {
                            "id": cve["id"],
                            "score": score,
                            "severity_class": severity, 
                            "product": prod["product"],
                            "version": prod["version"],
                            "enhanced_analysis": analysis,
                            "description": cve.get("description", ""),
                            "severity": cve.get("severity", "UNKNOWN"),
                            "url": cve.get("url", ""),
                            "cvss_v3": cve.get("cvss_v3", ""),
                            "verified": (confidence_result.score >= 0.7) if self.confidence_engine else (score >= 70)
                        }
                        
                        if self.verifier and self.verification:
                            try:
                                target_info = {
                                    'host': service.get('target', 'unknown'),
                                    'port': service.get('port', 0),
                                    'service': service.get('service', prod['product']),
                                    'product': prod['product'],
                                    'version': prod['version'],
                                    'banner': service.get('banner', '')
                                }
                                
                                logger.info(f"[VERIFY] {cve['id']} verification started")
                                verified_findings = self.verifier.verify_cve_findings([cve_finding], target_info)
                                
                                if verified_findings:
                                    enhanced_finding = verified_findings[0]
                                    
                                    verification_status = enhanced_finding.get('verification_status', 'UNVERIFIED')
                                    evidence_count = enhanced_finding.get('evidence_count', 0)
                                    verification_method = enhanced_finding.get('verification_method', 'unknown')
                                    
                                    logger.info(f"[VERIFY] Evidence detected: {evidence_count} items found" if evidence_count > 0 else "[VERIFY] No evidence detected")
                                    logger.info(f"[VERIFY] Status: {verification_status}")
                                    
                                    if enhanced_finding.get('verification_status') == 'VERIFIED':
                                        original_score = cve_finding.get('score', 0)
                                        verification_score = enhanced_finding.get('verification_confidence', 0) * 100  # Convert to 0-100 scale
                                        combined_score = int(original_score * 0.4 + verification_score * 0.6)
                                        
                                        cve_finding['score'] = combined_score
                                        cve_finding['verified'] = True
                                        cve_finding['verification_status'] = 'VERIFIED'
                                        cve_finding['verification_method'] = verification_method
                                        cve_finding['evidence_count'] = evidence_count
                                        cve_finding['verification_confidence'] = enhanced_finding.get('verification_confidence', 0)
                                        
                                        if combined_score >= 90:
                                            cve_finding['severity_class'] = 'HIGH_CONFIDENCE'
                                        elif combined_score >= 70:
                                            cve_finding['severity_class'] = 'MEDIUM_CONFIDENCE'
                                        else:
                                            cve_finding['severity_class'] = 'LOW_CONFIDENCE'
                                            
                                        logger.info(f"[CONF] Confidence recalculated using verification data: {combined_score}")
                                    else:
                                        cve_finding['verification_status'] = verification_status
                                        cve_finding['evidence_count'] = evidence_count
                                        
                                    if enhanced_finding.get('evidence'):
                                        cve_finding['evidence_details'] = enhanced_finding['evidence']
                                else:
                                    cve_finding['verification_status'] = 'ERROR'
                                        
                            except Exception as e:
                                logger.error(f"[VERIFY] Verification failed for {cve['id']}: {e}")
                                pass
                        
                        svc_findings_cves.append(cve_finding)
                
                if svc_findings_cves:
                    svc_findings_cves.sort(key=lambda x: x['score'], reverse=True)
                    
                    finding = {
                        'service': service.get('service', prod['product']),
                        'version': prod['version'],
                        'port': service.get('port', 0),
                        'total_cves': len(svc_findings_cves),
                        'critical': len([c for c in svc_findings_cves if c['severity'] == 'CRITICAL']),
                        'high': len([c for c in svc_findings_cves if c['severity_class'] == 'HIGH']),
                        'medium': len([c for c in svc_findings_cves if c['severity_class'] == 'MEDIUM']),
                        'low': len([c for c in svc_findings_cves if c['severity'] == 'LOW']),
                        'cves': svc_findings_cves,
                        'severity': self._calculate_overall_severity(
                            [c for c in svc_findings_cves if c['severity'] == 'CRITICAL'],
                            [c for c in svc_findings_cves if c['severity_class'] == 'HIGH'],
                            [c for c in svc_findings_cves if c['severity_class'] == 'MEDIUM'],
                            [c for c in svc_findings_cves if c['severity'] == 'LOW']
                        ),
                        'relevance': self._determine_relevance(svc_findings_cves),
                        'explanation': f"Found {len(svc_findings_cves)} CVEs via {keyword}"
                    }
                    findings.append(finding)

        logger.info(f"[Done] Vulnerability matching complete: {len(findings)} services with potential issues")
        return findings
    
    def _calculate_overall_severity(self, critical, high, medium, low) -> str:
        """Calculate overall severity for a service"""
        if critical:
            return 'CRITICAL'
        elif high:
            return 'HIGH'
        elif medium:
            return 'MEDIUM'
        elif low:
            return 'LOW'
        return 'NONE'
    
    def format_findings(self, findings: List[Dict]) -> str:
        """
        Format vulnerability findings for display
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            Formatted string report
        """
        if not findings:
            return "\n  No vulnerabilities found in detected services"
        
        report = "\n" + "="*70 + "\n"
        report += "  VULNERABILITY REPORT\n"
        report += "="*70 + "\n"
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'POTENTIAL': 4, 'INFORMATIONAL': 5}
        findings.sort(key=lambda x: severity_order.get(x.get('severity', 'INFORMATIONAL'), 99))
        
        for finding in findings:
            service = finding['service']
            version = finding['version'] or 'unknown'
            port = finding['port']
            total = finding['total_cves']
            severity = finding['severity']
            
            report += f"\n  {service.upper()} {version or 'unknown'} (Port {port})\n"
            report += f"   Overall Severity: {self._severity_emoji(severity)} {severity}\n"
            report += f"   Relevance: {finding.get('relevance', 'informational').upper()}\n"
            report += f"   Analysis: {finding.get('explanation', 'N/A')}\n"
            report += f"   Total CVEs: {total}\n"
            
            if 'enhanced_analysis' in finding:
                analysis = finding['enhanced_analysis']
                report += f"     Analysis:\n"
                report += f"     Confidence Level: {analysis.get('confidence_level', 'UNKNOWN')}\n"
                report += f"     Relevance Score: {analysis.get('relevance_score', 'N/A')}/100\n"
                report += f"     Matched Product: {analysis.get('matched_product', 'N/A')}\n"
                
                evidence = analysis.get('evidence', [])
                report += f"     Evidence: {'; '.join(evidence)}\n"
                report += f"     Scoring Method: {analysis.get('scoring_method', 'Unknown')}\n"
            
            if finding['critical'] > 0:
                report += f"     Critical: {finding['critical']}\n"
            if finding['high'] > 0:
                report += f"   [HIGH] High: {finding['high']}\n"
            if finding['medium'] > 0:
                report += f"   [MEDIUM] Medium: {finding['medium']}\n"
            if finding['low'] > 0:
                report += f"   [LOW] Low: {finding['low']}\n"
            
            report += f"\n     Top {min(5, len(finding['cves']))} CVEs:\n"
            for i, cve in enumerate(finding['cves'][:5], 1):
                cvss = cve.get('cvss_v3') or cve.get('cvss_v2') or 'N/A'
                report += f"\n   {i}. {cve['id']} - {cve['severity']}\n"
                report += f"      CVSS: {cvss}\n"
                report += f"      {cve['description'][:120]}...\n"
                
                if cve.get('verification_status'):
                    verification_status = cve['verification_status']
                    verification_method = cve.get('verification_method', 'unknown')
                    evidence_count = cve.get('evidence_count', 0)
                    
                    if verification_status == 'VERIFIED':
                        report += f"      ✓ VERIFIED - Method: {verification_method}\n"
                        if evidence_count > 0:
                            report += f"      Evidence Count: {evidence_count}\n"
                    else:
                        report += f"      Status: {verification_status}\n"
                        
                report += f"        {cve['url']}\n"
            
            report += "\n" + "-"*70 + "\n"
        
        report += "\n[Disclaimer] CVE presence does not imply exploitability. Results are correlation-based.\n"
        return report
    
    def _severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level"""
        emojis = {
            'CRITICAL': '[CRITICAL]',
            'HIGH': '[HIGH]',
            'MEDIUM': '[MEDIUM]',
            'LOW': '[LOW]',
            'NONE': '[NONE]'
        }
        return emojis.get(severity, '[UNKNOWN]')
    
    def export_json(self, findings: List[Dict], filename: str = 'vulnerabilities.json'):
        """Export findings to JSON file"""
        import json
        
        with open(filename, 'w') as f:
            json.dump(findings, f, indent=2)
        
        logger.info(f" Vulnerability report exported to {filename}")
    
    def export_csv(self, findings: List[Dict], filename: str = 'vulnerabilities.csv'):
        """Export findings to CSV file"""
        import csv
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Service', 'Version', 'Port', 'CVE-ID', 'Severity', 'CVSS', 'Description', 'URL'])
            
            for finding in findings:
                service = finding['service']
                version = finding['version'] or 'unknown'
                port = finding['port']
                
                for cve in finding['cves']:
                    writer.writerow([
                        service,
                        version,
                        port,
                        cve['id'],
                        cve['severity'],
                        cve.get('cvss_v3') or cve.get('cvss_v2') or 'N/A',
                        cve['description'][:200],
                        cve['url']
                    ])
        
        logger.info(f" CSV report exported to {filename}")

    def _parse_semantic_version(self, version: str):
        if not version:
            return None

        # STRIP distro suffix
        import re
        clean = re.match(r'(\d+\.\d+\.\d+)', version)
        return clean.group(1) if clean else None
    
    def _validate_vendor_relevance(self, service: str, cve_description: str) -> tuple[bool, str]:
        """
        Check if CVE is relevant to detected service vendor
        
        Args:
            service: Detected service name (e.g., "nginx", "apache")
            cve_description: CVE description text
            
        Returns:
            Tuple of (is_relevant, reason)
        """
        desc_lower = cve_description.lower()
        service_lower = service.lower()
        
        # Get valid vendors for detected service
        valid_vendors = self.vendor_alias_map.get(service_lower, [service_lower])
        
        # Check for irrelevant vendor indicators
        for indicator in self.irrelevant_indicators:
            if indicator in desc_lower:
                # Verify if service vendor is actually mentioned
                vendor_mentioned = any(vendor in desc_lower for vendor in valid_vendors)
                if not vendor_mentioned:
                    return False, f"Contains irrelevant product '{indicator}'"
        
        return True, "Vendor relevant"
    
    def _check_version_in_cve_description(self, version_tuple: tuple, cve_description: str) -> bool:
        """
        Check if specific version is mentioned in CVE description
        
        Args:
            version_tuple: (major, minor, patch) version tuple
            cve_description: CVE description text
            
        Returns:
            True if version is explicitly mentioned
        """
        major, minor, patch = version_tuple
        desc_lower = cve_description.lower()
        
        # Check for exact version matches
        version_patterns = [
            f"{major}.{minor}.{patch}",
            f"{major}.{minor}",
            f"version {major}.{minor}",
            f"v{major}.{minor}"
        ]
        
        return any(pattern in desc_lower for pattern in version_patterns)
    
        return False

    def _check_version_in_cpe_range(self, version_tuple: tuple, cve: Dict) -> bool:
        """
        Check if version falls within CPE-defined vulnerability ranges (Phase 2B)
        Strict semantic version comparison.
        """
        if not version_tuple or 'cpe_data' not in cve:
            return False
        
        # Helper for semantic comparison
        def compare(v1, v2):
             # Returns 1 if v1 > v2, -1 if v1 < v2, 0 if equal
            len_diff = len(v1) - len(v2)
            if len_diff > 0: v2 += (0,) * len_diff
            else: v1 += (0,) * -len_diff
            
            if v1 > v2: return 1
            elif v1 < v2: return -1
            return 0
            
        # Check each CPE match
        for cpe_match in cve['cpe_data']:
            if not cpe_match.get('vulnerable', True):
                continue
            
            in_range = True
            
            # Start Including (>=)
            if 'versionStartIncluding' in cpe_match:
                start = self._parse_semantic_version(cpe_match['versionStartIncluding'])
                if start and compare(version_tuple, start) < 0:
                    in_range = False
            
            # Start Excluding (>)
            if 'versionStartExcluding' in cpe_match:
                start = self._parse_semantic_version(cpe_match['versionStartExcluding'])
                if start and compare(version_tuple, start) <= 0:
                    in_range = False
                    
            # End Including (<=)
            if 'versionEndIncluding' in cpe_match:
                end = self._parse_semantic_version(cpe_match['versionEndIncluding'])
                if end and compare(version_tuple, end) > 0:
                    in_range = False
            
            # End Excluding (<)
            if 'versionEndExcluding' in cpe_match:
                end = self._parse_semantic_version(cpe_match['versionEndExcluding'])
                if end and compare(version_tuple, end) >= 0:
                    in_range = False
            
            if in_range:
                return True
                
            # If explicit version match required (and no ranges provided)
            cpe_version = cpe_match.get('version')
            if cpe_version and cpe_version != '*' and cpe_version != '-':
                parsed = self._parse_semantic_version(cpe_version)
                if parsed and compare(version_tuple, parsed) == 0:
                    return True
        
        return False
    
    def _determine_relevance(self, cve_findings: List[Dict]) -> str:
        """
        Determine overall relevance based on confidence scores
        
        Args:
            cve_findings: List of CVE findings with confidence/risk scores
            
        Returns:
            Relevance string using academic-safe terminology
        """
        if not cve_findings:
            return "informational"
        
        # Check for high confidence findings
        high_confidence_count = sum(1 for c in cve_findings 
                                  if c.get('enhanced_analysis', {}).get('confidence_level') == 'HIGH_CONFIDENCE')
        
        if high_confidence_count > 0:
            return "high_confidence"
        
        # Check for medium confidence
        medium_confidence_count = sum(1 for c in cve_findings 
                                    if c.get('enhanced_analysis', {}).get('confidence_level') == 'MEDIUM_CONFIDENCE')
        
        if medium_confidence_count > 0:
            return "medium_confidence"
        
        # Check for verified findings
        verified_count = sum(1 for c in cve_findings if c.get('verified', False))
        if verified_count > 0:
            return "low_confidence"
        
        return "informational"
    
    def _score_relevance_v2(self, cve, product):
        """Legacy scoring for backward compatibility"""
        score = 0
        analysis = {}

        cpe_text = str(cve).lower()
        desc_text = cve.get("description", "").lower()

        # 1. Vendor Match (+40)
        p_vendor = product.get("vendor", "").lower()
        if p_vendor and p_vendor in cpe_text:
            score += 40
            analysis["vendor_match"] = True
        else:
            analysis["vendor_match"] = False

        # 2. Product Match (+30)
        p_product = product.get("product", "").lower()
        if p_product and p_product in cpe_text:
            score += 30
            analysis["product_match"] = True
        else:
            analysis["product_match"] = False

        # 3. Version Scoring (+20 Exact, -10 if unknown)
        p_version = product.get("version", "")
        if p_version and p_version != "unknown":
            if p_version in cpe_text or p_version in desc_text:
                score += 20
                analysis["exact_version"] = True
            else:
                analysis["exact_version"] = False
        else:
            # 5A: Downgrade relevance if version unknown
            score = max(0, score - 10)
            analysis["exact_version"] = False
            analysis["version_status"] = "unknown"

        # 4. Keyword Match (+5)
        if p_product and p_product in desc_text:
            score += 5
            analysis["keyword_match"] = True

        # CAP vendor mismatch (5A Safeguard)
        if not analysis["vendor_match"]:
            if score > 39:
                logger.warning(f"Downgrading score {score} -> 39 due to vendor mismatch ({p_vendor})")
            score = min(score, 39)
            analysis["confidence_level"] = "INFORMATIONAL"
        else:
            if score >= 80:
                analysis["confidence_level"] = "HIGH"
            elif score >= 60:
                analysis["confidence_level"] = "MEDIUM"
            else:
                analysis["confidence_level"] = "INFORMATIONAL"

        analysis["relevance_score"] = score
        return score, analysis

    def _score_relevance(self, service: str, version: Optional[str], cves: List[Dict]) -> Dict:
        """
        Heuristic to determine relevance of CVE matches.
        
        Logic:
        - Confirmed (100): Product match AND Version overlap.
        - Likely (70): Product match but Version unknown.
        - Possible (40): Keyword match but Product mismatch (e.g., Kaseya snippet in Nginx header).
        - Informational (10): Generic keyword match with high discrepancy.
        """
        score = 50  # Default
        relevance = "possible"
        explanation = "Matched based on service keywords."

        # Case 1: Version check (if version available)
        if version and version != "unknown":
            # For this non-intrusive version, we do a simplistic version check
            # Real implementation would use packaging.version but we stay light
            version_match = False
            for cve in cves:
                desc = cve['description'].lower()
                if version.lower() in desc:
                    version_match = True
                    break
            
            if version_match:
                score = 90
                relevance = "confirmed"
                explanation = f"Detected version {version} mentioned in CVE descriptions."
            else:
                # Potential mismatch - downgrade to informational as per heuristic
                score = 30
                relevance = "informational"
                explanation = f"Detected version {version} does not explicitly appear in top CVE descriptions."
        
        # Case 2: Broad keyword mismatch detection (e.g. Kaseya on Nginx)
        # If any of the top CVEs mentioned a completely different major product
        other_products = ['kaseya', 'vsa', 'wordpress', 'joomla', 'drupal']
        for prod in other_products:
            if prod in str(cves[:5]).lower() and prod not in service.lower():
                score = 10
                relevance = "informational"
                explanation = f"Match contains references to '{prod}' which differs from detected service '{service}'."
                break

        return {
            'score': score,
            'relevance': relevance,
            'explanation': explanation
        }


# Example usage
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s:%(name)s:%(message)s'
    )
    
    # Example detected services
    services = [
        {'name': 'nginx', 'version': '1.24.0', 'port': 80},
        {'name': 'openssh', 'version': '9.6', 'port': 22},
        {'name': 'vsftpd', 'version': None, 'port': 21}
    ]
    
    # Initialize matcher
    matcher = CVEMatcher()
    
    # Match vulnerabilities
    findings = matcher.match_vulnerabilities(services)
    
    # Display report
    print(matcher.format_findings(findings))
    
    # Export results
    if findings:
        matcher.export_json(findings)
        matcher.export_csv(findings)

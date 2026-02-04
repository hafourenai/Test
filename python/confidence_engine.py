"""
Confidence Engine - scoring for vulnerability findings
"""

from enum import Enum

class ConfidenceLevel(Enum):
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"
    MEDIUM_CONFIDENCE = "MEDIUM_CONFIDENCE"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    POTENTIAL = "POTENTIAL"
    INFORMATIONAL = "INFORMATIONAL"

class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    POTENTIAL = "POTENTIAL"
    INFO = "INFO"

class ConfidenceResult:
    def __init__(self, score, level, explanation="", signals=None, evidence=None):
        self.score = score
        self.level = level
        self.explanation = explanation
        self.signals = signals or []
        self.evidence = evidence or []

class RiskResult:
    def __init__(self, score, level, explanation=""):
        self.score = score
        self.level = level
        self.explanation = explanation

class ConfidenceEngine:
    """  confidence scoring engine"""
    
    def calculate_cve_confidence(self, product_info, cve_data):
        """Calculate confidence in a CVE match"""
        # Basic scoring logic
        score = 0.5
        
        # 1. Product & Version matching
        if product_info.get('version') and product_info['version'] != 'unknown':
            if product_info['version'] in str(cve_data):
                score = 0.9
                level = ConfidenceLevel.HIGH_CONFIDENCE
            else:
                score = 0.6
                level = ConfidenceLevel.MEDIUM_CONFIDENCE
        else:
            # Even without version, it's a potential match if product matches
            score = 0.4
            level = ConfidenceLevel.POTENTIAL
            
        return ConfidenceResult(
            score=score,
            level=level,
            explanation=f"Based on version matching for {product_info.get('product')}",
            signals=["version_match"],
            evidence=[f"Product: {product_info.get('product')}, Version: {product_info.get('version')}"]
        )
        
    def calculate_risk_assessment(self, cve_data, confidence_score, context=None):
        """Calculate risk level based on CVE and confidence"""
        # Simplistic risk scoring
        cvss = cve_data.get('cvss_v3', 0)
        if not cvss:
            cvss = 5.0
            
        final_score = float(cvss) * confidence_score / 10.0
        
        if final_score >= 0.8:
            level = RiskLevel.CRITICAL
        elif final_score >= 0.6:
            level = RiskLevel.HIGH
        elif final_score >= 0.4:
            level = RiskLevel.MEDIUM
        elif final_score >= 0.2:
            level = RiskLevel.POTENTIAL
        else:
            level = RiskLevel.LOW
            
        return RiskResult(
            score=final_score,
            level=level,
            explanation=f"CVSS: {cvss}, Confidence: {confidence_score:.2f}"
        )

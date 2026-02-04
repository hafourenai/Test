"""
Payload Manager - Advanced Payload Management with Encoding & Obfuscation
Handles loading, encoding, mutation, and selection of attack payloads
"""

import base64
import urllib.parse
import random
import logging
from typing import List, Dict, Optional
from pathlib import Path

try:
    from .config import PAYLOAD_ENCODING, PAYLOAD_MUTATIONS
except ImportError:
    from config import PAYLOAD_ENCODING, PAYLOAD_MUTATIONS

logger = logging.getLogger(__name__)


class PayloadManager:
    """Advanced payload management with encoding and obfuscation"""
    
    def __init__(self):
        """Initialize payload manager"""
        self.payloads = {
            'xss': [],
            'sqli': [],
            'lfi': [],
            'rce': [],
            'xxe': [],
            'ssti': [],
            'idor': [],
            'open_redirect': []
        }
        self.payload_stats = {}  # Track effectiveness
        
        logger.info("[Payloads] Payload Manager initialized")
    
    def load_payloads(self, payload_type: str, file_path: str) -> int:
        """
        Load payloads from file
        
        Args:
            payload_type: Type of payload (xss, sqli, lfi, etc.)
            file_path: Path to payload file
            
        Returns:
            Number of payloads loaded
        """
        if payload_type not in self.payloads:
            logger.error(f"[Payloads] Unknown payload type: {payload_type}")
            return 0
        
        path = Path(file_path)
        if not path.exists():
            logger.error(f"[Payloads] File not found: {file_path}")
            return 0
        
        count = 0
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if line and not line.startswith('#'):
                        self.payloads[payload_type].append(line)
                        count += 1
            
            logger.info(f"[Payloads] Loaded {count} {payload_type} payloads from {file_path}")
            return count
            
        except Exception as e:
            logger.error(f"[Payloads] Error loading {file_path}: {e}")
            return 0
    
    def get_payloads(self, payload_type: str, encode: bool = True, 
                     max_count: Optional[int] = None) -> List[str]:
        """
        Get payloads with optional encoding
        
        Args:
            payload_type: Type of payload
            encode: Whether to generate encoded variants
            max_count: Maximum number of payloads to return
            
        Returns:
            List of payloads (original + encoded variants)
        """
        base_payloads = self.payloads.get(payload_type, [])
        
        if not base_payloads:
            logger.warning(f"[Payloads] No payloads loaded for type: {payload_type}")
            return []
        
        if not encode:
            return base_payloads[:max_count] if max_count else base_payloads
        
        # Generate encoded variants
        all_payloads = []
        for payload in base_payloads:
            # Original payload
            all_payloads.append(payload)
            
            # URL encoded
            if PAYLOAD_ENCODING['url_encode']:
                all_payloads.append(self._url_encode(payload))
            
            # Double URL encoded
            if PAYLOAD_ENCODING['double_encode']:
                all_payloads.append(self._double_url_encode(payload))
            
            # Unicode encoded (for XSS)
            if PAYLOAD_ENCODING['unicode_encode'] and payload_type == 'xss':
                all_payloads.append(self._unicode_encode(payload))
            
            # Hex encoded (for SQL)
            if PAYLOAD_ENCODING['hex_encode'] and payload_type == 'sqli':
                all_payloads.append(self._hex_encode(payload))
            
            # Mixed case
            if PAYLOAD_ENCODING['mixed_case']:
                all_payloads.append(self._mixed_case(payload))
            
            # Comment injection (for SQL)
            if PAYLOAD_ENCODING['comment_injection'] and payload_type == 'sqli':
                all_payloads.extend(self._comment_injection(payload))
        
        # Apply mutations if enabled
        if PAYLOAD_MUTATIONS['encoding_variation']:
            mutated = []
            for payload in all_payloads[:50]:  # Limit mutations
                mutated.extend(self.mutate_payload(payload, 'space'))
            all_payloads.extend(mutated)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_payloads = []
        for p in all_payloads:
            if p not in seen:
                seen.add(p)
                unique_payloads.append(p)
        
        result = unique_payloads[:max_count] if max_count else unique_payloads
        logger.debug(f"[Payloads] Generated {len(result)} {payload_type} payloads "
                    f"(original: {len(base_payloads)})")
        
        return result
    
    def _url_encode(self, payload: str) -> str:
        """URL encode payload"""
        return urllib.parse.quote(payload, safe='')
    
    def _double_url_encode(self, payload: str) -> str:
        """Double URL encode payload"""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
    
    def _unicode_encode(self, payload: str) -> str:
        """Unicode encode payload (for XSS bypass)"""
        # Only encode special characters
        encoded = ''
        for char in payload:
            if char in '<>"\'/':
                encoded += f'\\u{ord(char):04x}'
            else:
                encoded += char
        return encoded
    
    def _hex_encode(self, payload: str) -> str:
        """Hex encode payload (for SQL)"""
        try:
            return '0x' + payload.encode().hex()
        except:
            return payload
    
    def _base64_encode(self, payload: str) -> str:
        """Base64 encode payload"""
        try:
            return base64.b64encode(payload.encode()).decode()
        except:
            return payload
    
    def _mixed_case(self, payload: str) -> str:
        """Generate mixed case variation"""
        result = ''
        for i, char in enumerate(payload):
            if i % 2 == 0:
                result += char.upper()
            else:
                result += char.lower()
        return result
    
    def _comment_injection(self, payload: str) -> List[str]:
        """Generate SQL comment injection variants"""
        variants = []
        
        # MySQL style
        variants.append(payload.replace(' ', '/**/'))
        variants.append(payload + '--')
        variants.append(payload + '#')
        
        # Inline comments
        if 'SELECT' in payload.upper():
            variants.append(payload.replace('SELECT', 'SE/**/LECT'))
        if 'UNION' in payload.upper():
            variants.append(payload.replace('UNION', 'UN/**/ION'))
        
        return variants
    
    def mutate_payload(self, payload: str, mutation_type: str = 'space') -> List[str]:
        """
        Generate payload mutations
        
        Args:
            payload: Original payload
            mutation_type: Type of mutation (case, space, comment)
            
        Returns:
            List of mutated payloads
        """
        mutations = [payload]
        
        if mutation_type == 'case' and PAYLOAD_MUTATIONS['case_variation']:
            mutations.append(payload.upper())
            mutations.append(payload.lower())
            mutations.append(self._mixed_case(payload))
        
        elif mutation_type == 'space' and PAYLOAD_MUTATIONS['space_variation']:
            # Space variations
            mutations.append(payload.replace(' ', '+'))
            mutations.append(payload.replace(' ', '%20'))
            mutations.append(payload.replace(' ', '/**/'))
            mutations.append(payload.replace(' ', '\t'))
            mutations.append(payload.replace(' ', '%09'))  # Tab
            mutations.append(payload.replace(' ', '%0a'))  # Newline
        
        elif mutation_type == 'comment' and PAYLOAD_MUTATIONS['comment_variation']:
            mutations.extend(self._comment_injection(payload))
        
        return mutations
    
    def add_custom_payload(self, payload_type: str, payload: str):
        """Add a custom payload"""
        if payload_type in self.payloads:
            self.payloads[payload_type].append(payload)
            logger.info(f"[Payloads] Added custom {payload_type} payload")
        else:
            logger.error(f"[Payloads] Unknown payload type: {payload_type}")
    
    def get_stats(self) -> Dict:
        """Get payload statistics"""
        stats = {}
        for ptype, payloads in self.payloads.items():
            stats[ptype] = {
                'count': len(payloads),
                'effectiveness': self.payload_stats.get(ptype, {})
            }
        return stats
    
    def track_success(self, payload_type: str, payload: str, success: bool):
        """Track payload effectiveness"""
        if payload_type not in self.payload_stats:
            self.payload_stats[payload_type] = {
                'total': 0,
                'successful': 0,
                'payloads': {}
            }
        
        stats = self.payload_stats[payload_type]
        stats['total'] += 1
        if success:
            stats['successful'] += 1
        
        # Track individual payload
        if payload not in stats['payloads']:
            stats['payloads'][payload] = {'total': 0, 'successful': 0}
        
        stats['payloads'][payload]['total'] += 1
        if success:
            stats['payloads'][payload]['successful'] += 1
    
    def get_best_payloads(self, payload_type: str, top_n: int = 10) -> List[str]:
        """Get most effective payloads based on success rate"""
        if payload_type not in self.payload_stats:
            return self.payloads.get(payload_type, [])[:top_n]
        
        stats = self.payload_stats[payload_type]['payloads']
        
        # Sort by success rate
        sorted_payloads = sorted(
            stats.items(),
            key=lambda x: x[1]['successful'] / max(x[1]['total'], 1),
            reverse=True
        )
        
        return [p[0] for p in sorted_payloads[:top_n]]


# Example usage
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s - %(message)s'
    )
    
    print("="*60)
    print("Payload Manager Test")
    print("="*60)
    
    manager = PayloadManager()
    
    # Add some test payloads
    manager.add_custom_payload('xss', '<script>alert(1)</script>')
    manager.add_custom_payload('xss', '<img src=x onerror=alert(1)>')
    manager.add_custom_payload('sqli', "' OR '1'='1")
    manager.add_custom_payload('sqli', "' UNION SELECT NULL--")
    
    # Test XSS payloads with encoding
    print("\n[XSS Payloads]")
    xss_payloads = manager.get_payloads('xss', encode=True, max_count=10)
    for i, payload in enumerate(xss_payloads[:5], 1):
        print(f"  {i}. {payload[:80]}")
    
    # Test SQLi payloads with encoding
    print("\n[SQLi Payloads]")
    sqli_payloads = manager.get_payloads('sqli', encode=True, max_count=10)
    for i, payload in enumerate(sqli_payloads[:5], 1):
        print(f"  {i}. {payload[:80]}")
    
    # Test mutations
    print("\n[Payload Mutations]")
    test_payload = "SELECT * FROM users"
    mutations = manager.mutate_payload(test_payload, 'space')
    for i, mutation in enumerate(mutations[:5], 1):
        print(f"  {i}. {mutation}")
    
    # Show stats
    print("\n[Statistics]")
    stats = manager.get_stats()
    for ptype, stat in stats.items():
        if stat['count'] > 0:
            print(f"  {ptype}: {stat['count']} payloads")

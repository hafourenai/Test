# python/plugins/__init__.py
"""
Plugins package initialization
"""

from pathlib import Path

# Auto-discover plugins
__all__ = [p.stem for p in Path(__file__).parent.glob("*.py") 
           if not p.name.startswith("_")]

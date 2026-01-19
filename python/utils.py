"""
Infrastructure Utilities
Provides common helpers for path resolution, logging, and platform checks.
"""

import sys
import logging
from pathlib import Path

def get_project_root() -> Path:
    """
    Dynamically resolve the project root directory.
    Assumes this file is in <root>/python/utils.py
    """
    # Go up one level from 'python' dir to reach root
    return Path(__file__).resolve().parent.parent

def is_windows() -> bool:
    """Check if the current platform is Windows."""
    return sys.platform == "win32"

def setup_logger(name: str = "LOV_U_N") -> logging.Logger:
    """Configure and return a standard logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger

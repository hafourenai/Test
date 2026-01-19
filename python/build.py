"""
Build Layer
Handles the compilation of external components (Go scanner).
"""

import subprocess
import shutil
from pathlib import Path
from .utils import get_project_root, is_windows, setup_logger

logger = setup_logger(__name__)

def build_go_scanner() -> str:
    """
    Builds the Go scanner binary from source.
    
    Returns:
        str: Absolute path to the compiled executable.
        
    Raises:
        RuntimeError: If the build process fails.
    """
    root_dir = get_project_root()
    go_dir = root_dir / "go"
    
    if not go_dir.exists():
        raise FileNotFoundError(f"Go directory not found at: {go_dir}")
        
    binary_name = "scanner.exe" if is_windows() else "scanner"
    binary_path = go_dir / binary_name
    
    logger.info(f"Building Go scanner in: {go_dir}")
    
    # Check if 'go' is installed
    if not shutil.which("go"):
        raise RuntimeError("Go compiler not found in PATH")

    cmd = ["go", "build", "-o", binary_name, "main.go"]
    
    try:
        # Run build command inside the 'go' directory
        result = subprocess.run(
            cmd,
            cwd=str(go_dir),
            capture_output=True,
            text=True,
            check=False 
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"Go build failed:\n{result.stderr}")
            
        if not binary_path.exists():
            raise RuntimeError(f"Build succeeded but binary not found at: {binary_path}")
            
        logger.info(f"Go scanner built successfully: {binary_path}")
        return str(binary_path.resolve())
        
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Build command execution failed: {str(e)}")
    except Exception as e:
        raise RuntimeError(f"Unexpected error during build: {str(e)}")

import os
import shutil
from pathlib import Path

def cleanup():
    """
    Cleans up Python cache files, temporary reports, and build artifacts.
    """
    project_root = Path(__file__).parent
    
    # Patterns to remove
    directories_to_remove = [
        "__pycache__",
        ".pytest_cache",
        "build",
        "dist",
        "*.egg-info"
    ]
    
    files_to_remove = [
        "*.pyc",
        "*.pyo",
        "*.pyd",
        ".DS_Store"
    ]
    
    print(f"[Clean] Starting cleanup in: {project_root}")
    
    # Remove directories
    count_dir = 0
    for path in project_root.rglob("*"):
        if path.is_dir() and any(path.match(p) for p in directories_to_remove):
            try:
                shutil.rmtree(path)
                print(f"  [Removed Dir] {path.relative_to(project_root)}")
                count_dir += 1
            except Exception as e:
                print(f"  [Error] Failed to remove {path}: {e}")
                
    # Remove files
    count_file = 0
    for path in project_root.rglob("*"):
        if path.is_file() and any(path.match(p) for p in files_to_remove):
            try:
                path.unlink()
                print(f"  [Removed File] {path.relative_to(project_root)}")
                count_file += 1
            except Exception as e:
                print(f"  [Error] Failed to remove {path}: {e}")
                
    print(f"\n[Success] Cleanup complete!")
    print(f"   Directories removed: {count_dir}")
    print(f"   Files removed: {count_file}")

if __name__ == "__main__":
    cleanup()

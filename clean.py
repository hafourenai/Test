import os
import shutil
from pathlib import Path

def clean_project():
    project_root = Path(__file__).parent.resolve()
    print(f"[*] Cleaning project cache in: {project_root}")
    
    deleted_count = 0
    
    # 1. Remove __pycache__ folders
    for pycache in project_root.rglob("__pycache__"):
        if pycache.is_dir():
            try:
                shutil.rmtree(pycache)
                print(f"  [-] Removed: {pycache.relative_to(project_root)}")
                deleted_count += 1
            except Exception as e:
                print(f"  [!] Error removing {pycache}: {e}")

    # 2. Remove .pyc files
    for pyc in project_root.rglob("*.pyc"):
        try:
            pyc.unlink()
            print(f"  [-] Deleted: {pyc.relative_to(project_root)}")
            deleted_count += 1
        except Exception as e:
            print(f"  [!] Error deleting {pyc}: {e}")

    print(f"\n[*] Cleanup complete! {deleted_count} items removed.")

if __name__ == "__main__":
    clean_project()

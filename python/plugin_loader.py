# python/plugin_loader.py
"""
Plugin Loader - Dynamic plugin loading system
"""

import importlib
import inspect
from pathlib import Path
from typing import List, Any
import sys


class PluginLoader:
    """Loads and manages security check plugins"""
    
    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = Path(__file__).parent / plugin_dir
        self.plugins = []
        
    def load_all_plugins(self) -> List[Any]:
        """Load all available plugins"""
        if not self.plugin_dir.exists():
            print(f"[Warning] Plugin directory not found: {self.plugin_dir}")
            return []
        
        # Add plugin directory to path
        sys.path.insert(0, str(self.plugin_dir))
        
        loaded = []
        for plugin_file in self.plugin_dir.glob("*.py"):
            if plugin_file.name.startswith("_") or plugin_file.name == "base_plugin.py":
                continue
            
            try:
                module_name = plugin_file.stem
                module = importlib.import_module(module_name)
                
                # Find plugin class
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if hasattr(obj, 'analyze') and name != 'BasePlugin':
                        plugin_instance = obj()
                        loaded.append(plugin_instance)
                        print(f"[Success] Loaded plugin: {plugin_instance.name}")
            
            except Exception as e:
                print(f"[Warning] Failed to load plugin {plugin_file.name}: {e}")
        
        return loaded

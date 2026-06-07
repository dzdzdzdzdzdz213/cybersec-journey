import importlib.util, inspect, os, sys
from pathlib import Path
from typing import Dict, List, Callable, Any, Optional
from abc import ABC, abstractmethod

class DetectorPlugin(ABC):
    name: str = "base"
    version: str = "1.0.0"
    description: str = ""
    author: str = ""

    @abstractmethod
    def analyze(self, pkt: Dict[str, Any], context: "DetectionContext") -> List[Dict[str, Any]]:
        pass

    def on_load(self, config: Dict[str, Any]) -> None:
        pass

    def on_unload(self) -> None:
        pass

class DetectionContext:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.connection_tracker = {}
        self.packet_counts = {}
        self.byte_counts = {}

    def get_connection_key(self, pkt: Dict) -> str:
        src = pkt.get("src", "")
        dst = pkt.get("dst", "")
        sport = pkt.get("sport", 0)
        dport = pkt.get("dport", 0)
        return f"{src}:{sport}->{dst}:{dport}"

class PluginManager:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.plugins: Dict[str, DetectorPlugin] = {}
        self.plugin_modules: Dict[str, Any] = {}
        self._load_plugins()

    def _load_plugins(self) -> None:
        if not self.config.get("plugins", {}).get("enabled", True):
            return

        dirs = self.config.get("plugins", {}).get("directories", [])
        for d in dirs:
            path = Path(d)
            if path.exists():
                self._load_from_directory(path)

    def _load_from_directory(self, path: Path) -> None:
        for file in path.glob("*.py"):
            if file.name.startswith("_"):
                continue
            try:
                self._load_plugin_file(file)
            except Exception as e:
                print(f"[!] Failed to load plugin {file}: {e}")

    def _load_plugin_file(self, file: Path) -> None:
        module_name = f"shieldwall_plugin_{file.stem}"
        spec = importlib.util.spec_from_file_location(module_name, file)
        if not spec or not spec.loader:
            return
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

        for name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, DetectorPlugin) and obj is not DetectorPlugin:
                plugin = obj()
                plugin.on_load(self.config)
                self.plugins[plugin.name] = plugin
                self.plugin_modules[plugin.name] = module
                print(f"[+] Loaded plugin: {plugin.name} v{plugin.version}")

    def analyze(self, pkt: Dict, context: DetectionContext) -> List[Dict]:
        alerts = []
        for plugin in self.plugins.values():
            try:
                result = plugin.analyze(pkt, context)
                if result:
                    alerts.extend(result)
            except Exception as e:
                print(f"[!] Plugin {plugin.name} error: {e}")
        return alerts

    def reload(self) -> None:
        for name, plugin in self.plugins.items():
            plugin.on_unload()
        self.plugins.clear()
        self.plugin_modules.clear()
        self._load_plugins()

    def get_plugin(self, name: str) -> Optional[DetectorPlugin]:
        return self.plugins.get(name)

    def list_plugins(self) -> List[Dict]:
        return [
            {"name": p.name, "version": p.version, "description": p.description, "author": p.author}
            for p in self.plugins.values()
        ]

import yaml, os
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"
LOCAL_CONFIG_PATH = Path(__file__).parent / "config.local.yaml"

_config: Optional[Dict[str, Any]] = None

def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    global _config
    if _config is not None:
        return _config

    # Load defaults
    with open(DEFAULT_CONFIG_PATH) as f:
        config = yaml.safe_load(f) or {}

    # Override with local config if exists
    local_path = Path(config_path) if config_path else LOCAL_CONFIG_PATH
    if local_path.exists():
        with open(local_path) as f:
            local = yaml.safe_load(f) or {}
        config = deep_merge(config, local)

    # Environment variable substitution
    config = substitute_env(config)

    _config = config
    return config

def deep_merge(base: Dict, override: Dict) -> Dict:
    result = base.copy()
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = deep_merge(result[k], v)
        else:
            result[k] = v
    return result

def substitute_env(obj: Any) -> Any:
    if isinstance(obj, str):
        import re
        def repl(match):
            var = match.group(1)
            return os.environ.get(var, match.group(0))
        return re.sub(r'\$\{([^}]+)\}', repl, obj)
    elif isinstance(obj, dict):
        return {k: substitute_env(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [substitute_env(v) for v in obj]
    return obj

def get_config() -> Dict[str, Any]:
    if _config is None:
        return load_config()
    return _config

def reload_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    global _config
    _config = None
    return load_config(config_path)

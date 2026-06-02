import importlib.util
from pathlib import Path


def _load_collector(slice_dir, provider):
    path = Path(slice_dir) / "collectors" / f"{provider}.py"
    if not path.exists():
        raise FileNotFoundError(f"no collector for provider '{provider}' in {slice_dir}")
    spec = importlib.util.spec_from_file_location(f"collector_{provider}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def collect(slice_dir, provider, config=None):
    module = _load_collector(slice_dir, provider)
    return module.collect(config or {})

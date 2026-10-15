"""Automated USB Forensics & Artifact Parser - Backend Package."""

_cached_app = None


def __getattr__(name: str):
    """Lazy-load top-level FastAPI app instance on demand to prevent circular imports."""
    global _cached_app
    if name == "app":
        if _cached_app is None:
            import importlib.util
            from pathlib import Path

            _app_file = Path(__file__).resolve().parent.parent / "app.py"
            _spec = importlib.util.spec_from_file_location("root_app_module", str(_app_file))
            _mod = importlib.util.module_from_spec(_spec)
            _spec.loader.exec_module(_mod)
            _cached_app = _mod.app
        return _cached_app
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

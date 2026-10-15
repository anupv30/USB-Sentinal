"""Main module entrypoint re-exporting from root app.py."""

def __getattr__(name: str):
    if name == "app":
        from app import app as root_app
        return root_app
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

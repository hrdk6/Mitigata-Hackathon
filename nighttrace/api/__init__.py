"""FastAPI service exposing the blackboard + the live dashboard."""
from nighttrace.api.server import create_app

__all__ = ["create_app"]

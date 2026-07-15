"""HexaCore HTTP + WebSocket API (Brain/01 §3.2). Exposes the platform so a browser (the future
React console) or any client can create engagements, run them, and watch the live event feed.

ASGI entrypoint: ``hexacore.app.main:app`` (run with ``uvicorn``).
"""
from .main import create_app

__all__ = ["create_app"]

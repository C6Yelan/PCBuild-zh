"""Public chat service barrel for round-1 callers.

Keep ``backend.services.chat.generate_chat_reply`` stable while service internals
are reorganized behind the package boundary.
"""

# backend/services/chat/__init__.py
from .service import generate_chat_reply

__all__ = ["generate_chat_reply"]

"""
ASCII-safe structured logging, with UTF-8 stdout reconfigure for Windows.
"""
from __future__ import annotations

import logging
import sys

_CONFIGURED = False


def _configure_stdout_utf8() -> None:
    """Reconfigure Windows console streams to UTF-8 so [✓] prints safely."""
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def _configure() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    _configure_stdout_utf8()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    root = logging.getLogger("recon")
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)
    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    _configure()
    return logging.getLogger(f"recon.{name}")


# Expose UTF-8 setup so app.py can call it before Flask starts
reconfigure_stdout_utf8 = _configure_stdout_utf8
"""
logger.py — Juwan CTI v3.0 Logging
"""
import logging
import sys
from pathlib import Path
from config import settings


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, settings.LOG_LEVEL, logging.DEBUG))

    fmt = logging.Formatter(settings.LOG_FORMAT)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # File handler
    try:
        settings.ensure_log_dir()
        fh = logging.FileHandler(settings.LOG_FILE, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except Exception:
        pass  # File logging optional — never crash the app

    return logger

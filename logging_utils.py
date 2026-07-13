from __future__ import annotations

import logging
import os
import sys


LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"


def configure_logging(level: str | None = None) -> None:
    resolved_level = (level or os.getenv("CTEM_LOG_LEVEL", "INFO")).upper()
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, resolved_level, logging.INFO))
    if not root_logger.handlers:
        logging.basicConfig(
            level=getattr(logging, resolved_level, logging.INFO),
            format=LOG_FORMAT,
            stream=sys.stdout,
        )
    logging.captureWarnings(True)


def get_logger(name: str | None = None) -> logging.Logger:
    return logging.getLogger(name or "ctem")

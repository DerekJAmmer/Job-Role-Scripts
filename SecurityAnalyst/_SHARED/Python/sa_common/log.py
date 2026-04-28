"""Minimal structured logging helper.

Usage:
    from sa_common.log import get_logger
    log = get_logger(__name__)
    log.info("starting", extra={"host": "HOST1"})
"""

from __future__ import annotations

import logging
import sys


def get_logger(name: str = "sa", level: int = logging.INFO) -> logging.Logger:
    """Return a configured logger that writes human-readable lines to stderr.

    Safe to call repeatedly for the same name; handlers are only added once.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(level)
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-5s %(name)s :: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    logger.addHandler(handler)
    logger.propagate = False
    return logger

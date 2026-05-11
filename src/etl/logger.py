"""
ETL logging — writes to both console and a timestamped log file.

Usage:
    from src.etl.logger import get_logger
    logger = get_logger("extract")
    logger.info("Starting extraction")
"""
import logging
import sys
from datetime import datetime
from pathlib import Path


_configured = False


def _configure_logging(log_dir: Path):
    """One-time logger configuration."""
    global _configured
    if _configured:
        return

    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"etl_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-7s | %(name)-12s | %(message)s",
        datefmt="%H:%M:%S",
    )

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(formatter)

    # File handler — captures DEBUG and above
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)

    root = logging.getLogger("etl")
    root.setLevel(logging.DEBUG)
    root.addHandler(console)
    root.addHandler(fh)

    # Don't propagate to root logger to avoid double output
    root.propagate = False

    _configured = True
    root.info(f"Logging to: {log_file}")


def get_logger(name: str, log_dir: Path = None) -> logging.Logger:
    """Return a named logger under the 'etl' namespace."""
    if log_dir is None:
        log_dir = Path(__file__).resolve().parents[2] / "logs"
    _configure_logging(log_dir)
    return logging.getLogger(f"etl.{name}")
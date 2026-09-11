"""Run queued and scheduled GitHub alert imports in a separate process."""
from __future__ import annotations

import argparse
import logging
from pathlib import Path
import signal
import time

from ..limits import positive_int_setting
from .service import process_one

HEARTBEAT = Path("/tmp/secops-github-sync-heartbeat")
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--health", action="store_true")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if args.health:
        max_age = max(180, positive_int_setting("GITHUB_SYNC_POLL_SECONDS", 5) * 3)
        raise SystemExit(0 if HEARTBEAT.exists() and time.time() - HEARTBEAT.stat().st_mtime < max_age else 1)
    from ..deployment import validate_backend_settings
    validate_backend_settings()
    logging.basicConfig(level=logging.INFO)
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopping:
        try:
            processed = process_one()
            HEARTBEAT.touch()
        except Exception:
            logger.error("GitHub worker database operation failed")
            processed = False
        if args.once:
            break
        if not processed:
            for _ in range(positive_int_setting("GITHUB_SYNC_POLL_SECONDS", 5)):
                if stopping:
                    break
                time.sleep(1)


if __name__ == "__main__":
    main()

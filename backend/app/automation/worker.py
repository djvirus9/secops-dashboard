"""Run with python -m app.automation.worker; evaluates alerts and Jira progress."""
from __future__ import annotations

import argparse
import logging
import signal
import time
from pathlib import Path

from ..limits import positive_int_setting
from .service import process_one as evaluate_one

HEARTBEAT = Path("/tmp/secops-automation-heartbeat")
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--health", action="store_true")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if args.health:
        age = max(180, positive_int_setting("AUTOMATION_POLL_SECONDS", 5) * 3)
        raise SystemExit(0 if HEARTBEAT.exists() and time.time() - HEARTBEAT.stat().st_mtime < age else 1)
    from ..deployment import validate_worker_settings
    from ..jira_sync.service import process_one as sync_jira_one
    validate_worker_settings("automation")
    logging.basicConfig(level=logging.INFO)
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopping:
        processed = False
        healthy = True
        # Failure in one subsystem must not starve the other.
        for operation in (evaluate_one, sync_jira_one):
            try:
                processed = operation() or processed
            except Exception:
                healthy = False
                logger.error("Automation worker operation failed")
        if healthy:
            HEARTBEAT.touch()
        if args.once:
            break
        if not processed or not healthy:
            for _ in range(positive_int_setting("AUTOMATION_POLL_SECONDS", 5)):
                if stopping:
                    break
                time.sleep(1)


if __name__ == "__main__":
    main()

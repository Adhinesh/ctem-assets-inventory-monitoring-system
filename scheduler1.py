"""
scheduler1.py
-------------
Continuous CTEM monitoring runner.

Runs the fixed snapshot-based monitor in a simple 24/7 loop.

Examples:
    python3 scheduler1.py
    python3 scheduler1.py --interval-seconds 30
"""

from __future__ import annotations

import argparse
import time
from datetime import datetime

from monitor import build_live_monitor
from logging_utils import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)


def run_monitoring_once() -> dict:
    """Execute one live monitoring cycle and return a short summary."""
    started_at = datetime.now()
    logger.info("CTEM Continuous Monitoring started at %s", started_at.isoformat(timespec="seconds"))

    monitor = build_live_monitor(push_to_supabase=True)
    report_text = monitor.run()

    logger.info("\n%s", report_text)
    logger.info("Monitoring completed successfully")

    return {
        "run_id": monitor.run_id,
        "started_at": started_at.isoformat(),
        "previous_asset_count": len(monitor.previous),
        "current_asset_count": len(monitor.current),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run CTEM monitoring continuously.")
    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=60,
        help="Seconds to wait between monitoring runs. Default: 60.",
    )
    args = parser.parse_args()

    if args.interval_seconds < 5:
        raise SystemExit("interval must be at least 5 seconds")

    logger.info("Continuous monitor started")
    logger.info("Polling interval: %s second(s)", args.interval_seconds)
    logger.info("Press Ctrl+C to stop.")

    while True:
        cycle_started = time.time()
        try:
            summary = run_monitoring_once()
            logger.info(
                "Run summary: run_id=%s previous=%s current=%s",
                summary["run_id"],
                summary["previous_asset_count"],
                summary["current_asset_count"],
            )
        except Exception as exc:
            logger.exception("Monitoring failed")

        elapsed = time.time() - cycle_started
        sleep_for = max(args.interval_seconds - elapsed, 0)
        logger.info("Next run in %s second(s)", round(sleep_for, 1))

        try:
            time.sleep(sleep_for)
        except KeyboardInterrupt:
            logger.info("Continuous monitor stopped by user")
            break


if __name__ == "__main__":
    main()

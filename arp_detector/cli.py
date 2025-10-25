"""Command line interface for running the ARP monitor headlessly."""
from __future__ import annotations

import argparse
import signal
import sys
import time
from contextlib import contextmanager

from .monitor import ARPMonitor, MonitorConfig
from .notifications import NotificationManager, NotificationPolicy, create_callback_channel
from .reporting import ReportGenerator
from .simulation import TrafficSimulator


@contextmanager
def _running_monitor(monitor: ARPMonitor) -> None:
    try:
        monitor.start()
        yield
    finally:
        monitor.stop()


def run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ARP spoofing monitor (headless mode)")
    parser.add_argument("--interface", default=None, help="Interface to monitor (default: all)")
    parser.add_argument("--window", type=int, default=120, help="Sliding window in seconds")
    parser.add_argument("--detect", type=int, default=2, help="Occurrences required to raise an incident")
    parser.add_argument("--high", type=int, default=3, help="Occurrences required for high severity")
    parser.add_argument("--warn-alert", type=int, default=1, help="Occurrences required for warning alerts")
    parser.add_argument("--critical-alert", type=int, default=3, help="Occurrences required for critical alerts")
    parser.add_argument("--simulate", action="store_true", help="Run against the built-in spoofing scenario")
    parser.add_argument("--report", default=None, help="Path to export the monitoring report")
    args = parser.parse_args(argv)

    monitor = ARPMonitor()
    manager = NotificationManager(
        NotificationPolicy(
            warning_threshold=args.warn_alert,
            critical_threshold=args.critical_alert,
        )
    )
    manager.register_channel(
        create_callback_channel(
            name="stdout",
            minimum_level="warning",
            callback=lambda event, level, message: print(message, flush=True),
        )
    )
    monitor.set_notification_manager(manager)

    config = MonitorConfig(
        interface=args.interface,
        window_seconds=args.window,
        detection_threshold=args.detect,
        high_severity_threshold=args.high,
        alert_warning_threshold=args.warn_alert,
        alert_critical_threshold=args.critical_alert,
    )
    monitor.configure(config)

    if args.simulate:
        simulator = TrafficSimulator.default_scenario()
        simulator.run(monitor)
    else:
        with _running_monitor(monitor):
            _wait_for_interrupt()

    if args.report:
        report = ReportGenerator(monitor.metrics, monitor.logger)
        report.export(args.report)

    return 0


def _wait_for_interrupt() -> None:
    interrupted = False

    def _handler(signum, frame):  # noqa: ARG001
        nonlocal interrupted
        interrupted = True

    previous = signal.signal(signal.SIGINT, _handler)
    try:
        while not interrupted:
            time.sleep(1)
    finally:
        signal.signal(signal.SIGINT, previous)


def main() -> int:
    return run_cli()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

"""Utilities for exporting monitoring reports."""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .event_logger import EventLogger
from .metrics import Metrics


@dataclass
class ReportGenerator:
    metrics: Metrics
    logger: EventLogger

    def build(self) -> dict[str, object]:
        return {
            "metrics": self.metrics.snapshot(),
            "events": [
                {
                    "timestamp": entry.timestamp.isoformat(),
                    "message": entry.message,
                }
                for entry in self.logger.entries()
            ],
        }

    def export(self, destination: str | Path) -> None:
        path = Path(destination)
        report = self.build()
        if path.suffix.lower() == ".csv":
            self._export_csv(path, report)
        else:
            path.write_text(json.dumps(report, indent=2))

    def _export_csv(self, path: Path, report: dict[str, object]) -> None:
        metrics = report["metrics"]
        incidents: Iterable[dict[str, object]] = metrics.get("incidents", [])
        with path.open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["Metric", "Value"])
            for key, value in metrics.items():
                if key == "incidents":
                    continue
                writer.writerow([key, value])

            writer.writerow([])
            writer.writerow(["Incidents"])
            writer.writerow(["timestamp", "summary", "severity", "ip", "mac", "occurrences"])
            for incident in incidents:
                writer.writerow(
                    [
                        incident["timestamp"],
                        incident["summary"],
                        incident["severity"],
                        incident["ip_address"],
                        incident["mac_address"],
                        incident["occurrences"],
                    ]
                )

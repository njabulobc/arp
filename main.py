"""PyQt5 application entry point for the ARP detector."""
from __future__ import annotations

import sys
from datetime import datetime

from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from arp_detector.mitigation import MitigationAction, MitigationEngine
from arp_detector.monitor import ARPMonitor, MonitorConfig
from arp_detector.rules import DetectionEvent


class IncidentTable(QTableWidget):
    headers = [
        "Timestamp",
        "Severity",
        "Source IP",
        "Source MAC",
        "Target IP",
        "Target MAC",
        "Reason",
        "Occurrences",
    ]

    def __init__(self) -> None:
        super().__init__(0, len(self.headers))
        self.setHorizontalHeaderLabels(self.headers)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.SingleSelection)
        self.horizontalHeader().setStretchLastSection(True)
        self._events: list[DetectionEvent] = []

    def add_event(self, event: DetectionEvent) -> None:
        row = self.rowCount()
        self.insertRow(row)
        self._events.append(event)
        values = [
            event.packet.timestamp.strftime("%H:%M:%S"),
            event.severity.capitalize(),
            event.packet.sender_ip,
            event.packet.sender_mac,
            event.packet.target_ip,
            event.packet.target_mac,
            event.reason,
            str(event.occurrences),
        ]
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            if column == 1:
                color = QColor("#e74c3c") if event.severity == "high" else QColor("#f1c40f")
                item.setForeground(color)
            self.setItem(row, column, item)
        self.scrollToBottom()

    def selected_event(self) -> DetectionEvent | None:
        if not self.selectedIndexes():
            return None
        row = self.selectedIndexes()[0].row()
        if 0 <= row < len(self._events):
            return self._events[row]
        return None

    def clear_events(self) -> None:
        self.setRowCount(0)
        self._events.clear()


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ARP Spoofing Detector")
        self.monitor = ARPMonitor()
        self.mitigation = MitigationEngine()
        self._build_ui()
        self._connect_signals()
        self._load_interfaces()
        self._register_mitigation()

    def _build_ui(self) -> None:
        central = QWidget()
        layout = QVBoxLayout(central)

        layout.addWidget(self._create_configuration_panel())
        layout.addWidget(self._create_metrics_panel())
        layout.addWidget(self._create_incident_panel())
        layout.addWidget(self._create_log_panel())

        self.setCentralWidget(central)

    def _create_configuration_panel(self) -> QWidget:
        group = QGroupBox("Configuration")
        form = QFormLayout(group)

        self.interface_combo = QComboBox()
        self.interface_combo.addItem("All Interfaces", userData=None)

        self.window_spin = QSpinBox()
        self.window_spin.setRange(10, 600)
        self.window_spin.setValue(120)
        self.window_spin.setSuffix(" s")

        self.threshold_spin = QSpinBox()
        self.threshold_spin.setRange(1, 20)
        self.threshold_spin.setValue(3)

        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        self.reset_button = QPushButton("Reset")

        button_row = QHBoxLayout()
        button_row.addWidget(self.start_button)
        button_row.addWidget(self.stop_button)
        button_row.addWidget(self.reset_button)

        form.addRow("Interface", self.interface_combo)
        form.addRow("Threshold Window", self.window_spin)
        form.addRow("Threshold Count", self.threshold_spin)
        form.addRow(button_row)
        return group

    def _create_metrics_panel(self) -> QWidget:
        group = QGroupBox("Metrics")
        grid = QGridLayout(group)

        self.total_packets_label = QLabel("0")
        self.suspicious_packets_label = QLabel("0")

        grid.addWidget(QLabel("Packets Observed"), 0, 0)
        grid.addWidget(self.total_packets_label, 0, 1)
        grid.addWidget(QLabel("Suspicious Packets"), 1, 0)
        grid.addWidget(self.suspicious_packets_label, 1, 1)
        return group

    def _create_incident_panel(self) -> QWidget:
        group = QGroupBox("Incidents")
        vbox = QVBoxLayout(group)
        self.incident_table = IncidentTable()
        self.mitigate_button = QPushButton("Apply Mitigation")
        self.mitigate_button.setEnabled(False)
        vbox.addWidget(self.incident_table)
        vbox.addWidget(self.mitigate_button)
        return group

    def _create_log_panel(self) -> QWidget:
        group = QGroupBox("Event Log")
        vbox = QVBoxLayout(group)
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        vbox.addWidget(self.log_output)
        return group

    def _connect_signals(self) -> None:
        self.start_button.clicked.connect(self._start_monitor)
        self.stop_button.clicked.connect(self._stop_monitor)
        self.reset_button.clicked.connect(self._reset_monitor)
        self.mitigate_button.clicked.connect(self._mitigate_selected)
        self.monitor.packet_processed.connect(self._handle_packet_processed)
        self.monitor.incident_detected.connect(self._handle_incident_detected)
        self.monitor.log_generated.connect(self._append_log)
        self.incident_table.itemSelectionChanged.connect(self._update_mitigation_state)

    def _register_mitigation(self) -> None:
        def fake_mitigation(event: DetectionEvent) -> None:
            self._append_log(
                f"Mitigation simulated for {event.reason}. Operator should review network segmentation policies."
            )

        self.mitigation.register_action(MitigationAction("Simulated Mitigation", fake_mitigation))

    def _load_interfaces(self) -> None:
        try:
            interfaces = self.monitor.available_interfaces()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Interface Error", str(exc))
            interfaces = []
        for iface in interfaces:
            self.interface_combo.addItem(iface, userData=iface)

    # UI slots
    def _start_monitor(self) -> None:
        config = MonitorConfig(
            interface=self.interface_combo.currentData(),
            window_seconds=self.window_spin.value(),
            trigger_threshold=self.threshold_spin.value(),
        )
        self.monitor.configure(config)
        try:
            self.monitor.start()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Start Error", str(exc))
            return
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self._append_log("Monitoring started")

    def _stop_monitor(self) -> None:
        self.monitor.stop()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self._append_log("Monitoring stopped")

    def _reset_monitor(self) -> None:
        self.monitor.reset()
        self.incident_table.clear_events()
        self.total_packets_label.setText("0")
        self.suspicious_packets_label.setText("0")
        self._append_log("Monitor state cleared")

    def _handle_packet_processed(self, _packet) -> None:
        self.total_packets_label.setText(str(self.monitor.metrics.total_packets))

    def _handle_incident_detected(self, event: DetectionEvent) -> None:
        self.suspicious_packets_label.setText(str(self.monitor.metrics.suspicious_packets))
        self.incident_table.add_event(event)
        self._update_mitigation_state()

    def _append_log(self, message: str) -> None:
        timestamp = datetime.utcnow().strftime("%H:%M:%S")
        self.log_output.append(f"[{timestamp}] {message}")

    def _update_mitigation_state(self) -> None:
        self.mitigate_button.setEnabled(bool(self.incident_table.selectedItems()))

    def _mitigate_selected(self) -> None:
        event = self.incident_table.selected_event()
        if not event:
            return
        result = self.mitigation.mitigate(event)
        QMessageBox.information(self, "Mitigation", result)


def main() -> int:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.resize(1000, 700)
    window.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())

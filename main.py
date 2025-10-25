"""PyQt5 application entry point for the ARP detector."""
from __future__ import annotations

import sys
from datetime import datetime

from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
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
from arp_detector.notifications import NotificationManager, NotificationPolicy, create_callback_channel
from arp_detector.reporting import ReportGenerator
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
        self.notification_manager = NotificationManager()
        self._build_ui()
        self._connect_signals()
        self._load_interfaces()
        self._register_mitigation()
        self._register_notifications()

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
        self.threshold_spin.setValue(2)

        self.high_threshold_spin = QSpinBox()
        self.high_threshold_spin.setRange(1, 50)
        self.high_threshold_spin.setValue(4)

        self.warning_alert_spin = QSpinBox()
        self.warning_alert_spin.setRange(1, 20)
        self.warning_alert_spin.setValue(2)

        self.critical_alert_spin = QSpinBox()
        self.critical_alert_spin.setRange(1, 50)
        self.critical_alert_spin.setValue(4)

        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        self.reset_button = QPushButton("Reset")

        button_row = QHBoxLayout()
        button_row.addWidget(self.start_button)
        button_row.addWidget(self.stop_button)
        button_row.addWidget(self.reset_button)

        form.addRow("Interface", self.interface_combo)
        form.addRow("Detection Window", self.window_spin)
        form.addRow("Detection Count", self.threshold_spin)
        form.addRow("High Severity Count", self.high_threshold_spin)
        form.addRow("Warning Alert Count", self.warning_alert_spin)
        form.addRow("Critical Alert Count", self.critical_alert_spin)
        form.addRow(button_row)
        return group

    def _create_metrics_panel(self) -> QWidget:
        group = QGroupBox("Metrics")
        grid = QGridLayout(group)

        self.total_packets_label = QLabel("0")
        self.suspicious_packets_label = QLabel("0")
        self.accuracy_label = QLabel("0.0%")
        self.false_positive_label = QLabel("0.0%")
        self.cpu_usage_label = QLabel("0.0%")
        self.bandwidth_label = QLabel("0.0 KB/s")

        self.export_button = QPushButton("Export Report")

        grid.addWidget(QLabel("Packets Observed"), 0, 0)
        grid.addWidget(self.total_packets_label, 0, 1)
        grid.addWidget(QLabel("Suspicious Packets"), 1, 0)
        grid.addWidget(self.suspicious_packets_label, 1, 1)
        grid.addWidget(QLabel("Detection Accuracy"), 2, 0)
        grid.addWidget(self.accuracy_label, 2, 1)
        grid.addWidget(QLabel("False Positive Rate"), 3, 0)
        grid.addWidget(self.false_positive_label, 3, 1)
        grid.addWidget(QLabel("Avg CPU Usage"), 4, 0)
        grid.addWidget(self.cpu_usage_label, 4, 1)
        grid.addWidget(QLabel("Avg Bandwidth Impact"), 5, 0)
        grid.addWidget(self.bandwidth_label, 5, 1)
        grid.addWidget(self.export_button, 6, 0, 1, 2)
        return group

    def _create_incident_panel(self) -> QWidget:
        group = QGroupBox("Incidents")
        vbox = QVBoxLayout(group)
        self.incident_table = IncidentTable()
        self.mitigation_action_combo = QComboBox()
        self.mitigate_button = QPushButton("Apply Mitigation")
        self.mitigate_button.setEnabled(False)
        vbox.addWidget(self.incident_table)
        vbox.addWidget(self.mitigation_action_combo)
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
        self.export_button.clicked.connect(self._export_report)

    def _register_mitigation(self) -> None:
        def fake_mitigation(event: DetectionEvent) -> str:
            recommendation = (
                "Mitigation simulated for {reason}. Review network segmentation and isolate {ip}."
            ).format(reason=event.reason, ip=event.packet.sender_ip)
            self._append_log(recommendation)
            return recommendation

        self.mitigation.register_action(MitigationAction("Simulated Mitigation", fake_mitigation))
        self.mitigation.register_shell_command(
            "Flush suspect ARP entry",
            ["arp", "-d", "{src_ip}"],
        )
        self._refresh_mitigation_actions()

    def _register_notifications(self) -> None:
        self.notification_manager.clear_channels()

        def _popup(event: DetectionEvent, level: str, message: str) -> None:
            QMessageBox.warning(self, f"ARP {level.title()} Alert", message)

        self.notification_manager.register_channel(
            create_callback_channel("popup", "warning", _popup)
        )

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
        detection_threshold = self.threshold_spin.value()
        high_severity = max(self.high_threshold_spin.value(), detection_threshold)
        self.high_threshold_spin.setValue(high_severity)
        warning_alert = self.warning_alert_spin.value()
        critical_alert = max(self.critical_alert_spin.value(), warning_alert, detection_threshold)
        self.critical_alert_spin.setValue(critical_alert)

        config = MonitorConfig(
            interface=self.interface_combo.currentData(),
            window_seconds=self.window_spin.value(),
            detection_threshold=detection_threshold,
            high_severity_threshold=high_severity,
            alert_warning_threshold=warning_alert,
            alert_critical_threshold=critical_alert,
        )
        self.monitor.configure(config)
        self.notification_manager.configure(
            NotificationPolicy(
                warning_threshold=warning_alert,
                critical_threshold=critical_alert,
            )
        )
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
        self._update_metrics_labels()
        self._append_log("Monitor state cleared")

    def _handle_packet_processed(self, _packet) -> None:
        self._update_metrics_labels()

    def _handle_incident_detected(self, event: DetectionEvent) -> None:
        self.incident_table.add_event(event)
        self._update_mitigation_state()
        self.notification_manager.notify(event)
        self._update_metrics_labels()

    def _append_log(self, message: str) -> None:
        timestamp = datetime.utcnow().strftime("%H:%M:%S")
        self.log_output.append(f"[{timestamp}] {message}")

    def _update_mitigation_state(self) -> None:
        self.mitigate_button.setEnabled(bool(self.incident_table.selectedItems()))

    def _mitigate_selected(self) -> None:
        event = self.incident_table.selected_event()
        if not event:
            return
        action = self.mitigation_action_combo.currentText()
        result = self.mitigation.mitigate(event, action)
        QMessageBox.information(self, "Mitigation", result)

    def _refresh_mitigation_actions(self) -> None:
        self.mitigation_action_combo.clear()
        for action in self.mitigation.available_actions():
            self.mitigation_action_combo.addItem(action.description)

    def _update_metrics_labels(self) -> None:
        metrics = self.monitor.metrics
        self.total_packets_label.setText(str(metrics.total_packets))
        self.suspicious_packets_label.setText(str(metrics.suspicious_packets))
        self.accuracy_label.setText(f"{metrics.accuracy * 100:.1f}%")
        self.false_positive_label.setText(f"{metrics.false_positive_rate * 100:.1f}%")
        self.cpu_usage_label.setText(f"{metrics.average_cpu:.1f}%")
        bandwidth_kb = metrics.average_bandwidth / 1024
        self.bandwidth_label.setText(f"{bandwidth_kb:.1f} KB/s")

    def _export_report(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Monitoring Report",
            "arp_report.json",
            "JSON Files (*.json);;CSV Files (*.csv)",
        )
        if not path:
            return
        report = ReportGenerator(self.monitor.metrics, self.monitor.logger)
        try:
            report.export(path)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Export Failed", str(exc))
            return
        QMessageBox.information(self, "Report Exported", f"Report saved to {path}")


def main() -> int:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.resize(1000, 700)
    window.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())

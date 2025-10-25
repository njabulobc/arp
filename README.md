# ARP Spoofing Detector

A desktop application built with PyQt5 that captures ARP traffic, detects spoofing attempts, and assists operators with mitigation workflows. The detector implements a modular analysis pipeline inspired by traditional intrusion detection systems.

## Features

- Real-time ARP packet capture using Scapy
- Binding cache and conflict detection for IP/MAC anomalies
- Rule and threshold-based decision logic with severity grading
- Incident dashboard with metrics, event log, and mitigation hooks
- Configurable detection window, alert escalation, and monitored interface
- Effectiveness metrics covering accuracy, false-positive rate, CPU load, and bandwidth impact
- Built-in spoofing simulation to validate detection performance against ground truth
- Headless CLI mode with configurable notification policy and report export

## Requirements

- Python 3.10+
- [Scapy](https://scapy.net/) for packet capture
- [PyQt5](https://pypi.org/project/PyQt5/) for the user interface
- [psutil](https://pypi.org/project/psutil/) for CPU and bandwidth sampling

Install dependencies with:

```bash
pip install -r requirements.txt
```

## Usage

> **Note:** Capturing ARP frames typically requires administrative privileges.

1. Start the application:
   ```bash
   python main.py
   ```
2. Select the network interface you want to monitor (or use *All Interfaces*).
3. Adjust the detection thresholds, severity escalation counts, and alert policy as needed.
4. Click **Start** to begin monitoring. Suspicious activity appears in the incident table, event log, and pop-up alerts.
5. Select an incident, pick a mitigation action, and choose **Apply Mitigation** to execute the response handler.
6. Use **Export Report** to persist metrics and the audit log as JSON or CSV.

### Headless Mode & Simulation

Run the detector without the GUI to support server deployments or automated evaluation:

```bash
python -m arp_detector.cli --simulate --report report.json
```

The `--simulate` flag replays a built-in blend of baseline and spoofing traffic so you can measure accuracy, false positives, and resource utilisation without touching a live network. Omit the flag to monitor real traffic, and use `--report` to export a JSON or CSV summary after execution.

## Architecture Overview

The monitoring pipeline mirrors the flow illustrated in the accompanying diagrams:

1. **Capture Layer** – The `AsyncSniffer` from Scapy listens for ARP traffic and forwards packets to the parser.
2. **Analysis Layer** – Parsed packets feed a binding cache, conflict checker, and rule-matching module that evaluate anomalies.
3. **Decision Layer** – Threshold evaluation aggregates events over time to classify incidents with severity labels.
4. **Response Layer** – Detected incidents are logged, visualized in the UI, exported via reports, and routed through a mitigation engine for operator action or automated shell commands.

## Development Notes

- The application uses Qt signals to keep the UI responsive while Scapy captures packets in the background.
- The mitigation engine supports both simulated responses and command-based actions. Extend `arp_detector/mitigation.py` with environment-specific handlers (e.g., pushing ACL updates or triggering NAC workflows).
- Metrics and logs are stored in-memory and can be exported via the **Export Report** button or CLI `--report` option.
- Effectiveness counters track true/false positives and negatives when packets include ground-truth labels (e.g., from the simulator).

## Testing without Live Traffic

If you cannot capture real ARP traffic, run the headless CLI with `--simulate` to drive the detector with labelled baseline and spoofing traffic. You can also craft packets with Scapy and feed them into the monitor using `ARPMonitor.ingest_simulated_packet` for custom scenarios.

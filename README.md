# ARP Spoofing Detector

A desktop application built with PyQt5 that captures ARP traffic, detects spoofing attempts, and assists operators with mitigation workflows. The detector implements a modular analysis pipeline inspired by traditional intrusion detection systems.

## Features

- Real-time ARP packet capture using Scapy
- Binding cache and conflict detection for IP/MAC anomalies
- Rule and threshold-based decision logic with severity grading
- Incident dashboard with metrics, event log, and mitigation hooks
- Configurable detection window, threshold, and monitored interface

## Requirements

- Python 3.10+
- [Scapy](https://scapy.net/) for packet capture
- [PyQt5](https://pypi.org/project/PyQt5/) for the user interface

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
3. Adjust the detection window and threshold as needed.
4. Click **Start** to begin monitoring. Suspicious activity appears in the incident table and event log.
5. Select an incident and choose **Apply Mitigation** to execute the registered response handler.

## Architecture Overview

The monitoring pipeline mirrors the flow illustrated in the accompanying diagrams:

1. **Capture Layer** – The `AsyncSniffer` from Scapy listens for ARP traffic and forwards packets to the parser.
2. **Analysis Layer** – Parsed packets feed a binding cache, conflict checker, and rule-matching module that evaluate anomalies.
3. **Decision Layer** – Threshold evaluation aggregates events over time to classify incidents with severity labels.
4. **Response Layer** – Detected incidents are logged, visualized in the UI, and routed through a mitigation engine for operator action.

## Development Notes

- The application uses Qt signals to keep the UI responsive while Scapy captures packets in the background.
- The mitigation engine currently provides a simulated response. Extend `arp_detector/mitigation.py` with environment-specific actions (e.g., sending corrective ARP broadcasts or updating firewall rules).
- Metrics and logs are stored in-memory for simplicity; integrate a persistent backend if historical reporting is required.

## Testing without Live Traffic

If you cannot capture real ARP traffic, you can craft packets with Scapy in a Python shell and feed them into the monitor using `ARPMonitor._handle_packet`. This allows you to validate the decision logic without elevated privileges.

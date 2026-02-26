# Dockerized Modbus Network Defense using Zeek, Suricata and Machine Learning

## Why this matters 
Industrial Control Systems (ICS) run physical processes (motors, drives, pumps, PLC controlled equipment). When attackers gain access to OT networks, a common pattern of what they do is:

1) **Reconnaissance** — First map devices and read registers to understand process state of the equipments 
2) **Manipulation** — Then they write coils/registers or probe invalid addresses to influence behavior which causes disruption, or prepare for escalation.

Even “simple” protocol abuse can lead to downtime, unsafe states, equipment stress, and real operational impact.

This project is a reproducible mini-lab that demonstrates a realistic OT security workflow:
- Generate OT protocol traffic (normal + attack-like),
- Capture network evidence (telemetry + IDS),
- Classify and check for suspicious behavior using a lightweight ML model.

---

## What this mini project implements
### Objective
Build a Dockerized OT testbed for **Modbus/TCP** to detect **recon** and **manipulation** behavior using:
- **Zeek** (network telemetry logs)
- **Suricata** (IDS events/alerts)
- **ML Calssifier** (windowed features + Logistic Regression)

### Project phases
- **Phase 1 — OT + Monitoring:** Modbus server + traffic generator + Zeek + Suricata → logs saved to `data/`
- **Phase 2 — ML Classifier:** 5-second windows, feature extraction, classifier training → `data/ml_results.json`
- **Phase 3 — Packaging:** Demo (`scripts/demo.ps1`), cleanup, reproducible visuals in `reports/`

---

## Tools used and how this maps to real ICS practice
- **Modbus/TCP:** widely used OT protocol for register/coil read/write operations.
- **Zeek:** used for network telemetry at scale (connection logs, behavioral metadata, investigation support).
- **Suricata:** IDS engine used for rule/threshold detections and structured event output (`eve.json`).
- **Python + ML:** practical triage layer to classify suspicious windows and show which signals drive the decision.
- **Docker Compose:** makes the lab reproducible and portable, similar to how security teams build testbeds and CI security labs.

---

## Framework (end-to-end workflow)
### Dataflow
1. `traffic-gen` produces **Normal → Recon → Manipulation** Modbus traffic to `modbus-server`
2. **Zeek** records network connection telemetry → `data/zeek/`
3. **Suricata** records IDS events/alerts → `data/suricata/eve.json`
4. **ML** reads labels + traffic events (+ optional Suricata alerts) → trains classifier → `data/ml_results.json`

### Architecture diagram
Add your draw.io export here:
- `reports/framework.png`

## Real ICS Application Scenario (Physical Meaning)
To make the experiment realistic, we map Modbus memory to a **water treatment pump station**.

### Modbus memory map (example)
| Modbus Item | Address | Physical Meaning |
|---|---:|---|
| Holding Register | 10 | Discharge pressure (psi) |
| Holding Register | 11 | Motor current (A) |
| Holding Register | 12 | Motor temperature (°C) |
| Coil | 5 | Cooling pump ON/OFF |
| Coil | 6 | Main pump ON/OFF |
| Holding Register | 20 | Valve position (%) |

### How the three phases translate to real impact
- **Normal:** SCADA periodically reads pressure/current/temp and verifies cooling pump state.
- **Recon:** An attacker scans register/coil ranges to discover where safety-critical controls and sensors are mapped.
- **Manipulation:** The attacker writes to coils/registers (e.g., turns cooling pump OFF or spoofs pressure readings), increasing risk of overheating, cavitation, or pipe stress while hiding the true state from operators.

**Why this matters:** This demonstrates how network-level OT attacks can translate into physical consequences, and how telemetry + IDS + ML classifier can detect early recon and manipulation behaviors.


# HelixMind v1.1 — Anomaly Intelligence Layer

**Role in the ecosystem:** Telemetry / Monitoring / Anomaly Intelligence

HelixMind is the observation and anomaly detection layer of the larger system.

## What it does

- Collects system telemetry (CPU, Memory, Disk, Load, Processes, Network, Uptime)
- Runs multi-layer anomaly detection
- Detects **correlated multi-signal events** (not just isolated thresholds)
- Produces an **explainable Health Score** with component breakdown
- Emits structured machine-readable insights and events

## Architecture (current)

```
collect_metrics()
      ↓
multi_layer_detection()  +  detect_correlated_events()
      ↓
calculate_health_score()   (explainable components)
      ↓
structured outputs:
  - helix_state.json
  - helix_insights.json
  - helix_events.json
  - helix_report.txt
```

## Key improvements in v1.1

- Multi-signal correlation (resource pressure detection)
- Health Score with explicit component weights
- Structured events with confidence scores
- Cleaner separation of concerns

## Files

| File                  | Purpose                                      |
|-----------------------|----------------------------------------------|
| `helix_core.py`       | Main engine                                  |
| `helix_state.json`    | Full persistent state + history              |
| `helix_insights.json` | Latest machine-readable analysis             |
| `helix_events.json`   | Recent correlated events                     |
| `helix_report.txt`    | Human-readable report                        |
| `helix.log`           | Operational log                              |

## Run

```bash
pip install -r requirements.txt
python helix_core.py
```

## Automation

GitHub Actions runs every 2 hours and commits all outputs.

---

**Ecosystem position:**  
HelixMind → (Telemetry + Anomalies) → consumed later by Cognitive / Reasoning layers

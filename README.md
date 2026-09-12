# HelixMind — Apex Cognitive System

**The strongest self-evolving intelligence core in the series.**

HelixMind goes beyond basic monitoring. It implements multi-layer detection, predictive signals, a quantitative Health Score, and automated insight generation.

## Key Capabilities

- **Multi-Layer Anomaly Detection**
  - Layer 1: Absolute thresholds
  - Layer 2: Statistical deviation (mean + std)
  - Layer 3: Short-term predictive trend signals

- **Health Score (0–100)** with clear status labels
- **Rich Metrics**: CPU, Memory, Disk, Load averages (1/5/15), Processes, Uptime, Network
- **Automated Insights** saved to `helix_insights.json`
- **Deep History** (up to 300 snapshots)
- **Full Operational Logging**

## Files

| File                 | Purpose                              |
|----------------------|--------------------------------------|
| `helix_core.py`      | Main Apex engine                     |
| `helix_state.json`   | Persistent state & full history      |
| `helix_report.txt`   | Human-readable report                |
| `helix_insights.json`| Structured insights & anomalies      |
| `helix.log`          | Operational log                      |

## Run Locally

```bash
pip install -r requirements.txt
python helix_core.py
```

## Automation

GitHub Actions runs the full cycle every 2 hours and commits results automatically.

---

**Author**: mfathialrahman-crypto  
**Position in family**: The Apex / Peak power version

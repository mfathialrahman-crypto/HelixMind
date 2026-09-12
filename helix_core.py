#!/usr/bin/env python3
"""
HelixMind — Apex Self-Evolving Cognitive System
Version: 1.0 (Apex)
Author: mfathialrahman-crypto

Features:
- Multi-layer anomaly detection
- Predictive trend scoring
- Health score calculation
- Automated insights generation
- Persistent structured state
- Rich professional reporting
"""

import os
import json
import platform
import socket
import hashlib
from datetime import datetime, timezone, timedelta
from statistics import mean, stdev, median
from pathlib import Path
from typing import Dict, List, Any, Tuple

# ==================== CONFIG ====================
STATE_FILE = "helix_state.json"
REPORT_FILE = "helix_report.txt"
INSIGHTS_FILE = "helix_insights.json"
LOG_FILE = "helix.log"
MAX_HISTORY = 300
MAX_ALERTS = 50

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def log(message: str, level: str = "INFO"):
    ts = utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")
    entry = f"[{ts}] [{level}] {message}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry)

def load_json(path: str, default: Any) -> Any:
    if Path(path).exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            log(f"Failed loading {path}: {e}", "ERROR")
    return default

def save_json(path: str, data: Any):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)

def collect_metrics() -> Dict[str, Any]:
    m = {
        "cpu": 0.0,
        "memory": 0.0,
        "disk": 0.0,
        "load_1": 0.0,
        "load_5": 0.0,
        "load_15": 0.0,
        "net_sent_mb": 0.0,
        "net_recv_mb": 0.0,
        "process_count": 0,
        "boot_time": None,
        "uptime_hours": 0.0
    }
    try:
        import psutil
        m["cpu"] = round(psutil.cpu_percent(interval=1.0), 1)
        mem = psutil.virtual_memory()
        m["memory"] = round(mem.percent, 1)
        m["disk"] = round(psutil.disk_usage("/").percent, 1)

        if hasattr(os, "getloadavg"):
            load = os.getloadavg()
            m["load_1"] = round(load[0], 2)
            m["load_5"] = round(load[1], 2)
            m["load_15"] = round(load[2], 2)

        net = psutil.net_io_counters()
        m["net_sent_mb"] = round(net.bytes_sent / 1024 / 1024, 2)
        m["net_recv_mb"] = round(net.bytes_recv / 1024 / 1024, 2)
        m["process_count"] = len(psutil.pids())

        boot = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
        m["boot_time"] = boot.isoformat()
        m["uptime_hours"] = round((utc_now() - boot).total_seconds() / 3600, 1)
    except Exception as e:
        log(f"Metrics error: {e}", "ERROR")
    return m

def signature(data: Dict) -> str:
    raw = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:24]

def calculate_health_score(metrics: Dict, history: List[Dict]) -> Tuple[int, str]:
    """Returns score 0-100 and status label"""
    score = 100

    # Penalties
    if metrics["cpu"] > 90: score -= 35
    elif metrics["cpu"] > 75: score -= 18
    elif metrics["cpu"] > 60: score -= 8

    if metrics["memory"] > 92: score -= 30
    elif metrics["memory"] > 85: score -= 15
    elif metrics["memory"] > 75: score -= 7

    if metrics["disk"] > 93: score -= 25
    elif metrics["disk"] > 85: score -= 12

    if metrics["load_1"] > 4.0: score -= 10

    score = max(0, min(100, score))

    if score >= 90: label = "Excellent"
    elif score >= 75: label = "Good"
    elif score >= 55: label = "Fair"
    elif score >= 35: label = "Degraded"
    else: label = "Critical"

    return score, label

def multi_layer_detection(current: Dict, history: List[Dict]) -> Tuple[List[str], List[Dict], List[str]]:
    """
    Returns: (anomalies, alerts, insights)
    """
    anomalies = []
    alerts = []
    insights = []

    # Layer 1: Absolute thresholds
    if current["cpu"] >= 92:
        anomalies.append("🔴 L1 CRITICAL — CPU saturation")
        alerts.append({"level": "critical", "metric": "cpu", "value": current["cpu"]})
    elif current["cpu"] >= 78:
        anomalies.append("⚠️ L1 WARNING — Elevated CPU")

    if current["memory"] >= 93:
        anomalies.append("🔴 L1 CRITICAL — Memory pressure")
        alerts.append({"level": "critical", "metric": "memory", "value": current["memory"]})
    elif current["memory"] >= 83:
        anomalies.append("⚠️ L1 WARNING — High memory")

    if current["disk"] >= 94:
        anomalies.append("🔴 L1 CRITICAL — Disk near full")
        alerts.append({"level": "critical", "metric": "disk", "value": current["disk"]})
    elif current["disk"] >= 86:
        anomalies.append("⚠️ L1 WARNING — Disk high")

    # Layer 2: Statistical deviation
    if len(history) >= 10:
        recent = history[-15:]
        cpu_vals = [h.get("cpu", 0) for h in recent]
        mem_vals = [h.get("memory", 0) for h in recent]

        try:
            cpu_mean = mean(cpu_vals)
            cpu_std = stdev(cpu_vals) if len(cpu_vals) > 1 else 0
            mem_mean = mean(mem_vals)

            if current["cpu"] > cpu_mean + max(2.2 * cpu_std, 12) and current["cpu"] > 35:
                anomalies.append(f"📈 L2 STAT — CPU spike vs baseline {cpu_mean:.1f}%")
                insights.append(f"CPU is significantly above recent average ({cpu_mean:.1f}%)")

            if current["memory"] > mem_mean + 10:
                anomalies.append(f"📈 L2 STAT — Memory rising above baseline {mem_mean:.1f}%")
                insights.append(f"Memory trend is upward relative to recent history")
        except Exception:
            pass

    # Layer 3: Predictive simple trend
    if len(history) >= 6:
        last3_cpu = [h.get("cpu", 0) for h in history[-3:]]
        prev3_cpu = [h.get("cpu", 0) for h in history[-6:-3]]
        if mean(last3_cpu) > mean(prev3_cpu) + 8:
            insights.append("Predictive signal: CPU shows accelerating upward trend")

    if not anomalies:
        anomalies.append("✅ All layers clear — system stable")

    return anomalies, alerts, insights

def generate_report(state: Dict, metrics: Dict, anomalies: List[str],
                    health_score: int, health_label: str,
                    insights: List[str], sig: str) -> str:
    border = "═" * 62
    now = utc_now()

    lines = [
        f"╔{border}╗",
        f"║               HELIXMIND — APEX COGNITIVE CORE               ║",
        f"╠{border}╣",
        f"║  Identity      : {state.get('identity', 'HelixMind v1.0')}",
        f"║  Host          : {socket.gethostname()}",
        f"║  Platform      : {platform.system()} {platform.release()}",
        f"║  Evolution     : Generation #{state.get('evolution', 0)}",
        f"║  Timestamp     : {now.strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"║  Signature     : {sig}",
        f"╠{border}╣",
        f"║  HEALTH SCORE  : {health_score}/100  [{health_label}]",
        f"╠{border}╣",
        f"║  CPU           : {metrics['cpu']}%",
        f"║  Memory        : {metrics['memory']}%",
        f"║  Disk          : {metrics['disk']}%",
        f"║  Load (1/5/15) : {metrics['load_1']} / {metrics['load_5']} / {metrics['load_15']}",
        f"║  Processes     : {metrics['process_count']}",
        f"║  Uptime        : {metrics['uptime_hours']} hours",
        f"║  Network ↑     : {metrics['net_sent_mb']} MB",
        f"║  Network ↓     : {metrics['net_recv_mb']} MB",
        f"╠{border}╣",
        f"║  Multi-Layer Analysis:",
    ]
    for a in anomalies:
        lines.append(f"║    {a}")

    if insights:
        lines.append(f"╠{border}╣")
        lines.append(f"║  Insights:")
        for i in insights:
            lines.append(f"║    • {i}")

    lines.append(f"╠{border}╣")
    lines.append(f"║  History depth : {len(state.get('history', []))} snapshots")
    lines.append(f"║  Status        : {state.get('status', 'active')}")
    lines.append(f"╚{border}╝")
    return "\n".join(lines) + "\n"

def main():
    log("HelixMind cycle initiated")

    state = load_json(STATE_FILE, {
        "identity": "HelixMind v1.0 — Apex",
        "evolution": 0,
        "history": [],
        "alerts": [],
        "status": "initializing"
    })

    metrics = collect_metrics()
    anomalies, new_alerts, insights = multi_layer_detection(metrics, state.get("history", []))
    health_score, health_label = calculate_health_score(metrics, state.get("history", []))

    metrics["timestamp"] = utc_now().isoformat()
    sig = signature(metrics)
    metrics["signature"] = sig
    metrics["health_score"] = health_score

    # Update state
    state["evolution"] = state.get("evolution", 0) + 1
    history = state.get("history", [])
    history.append(metrics)
    if len(history) > MAX_HISTORY:
        history = history[-MAX_HISTORY:]
    state["history"] = history
    state["alerts"] = (state.get("alerts", []) + new_alerts)[-MAX_ALERTS:]
    state["last_run"] = utc_now().isoformat()
    state["status"] = "active"
    state["hostname"] = socket.gethostname()
    state["os"] = platform.system()
    state["last_health_score"] = health_score
    state["last_health_label"] = health_label

    save_json(STATE_FILE, state)

    # Insights file
    insights_data = {
        "generated_at": utc_now().isoformat(),
        "generation": state["evolution"],
        "health_score": health_score,
        "insights": insights,
        "anomalies": anomalies
    }
    save_json(INSIGHTS_FILE, insights_data)

    report = generate_report(state, metrics, anomalies, health_score, health_label, insights, sig)
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(report)

    print(report)
    log(f"Cycle complete — Gen #{state['evolution']} | Health {health_score}/100")

if __name__ == "__main__":
    main()

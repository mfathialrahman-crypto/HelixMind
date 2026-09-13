#!/usr/bin/env python3
"""
HelixMind — Telemetry + Anomaly Intelligence Engine
Version: 1.1
Role in ecosystem: Monitoring / Telemetry / Anomaly Intelligence Layer
"""

import os
import json
import platform
import socket
import hashlib
from datetime import datetime, timezone
from statistics import mean, stdev
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional

# ==================== CONFIG ====================
STATE_FILE = "helix_state.json"
REPORT_FILE = "helix_report.txt"
INSIGHTS_FILE = "helix_insights.json"
EVENTS_FILE = "helix_events.json"
LOG_FILE = "helix.log"
MAX_HISTORY = 300
MAX_ALERTS = 50
MAX_EVENTS = 100

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def log(message: str, level: str = "INFO"):
    ts = utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] [{level}] {message}\n")

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
        m["memory"] = round(psutil.virtual_memory().percent, 1)
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
        log(f"Metrics collection failed: {e}", "ERROR")
    return m

def signature(data: Dict) -> str:
    raw = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:24]

def calculate_health_score(metrics: Dict, history: List[Dict]) -> Tuple[int, str, Dict]:
    """Explainable health score with component breakdown."""
    components = {
        "cpu": 25,
        "memory": 25,
        "disk": 20,
        "load": 15,
        "stability": 15
    }

    # CPU component
    if metrics["cpu"] >= 92:
        components["cpu"] = 0
    elif metrics["cpu"] >= 80:
        components["cpu"] = 8
    elif metrics["cpu"] >= 65:
        components["cpu"] = 15

    # Memory component
    if metrics["memory"] >= 93:
        components["memory"] = 0
    elif metrics["memory"] >= 85:
        components["memory"] = 8
    elif metrics["memory"] >= 75:
        components["memory"] = 16

    # Disk component
    if metrics["disk"] >= 94:
        components["disk"] = 0
    elif metrics["disk"] >= 88:
        components["disk"] = 7
    elif metrics["disk"] >= 80:
        components["disk"] = 14

    # Load component
    if metrics["load_1"] >= 5.0:
        components["load"] = 0
    elif metrics["load_1"] >= 3.0:
        components["load"] = 6
    elif metrics["load_1"] >= 2.0:
        components["load"] = 11

    # Stability (based on recent variance if enough history)
    if len(history) >= 8:
        recent_cpu = [h.get("cpu", 0) for h in history[-8:]]
        try:
            if stdev(recent_cpu) > 18:
                components["stability"] = 5
            elif stdev(recent_cpu) > 10:
                components["stability"] = 10
        except Exception:
            pass

    score = sum(components.values())
    score = max(0, min(100, score))

    if score >= 90:
        label = "Excellent"
    elif score >= 75:
        label = "Good"
    elif score >= 55:
        label = "Fair"
    elif score >= 35:
        label = "Degraded"
    else:
        label = "Critical"

    return score, label, components

def detect_correlated_events(current: Dict, history: List[Dict]) -> List[Dict]:
    """Detect multi-signal correlated incidents instead of isolated alerts."""
    events = []

    high_cpu = current["cpu"] >= 78
    high_mem = current["memory"] >= 82
    high_load = current["load_1"] >= 2.5
    high_proc = current["process_count"] > 250  # rough heuristic on runner

    # Correlated resource pressure
    signals = sum([high_cpu, high_mem, high_load])
    if signals >= 2:
        confidence = 0.55 + (0.15 * signals)
        events.append({
            "type": "resource_pressure",
            "severity": "high" if signals >= 3 else "medium",
            "confidence": round(min(confidence, 0.95), 2),
            "signals": {
                "cpu": current["cpu"],
                "memory": current["memory"],
                "load_1": current["load_1"]
            },
            "explanation": "Multiple resource metrics elevated simultaneously — possible single underlying cause"
        })

    # Disk pressure standalone (usually independent)
    if current["disk"] >= 90:
        events.append({
            "type": "disk_pressure",
            "severity": "critical" if current["disk"] >= 95 else "high",
            "confidence": 0.9,
            "signals": {"disk": current["disk"]},
            "explanation": "Disk usage critically high"
        })

    return events

def multi_layer_detection(current: Dict, history: List[Dict]) -> Tuple[List[str], List[Dict], List[str], List[Dict]]:
    anomalies = []
    alerts = []
    insights = []

    # Layer 1 — Absolute
    if current["cpu"] >= 92:
        anomalies.append("L1 CRITICAL — CPU saturation")
        alerts.append({"level": "critical", "metric": "cpu", "value": current["cpu"]})
    elif current["cpu"] >= 78:
        anomalies.append("L1 WARNING — Elevated CPU")

    if current["memory"] >= 93:
        anomalies.append("L1 CRITICAL — Memory pressure")
        alerts.append({"level": "critical", "metric": "memory", "value": current["memory"]})
    elif current["memory"] >= 83:
        anomalies.append("L1 WARNING — High memory")

    if current["disk"] >= 94:
        anomalies.append("L1 CRITICAL — Disk near full")
        alerts.append({"level": "critical", "metric": "disk", "value": current["disk"]})
    elif current["disk"] >= 86:
        anomalies.append("L1 WARNING — Disk high")

    # Layer 2 — Statistical
    if len(history) >= 10:
        recent = history[-15:]
        cpu_vals = [h.get("cpu", 0) for h in recent]
        mem_vals = [h.get("memory", 0) for h in recent]
        try:
            cpu_mean = mean(cpu_vals)
            cpu_std = stdev(cpu_vals) if len(cpu_vals) > 1 else 0
            mem_mean = mean(mem_vals)

            if current["cpu"] > cpu_mean + max(2.2 * cpu_std, 12) and current["cpu"] > 35:
                anomalies.append(f"L2 STAT — CPU spike vs baseline {cpu_mean:.1f}%")
                insights.append(f"CPU significantly above recent average ({cpu_mean:.1f}%)")

            if current["memory"] > mem_mean + 10:
                anomalies.append(f"L2 STAT — Memory rising above baseline {mem_mean:.1f}%")
                insights.append("Memory trend upward relative to recent history")
        except Exception:
            pass

    # Layer 3 — Short predictive
    if len(history) >= 6:
        last3 = [h.get("cpu", 0) for h in history[-3:]]
        prev3 = [h.get("cpu", 0) for h in history[-6:-3]]
        if mean(last3) > mean(prev3) + 8:
            insights.append("Predictive: CPU shows accelerating upward trend")

    # Correlated events
    correlated = detect_correlated_events(current, history)
    for ev in correlated:
        insights.append(f"CORRELATED [{ev['severity']}] {ev['type']} (conf {ev['confidence']})")

    if not anomalies:
        anomalies.append("All layers clear — system stable")

    return anomalies, alerts, insights, correlated

def generate_report(state, metrics, anomalies, health_score, health_label,
                    components, insights, correlated, sig) -> str:
    border = "═" * 64
    now = utc_now()
    lines = [
        f"╔{border}╗",
        f"║            HELIXMIND v1.1 — ANOMALY INTELLIGENCE             ║",
        f"╠{border}╣",
        f"║  Identity      : {state.get('identity')}",
        f"║  Host          : {socket.gethostname()}",
        f"║  Platform      : {platform.system()} {platform.release()}",
        f"║  Evolution     : Generation #{state.get('evolution', 0)}",
        f"║  Timestamp     : {now.strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"║  Signature     : {sig}",
        f"╠{border}╣",
        f"║  HEALTH SCORE  : {health_score}/100  [{health_label}]",
        f"║  Breakdown     : CPU {components['cpu']} | Mem {components['memory']} | Disk {components['disk']} | Load {components['load']} | Stab {components['stability']}",
        f"╠{border}╣",
        f"║  CPU           : {metrics['cpu']}%",
        f"║  Memory        : {metrics['memory']}%",
        f"║  Disk          : {metrics['disk']}%",
        f"║  Load (1/5/15) : {metrics['load_1']} / {metrics['load_5']} / {metrics['load_15']}",
        f"║  Processes     : {metrics['process_count']}",
        f"║  Uptime        : {metrics['uptime_hours']} h",
        f"╠{border}╣",
        f"║  Analysis:",
    ]
    for a in anomalies:
        lines.append(f"║    • {a}")

    if insights:
        lines.append(f"╠{border}╣")
        lines.append(f"║  Insights:")
        for i in insights:
            lines.append(f"║    • {i}")

    if correlated:
        lines.append(f"╠{border}╣")
        lines.append(f"║  Correlated Events:")
        for ev in correlated:
            lines.append(f"║    • [{ev['severity'].upper()}] {ev['type']} (conf={ev['confidence']})")

    lines.append(f"╠{border}╣")
    lines.append(f"║  History       : {len(state.get('history', []))} snapshots")
    lines.append(f"║  Status        : {state.get('status', 'active')}")
    lines.append(f"╚{border}╝")
    return "\n".join(lines) + "\n"

def main():
    log("HelixMind v1.1 cycle started")

    state = load_json(STATE_FILE, {
        "identity": "HelixMind v1.1 — Anomaly Intelligence",
        "evolution": 0,
        "history": [],
        "alerts": [],
        "events": [],
        "status": "initializing"
    })

    metrics = collect_metrics()
    anomalies, new_alerts, insights, correlated = multi_layer_detection(
        metrics, state.get("history", [])
    )
    health_score, health_label, components = calculate_health_score(
        metrics, state.get("history", [])
    )

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

    # Structured events
    new_events = []
    for ev in correlated:
        event = {
            "id": signature(ev),
            "timestamp": utc_now().isoformat(),
            "generation": state["evolution"],
            **ev
        }
        new_events.append(event)
    state["events"] = (state.get("events", []) + new_events)[-MAX_EVENTS:]

    state["last_run"] = utc_now().isoformat()
    state["status"] = "active"
    state["hostname"] = socket.gethostname()
    state["os"] = platform.system()
    state["last_health_score"] = health_score
    state["last_health_label"] = health_label
    state["last_health_components"] = components

    save_json(STATE_FILE, state)

    # Machine-readable insights
    insights_payload = {
        "generated_at": utc_now().isoformat(),
        "generation": state["evolution"],
        "health_score": health_score,
        "health_label": health_label,
        "health_components": components,
        "anomalies": anomalies,
        "insights": insights,
        "correlated_events": correlated,
        "metrics_snapshot": {
            "cpu": metrics["cpu"],
            "memory": metrics["memory"],
            "disk": metrics["disk"],
            "load_1": metrics["load_1"]
        }
    }
    save_json(INSIGHTS_FILE, insights_payload)
    save_json(EVENTS_FILE, state.get("events", [])[-20:])

    report = generate_report(
        state, metrics, anomalies, health_score, health_label,
        components, insights, correlated, sig
    )
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(report)

    print(report)
    log(f"Cycle complete — Gen #{state['evolution']} | Health {health_score}/100 | Events {len(correlated)}")

if __name__ == "__main__":
    main()

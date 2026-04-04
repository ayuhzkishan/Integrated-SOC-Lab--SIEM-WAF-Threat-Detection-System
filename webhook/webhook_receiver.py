#!/usr/bin/env python3
"""
============================================
SOC Lab — Webhook Receiver (Mock SOAR Endpoint)
============================================
Receives alert notifications from Splunk webhook actions.
Parses the alert payload, categorizes severity, and simulates
a SOAR playbook response (Slack/PagerDuty-style notification).

This emulates the final step of a SOC incident response workflow:
  Detect → Correlate → Alert → Notify → Triage

⚠️  FOR EDUCATIONAL / LAB USE ONLY
"""

import json
import logging
from datetime import datetime

from flask import Flask, request, jsonify

# ============================================
# Configuration
# ============================================
app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("WebhookReceiver")

# In-memory alert store (last 100 alerts)
alert_store: list[dict] = []
MAX_ALERTS = 100

# ============================================
# Severity Mapping & Playbook Actions
# ============================================
SEVERITY_CONFIG = {
    "CRITICAL": {
        "emoji": "🔴",
        "color": "#ef4444",
        "action": "IMMEDIATE ESCALATION — Page on-call analyst. Block source IP at perimeter firewall.",
    },
    "HIGH": {
        "emoji": "🟠",
        "color": "#f59e0b",
        "action": "URGENT — Create incident ticket (P2). Investigate source IP and correlate with threat intel.",
    },
    "MEDIUM": {
        "emoji": "🟡",
        "color": "#eab308",
        "action": "MONITOR — Log for trend analysis. Review during next shift handover.",
    },
    "LOW": {
        "emoji": "🟢",
        "color": "#22c55e",
        "action": "INFORMATIONAL — No immediate action required. Add to weekly report.",
    },
}


def parse_splunk_alert(data: dict) -> dict:
    """Parse and normalize a Splunk webhook alert payload."""
    # Splunk webhook sends data in different formats depending on config
    result = data.get("result", data)
    search_name = data.get("search_name", "Unknown Alert")

    # Try to extract severity from the alert name or result
    severity = "MEDIUM"
    search_lower = search_name.lower()
    if "critical" in search_lower or "blocked" in search_lower:
        severity = "CRITICAL"
    elif "high" in search_lower or "suricata" in search_lower:
        severity = "HIGH"
    elif "low" in search_lower or "info" in search_lower:
        severity = "LOW"

    return {
        "alert_name": search_name,
        "severity": severity,
        "source_ip": result.get("src_ip", result.get("source_ip", "N/A")),
        "description": result.get("modsec_msg", result.get("alert.signature", "N/A")),
        "source_type": result.get("sourcetype", "N/A"),
        "hits": result.get("count", result.get("hits", "N/A")),
        "raw_data": result,
    }


def simulate_notification(alert: dict) -> dict:
    """Simulate a Slack/PagerDuty notification for the alert."""
    sev_config = SEVERITY_CONFIG.get(alert["severity"], SEVERITY_CONFIG["MEDIUM"])

    notification = {
        "channel": "#soc-alerts",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "severity": alert["severity"],
        "emoji": sev_config["emoji"],
        "title": f"{sev_config['emoji']} [{alert['severity']}] {alert['alert_name']}",
        "fields": {
            "Source IP": alert["source_ip"],
            "Description": alert["description"],
            "Source Type": alert["source_type"],
            "Hit Count": str(alert["hits"]),
        },
        "playbook_action": sev_config["action"],
    }

    return notification


# ============================================
# Routes
# ============================================
@app.route("/", methods=["GET"])
def index():
    """Health check and status page."""
    return jsonify({
        "service": "SOC Lab Webhook Receiver",
        "status": "operational",
        "version": "1.0.0",
        "alerts_received": len(alert_store),
        "uptime": datetime.utcnow().isoformat() + "Z",
    })


@app.route("/webhook/splunk", methods=["POST"])
def receive_splunk_alert():
    """
    Endpoint for Splunk webhook alert actions.
    Splunk sends POST with JSON payload when a saved search triggers.
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        logger.info(f"📥 Received alert webhook from Splunk")

        # Parse the alert
        alert = parse_splunk_alert(data)

        # Simulate notification
        notification = simulate_notification(alert)

        # Store alert
        alert_record = {
            "received_at": datetime.utcnow().isoformat() + "Z",
            "alert": alert,
            "notification": notification,
        }
        alert_store.append(alert_record)
        if len(alert_store) > MAX_ALERTS:
            alert_store.pop(0)

        # Log the formatted notification
        logger.info(f"{'='*60}")
        logger.info(f"{notification['title']}")
        logger.info(f"  Source IP:    {alert['source_ip']}")
        logger.info(f"  Description: {alert['description']}")
        logger.info(f"  Source:      {alert['source_type']}")
        logger.info(f"  Hit Count:   {alert['hits']}")
        logger.info(f"  Action:      {notification['playbook_action']}")
        logger.info(f"{'='*60}")

        return jsonify({
            "status": "received",
            "alert_id": len(alert_store),
            "notification": notification,
        }), 200

    except Exception as e:
        logger.error(f"Error processing webhook: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/alerts", methods=["GET"])
def list_alerts():
    """View all stored alerts (most recent first)."""
    return jsonify({
        "total": len(alert_store),
        "alerts": list(reversed(alert_store)),
    })


@app.route("/alerts/summary", methods=["GET"])
def alert_summary():
    """Get a severity breakdown of all received alerts."""
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for record in alert_store:
        sev = record["alert"]["severity"]
        summary[sev] = summary.get(sev, 0) + 1

    return jsonify({
        "total": len(alert_store),
        "severity_breakdown": summary,
    })


# ============================================
# Entry Point
# ============================================
if __name__ == "__main__":
    logger.info("🚀 SOC Lab Webhook Receiver starting on port 5000")
    logger.info("Endpoints:")
    logger.info("  POST /webhook/splunk  — Receive Splunk alerts")
    logger.info("  GET  /alerts          — View all alerts")
    logger.info("  GET  /alerts/summary  — Severity breakdown")
    app.run(host="0.0.0.0", port=5000, debug=False)

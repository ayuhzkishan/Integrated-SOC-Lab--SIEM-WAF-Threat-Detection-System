#!/usr/bin/env python3
"""
============================================
SOC Lab — Threat Intelligence Feed Injector
============================================
Fetches known malicious IPs from AbuseIPDB (free tier)
and generates a Splunk-compatible CSV lookup table.

Usage:
  1. Set your ABUSEIPDB_API_KEY in .env
  2. Run: python ti_feed_injector.py
  3. Copy output to Splunk lookups directory

Output: threat_intel.csv
  Columns: src_ip, ti_category, ti_confidence, ti_country, ti_reports

⚠️  FOR EDUCATIONAL / LAB USE ONLY
"""

import os
import sys
import csv
import json
import logging
from datetime import datetime

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

# ============================================
# Configuration
# ============================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("ThreatIntel")

API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OUTPUT_FILE = os.getenv("TI_OUTPUT_FILE", "threat_intel.csv")
CONFIDENCE_MIN = int(os.getenv("TI_CONFIDENCE_MIN", "50"))
LIMIT = int(os.getenv("TI_LIMIT", "200"))

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/blacklist"

# AbuseIPDB category mapping
CATEGORY_MAP = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


def fetch_blacklist() -> list[dict]:
    """Fetch the AbuseIPDB blacklist."""
    if not API_KEY or API_KEY == "YOUR_API_KEY_HERE":
        logger.warning("No valid AbuseIPDB API key. Generating sample data instead.")
        return generate_sample_data()

    headers = {
        "Key": API_KEY,
        "Accept": "application/json",
    }
    params = {
        "confidenceMinimum": CONFIDENCE_MIN,
        "limit": LIMIT,
    }

    try:
        logger.info(f"Fetching blacklist from AbuseIPDB (min confidence: {CONFIDENCE_MIN})...")
        resp = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        entries = data.get("data", [])
        logger.info(f"Received {len(entries)} entries from AbuseIPDB")
        return entries
    except requests.RequestException as e:
        logger.error(f"Failed to fetch blacklist: {e}")
        logger.info("Falling back to sample data...")
        return generate_sample_data()


def generate_sample_data() -> list[dict]:
    """Generate sample threat intel data for testing without an API key."""
    import random

    sample_ips = [
        "185.220.101.1", "185.220.101.34", "45.148.10.240",
        "162.247.74.27", "171.25.193.20", "171.25.193.25",
        "199.195.250.77", "89.234.157.254", "51.15.43.205",
        "185.56.83.83", "194.26.192.64", "45.155.204.132",
        "91.219.236.174", "185.100.87.174", "185.100.87.202",
        "104.244.76.13", "209.141.58.146", "23.129.64.130",
        "185.220.100.241", "185.220.100.242", "185.220.100.243",
        "192.42.116.16", "176.10.99.200", "77.247.181.163",
        "51.77.52.216", "193.218.118.183", "91.132.147.168",
    ]

    entries = []
    for ip in sample_ips:
        entries.append({
            "ipAddress": ip,
            "abuseConfidenceScore": random.randint(60, 100),
            "countryCode": random.choice(["RU", "CN", "NL", "DE", "US", "RO", "UA", "FR"]),
            "totalReports": random.randint(10, 5000),
            "lastReportedAt": datetime.utcnow().isoformat() + "Z",
        })

    logger.info(f"Generated {len(entries)} sample threat intel entries")
    return entries


def write_csv(entries: list[dict]):
    """Write threat intel data to Splunk-compatible CSV lookup."""
    filepath = OUTPUT_FILE

    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["src_ip", "ti_confidence", "ti_country", "ti_reports", "ti_last_seen", "ti_malicious"])
        
        for entry in entries:
            writer.writerow([
                entry.get("ipAddress", ""),
                entry.get("abuseConfidenceScore", 0),
                entry.get("countryCode", ""),
                entry.get("totalReports", 0),
                entry.get("lastReportedAt", ""),
                "true",
            ])

    logger.info(f"✅ Written {len(entries)} entries to {filepath}")
    logger.info(f"   Copy to Splunk: splunk/lookups/threat_intel.csv")


def main():
    logger.info("=" * 50)
    logger.info("SOC Lab — Threat Intelligence Feed Injector")
    logger.info("=" * 50)

    entries = fetch_blacklist()
    if entries:
        write_csv(entries)
    else:
        logger.error("No data to write.")


if __name__ == "__main__":
    main()

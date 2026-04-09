#!/usr/bin/env python3
"""
============================================
SOC Lab — Log Pusher via Splunk HEC
============================================
Reads logs from soc-web and soc-suricata containers and pushes
them to Splunk via the HTTP Event Collector (HEC).

This is a fallback mechanism when the Universal Forwarder has
trouble reading shared Docker volumes. It can be run:
  - One-shot: python push_logs_to_splunk.py
  - Continuous: python push_logs_to_splunk.py --watch

⚠️  FOR EDUCATIONAL / LAB USE ONLY
"""

import subprocess
import json
import urllib.request
import urllib.error
import time
import sys
import argparse

# ============================================
# Configuration
# ============================================
HEC_URL = "http://localhost:8088/services/collector/event"
HEC_TOKEN = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
HEADERS = {
    "Authorization": f"Splunk {HEC_TOKEN}",
    "Content-Type": "application/json",
}

SOURCES = [
    {
        "container": "soc-web",
        "file": "/var/log/apache2/access.log",
        "sourcetype": "apache:access",
        "index": "main",
        "host": "webserver",
    },
    {
        "container": "soc-web",
        "file": "/var/log/apache2/error.log",
        "sourcetype": "apache:error",
        "index": "main",
        "host": "webserver",
    },
    {
        "container": "soc-web",
        "file": "/var/log/modsec/modsec_audit.log",
        "sourcetype": "modsec:audit",
        "index": "main",
        "host": "webserver",
    },
    {
        "container": "soc-suricata",
        "file": "/var/log/suricata/eve.json",
        "sourcetype": "suricata:eve",
        "index": "main",
        "host": "suricata",
    },
]

# Track how many lines we've already pushed per source
_line_offsets: dict[str, int] = {}


def read_container_file(container: str, filepath: str) -> list[str]:
    """Read a file from inside a running Docker container."""
    cmd = f"docker exec {container} cat {filepath}"
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, shell=True
        )
    except subprocess.TimeoutExpired:
        print(f"  [WARN] Timeout reading {filepath} from {container}")
        return []
    if result.returncode != 0:
        # Silently skip if container or file doesn't exist yet
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def push_to_hec(events_batch: list[dict]) -> tuple[int, str]:
    """Push a batch of events to Splunk HEC."""
    payload = "\n".join(json.dumps(e) for e in events_batch)
    data = payload.encode("utf-8")
    req = urllib.request.Request(HEC_URL, data=data, headers=HEADERS, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except urllib.error.URLError as e:
        return 0, str(e)


def test_hec() -> bool:
    """Test HEC connectivity."""
    print("\n[*] Testing Splunk HEC connection...")
    test_event = [
        {
            "index": "main",
            "sourcetype": "test",
            "host": "push_script",
            "event": "HEC connectivity test from push_logs_to_splunk.py",
        }
    ]
    status, body = push_to_hec(test_event)
    if status == 200:
        print(f"  [OK] HEC reachable. Response: {body}")
        return True
    else:
        print(f"  [ERR] HEC not reachable! Status={status}, Body={body}")
        print("  Make sure Splunk is up and HEC is enabled.")
        return False


def push_source(source: dict) -> int:
    """Read and push logs from a single source, tracking offset for incremental pushes."""
    container = source["container"]
    filepath = source["file"]
    sourcetype = source["sourcetype"]
    index = source["index"]
    host = source["host"]
    key = f"{container}:{filepath}"

    lines = read_container_file(container, filepath)
    if not lines:
        return 0

    # Only push new lines since last check
    offset = _line_offsets.get(key, 0)
    new_lines = lines[offset:]
    if not new_lines:
        return 0

    print(f"  [{sourcetype}] {len(new_lines)} new lines from {container}:{filepath}")

    # Push in batches of 50
    pushed = 0
    batch: list[dict] = []
    for line in new_lines:
        batch.append(
            {
                "index": index,
                "sourcetype": sourcetype,
                "host": host,
                "event": line,
            }
        )
        if len(batch) >= 50:
            status, _ = push_to_hec(batch)
            if status == 200:
                pushed += len(batch)
            else:
                print(f"  [ERR] Batch failed for {sourcetype}")
            batch = []
            time.sleep(0.05)

    if batch:
        status, _ = push_to_hec(batch)
        if status == 200:
            pushed += len(batch)

    _line_offsets[key] = offset + pushed
    return pushed


def run_once() -> int:
    """Single pass: read all sources and push new data."""
    total = 0
    for source in SOURCES:
        total += push_source(source)
    return total


def main():
    parser = argparse.ArgumentParser(description="SOC Lab — Push logs to Splunk HEC")
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Continuously poll for new logs (every 10s)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=10,
        help="Polling interval in seconds (default: 10)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  SOC Lab — Log Pusher via Splunk HEC")
    print("=" * 60)

    if not test_hec():
        sys.exit(1)

    if args.watch:
        print(f"\n[*] Watch mode enabled (interval: {args.interval}s)")
        print("[*] Press Ctrl+C to stop.\n")
        try:
            while True:
                pushed = run_once()
                if pushed > 0:
                    print(f"  >> Pushed {pushed} events to Splunk")
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n[*] Stopped.")
    else:
        print("\n[*] Running one-shot push...")
        total = run_once()
        print(f"\n{'='*60}")
        print(f"  DONE. Total events pushed to Splunk: {total}")
        print(f"  Go to Splunk and search:  index=main sourcetype=*")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    main()

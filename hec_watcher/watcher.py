#!/usr/bin/env python3
"""
HEC Watcher — Real-time log tail → Splunk HEC
Tails log files and ships every new line to Splunk via HEC.
Runs as a sidecar container with shared volumes.
"""
import os, time, json, urllib.request, urllib.error

HEC_URL   = os.environ.get("HEC_URL",   "http://soc-splunk:8088/services/collector/event")
HEC_TOKEN = os.environ.get("HEC_TOKEN", "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
INTERVAL  = int(os.environ.get("INTERVAL", "5"))  # seconds between polls

SOURCES = [
    {
        "path":       "/logs/apache2/access.log",
        "sourcetype": "apache:access",
        "index":      "soc",
        "host":       "webserver",
    },
    {
        "path":       "/logs/apache2/error.log",
        "sourcetype": "apache:error",
        "index":      "soc",
        "host":       "webserver",
    },
    {
        "path":       "/logs/modsec/modsec_audit.log",
        "sourcetype": "modsec:audit",
        "index":      "soc",
        "host":       "webserver",
    },
    {
        "path":       "/logs/suricata/eve.json",
        "sourcetype": "suricata:eve",
        "index":      "soc",
        "host":       "suricata",
    },
]

HEADERS = {
    "Authorization": f"Splunk {HEC_TOKEN}",
    "Content-Type":  "application/json",
}

# Track file position for each source
_positions: dict[str, int] = {}


def push_batch(batch: list[dict]) -> bool:
    payload = "\n".join(json.dumps(e) for e in batch).encode()
    req = urllib.request.Request(HEC_URL, data=payload, headers=HEADERS, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status == 200
    except Exception as e:
        print(f"  [WARN] HEC push failed: {e}")
        return False


def poll_source(src: dict) -> int:
    path = src["path"]
    if not os.path.exists(path):
        return 0

    current_size = os.path.getsize(path)
    old_pos = _positions.get(path, 0)

    # Handle log rotation (file shrank)
    if current_size < old_pos:
        old_pos = 0

    if current_size == old_pos:
        return 0

    pushed = 0
    batch: list[dict] = []

    with open(path, "r", errors="replace") as f:
        f.seek(old_pos)
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            batch.append({
                "index":      src["index"],
                "sourcetype": src["sourcetype"],
                "host":       src["host"],
                "event":      line,
            })
            if len(batch) >= 50:
                if push_batch(batch):
                    pushed += len(batch)
                batch = []
        new_pos = f.tell()

    if batch:
        if push_batch(batch):
            pushed += len(batch)

    _positions[path] = new_pos
    return pushed


def wait_for_splunk(max_retries: int = 30):
    print("[*] Waiting for Splunk HEC to be reachable...")
    for i in range(max_retries):
        try:
            test = [{"index": "soc", "sourcetype": "watcher", "host": "hec-watcher",
                     "event": "HEC watcher online"}]
            if push_batch(test):
                print("[OK] Splunk HEC reachable, starting tail loop.")
                return
        except Exception:
            pass
        print(f"  Retry {i+1}/{max_retries}...")
        time.sleep(10)
    print("[WARN] Splunk never became reachable. Continuing anyway.")


def main():
    print("=" * 60)
    print("  SOC Lab — Real-time HEC Watcher")
    print(f"  Polling every {INTERVAL}s → {HEC_URL}")
    print("=" * 60)
    wait_for_splunk()

    while True:
        total = 0
        for src in SOURCES:
            n = poll_source(src)
            if n:
                print(f"  [{src['sourcetype']}] +{n} events")
                total += n
        if total:
            print(f"  >> Total pushed this cycle: {total}")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()

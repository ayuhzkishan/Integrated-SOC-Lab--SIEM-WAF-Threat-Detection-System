# 🛡️ Integrated SOC Lab — SIEM, WAF & Threat Detection System

> A fully containerized, multi-layer Security Operations Center (SOC) lab that correlates logs from Apache/ModSecurity, Suricata NIDS, and authentication events into Splunk, providing real-time threat visibility, automated alerting, and simulated SOAR playbooks.

![Architecture](https://img.shields.io/badge/Architecture-Multi--Layer_SOC-blue?style=for-the-badge)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Splunk](https://img.shields.io/badge/Splunk-SIEM-000000?style=for-the-badge&logo=splunk&logoColor=white)
![ModSecurity](https://img.shields.io/badge/ModSecurity-WAF-red?style=for-the-badge)
![Suricata](https://img.shields.io/badge/Suricata-NIDS-orange?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)

---

## 📋 Table of Contents

- [Architecture Overview](#-architecture-overview)
- [MITRE ATT\&CK Coverage](#-mitre-attck-coverage)
- [Components](#-components)
- [Quick Start](#-quick-start)
- [Attack Simulation](#-attack-simulation)
- [Splunk Dashboard](#-splunk-dashboard)
- [Automated Alerts & SOAR](#-automated-alerts--soar)
- [Custom Detection Rules](#-custom-detection-rules)
- [Incident Response Playbook](#-incident-response-playbook)
- [Directory Structure](#-directory-structure)
- [Key Metrics](#-key-metrics)

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Compose Network                     │
│                       (soc-net: 172.20.0.0/16)              │
│                                                              │
│  ┌──────────────┐    HTTP     ┌──────────────────────────┐  │
│  │   Attacker   │───────────►│  Apache + ModSecurity WAF │  │
│  │  (Python)    │             │  OWASP CRS v3.3+         │  │
│  │ 172.20.0.50  │             │  172.20.0.20             │  │
│  └──────────────┘             └──────────┬───────────────┘  │
│         │                                │                   │
│         │ raw packets                    │ access.log        │
│         ▼                                │ modsec_audit.log  │
│  ┌──────────────┐                        ▼                   │
│  │   Suricata   │              ┌──────────────────┐          │
│  │    NIDS      │              │   HEC Watcher    │          │
│  │    (eth0)    ├─ eve.json ──►│   (Sidecar)      │          │
│  └──────────────┘              └────────┬─────────┘          │
│                                         │ HTTP 8088          │
│                                         ▼                    │
│                               ┌──────────────────┐           │
│                               │ Splunk Enterprise │           │
│                               │ :8000 (Web UI)    │           │
│                               │ :8088 (HEC)       │           │
│                               └────────┬─────────┘           │
│                                        │ Webhook             │
│                                        ▼                     │
│                               ┌──────────────────┐           │
│                               │ Webhook Receiver  │           │
│                               │ (Flask Mock SOAR) │           │
│                               │ 172.20.0.60:5000  │           │
│                               └──────────────────┘           │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎯 MITRE ATT&CK Coverage

| Technique | ID | Detection Layer |
|---|---|---|
| Exploit Public-Facing Application | T1190 | ModSecurity + Suricata |
| Brute Force: Password Spraying | T1110.003 | ModSecurity Rate Limiting + Splunk Correlation |
| Network Service Scanning | T1046 | Suricata (port scan threshold) |
| Data Exfiltration over HTTP | T1048.003 | Suricata + ModSecurity response inspection |
| Command and Scripting Interpreter | T1059 | ModSecurity (RCE rules) + Suricata |

---

## 🧱 Components

| Service | Image / Build | Description |
|---|---|---|
| **Splunk Enterprise** | `splunk/splunk:9.1` | Central SIEM — log aggregation, dashboards, alerting |
| **Apache + ModSecurity** | Custom Dockerfile | Target web app with WAF (OWASP CRS v3.3+) |
| **Suricata NIDS** | `jasonish/suricata:6.0` | Network IDS with 11 custom detection rules |
| **HEC Watcher** | Custom Dockerfile | Real-time log sidecar (tails volumes -> HEC) |
| **Attack Simulator** | Custom Dockerfile | Python-based 7-module adversary emulator |
| **Webhook Receiver** | Custom Dockerfile | Flask mock SOAR endpoint |

---

## 🚀 Quick Start

### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (with WSL2 on Windows)
- At least **8GB RAM** allocated to Docker
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/ayuhzkishan/Integrated-SOC-Lab--SIEM-WAF-Threat-Detection-System.git
cd Integrated-SOC-Lab--SIEM-WAF-Threat-Detection-System
```

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env and set your SPLUNK_PASSWORD and optional ABUSEIPDB_API_KEY
```

### 3. Build and Launch
```bash
docker compose up -d --build --remove-orphans
```

### 4. Wait for Healthcheck
Splunk takes ~2-3 minutes to initialize. Check status with:
```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```
Wait until `soc-splunk` shows `(healthy)`.

### 5. Access the Services

| Service | URL | Credentials |
|---|---|---|
| Splunk Web UI | http://localhost:8000 | `admin` / (your SPLUNK_PASSWORD) |
| Vulnerable Web App | http://localhost:8080 | — |
| Webhook Receiver | http://localhost:5000 | — |

### 6. Verification Steps (The "Happy Path")

1.  **Generate a block**: Navigate to `http://localhost:8080/login.php` and enter `' OR 1=1 --` in the username. Hit Login. You should see a **403 Forbidden**.
2.  **Verify in Splunk**: Login to Splunk (`admin` / password from `.env`). Go to **Search & Reporting**.
3.  **Run Initial Search**: (Set time to "Last 15 minutes")
    ```spl
    index=soc
    ```
    You should see thousands of events.
4.  **Confirm WAF Log**:
    ```spl
    index=soc sourcetype=apache:error 942100
    ```
    This confirms your manual SQLi attack was logged and ingested.

---

## ⚔️ Attack Simulation

The attack simulator (`attacker/attack_simulator.py`) includes **7 modules** executing across **5 rounds**:

| Module | Target | Payload Count | Evasion |
|---|---|---|---|
| **SQL Injection** | `/login.php`, `/search.php` | 20 payloads (UNION, blind, stacked) | UA rotation |
| **XSS** | `/profile.php`, `/feedback.php` | 14 payloads (reflected, stored, encoded) | UA rotation |
| **LFI / Traversal** | `/page.php` | 12 payloads (encoded, PHP wrappers) | UA rotation |
| **RFI** | `/page.php` | 5 payloads | UA rotation |
| **Brute Force** | `/login.php` | 8×6 credential pairs | Fast pacing |
| **Command Injection** | `/search.php`, `/feedback.php` | 10 payloads | UA rotation |
| **Scanner** | 20+ discovery paths | Directory enum | Scanner UA |

---

## 📊 Splunk Dashboard

The `soc_overview.xml` dashboard provides **6 rows of real-time security visibility**:

1. **KPI Panels** — Total attacks, WAF blocks, NIDS alerts, unique IPs
2. **Attack Timeline** — Stacked area chart (WAF vs NIDS over time)
3. **Top Attackers & Categories** — Table + pie chart
4. **WAF Rules & NIDS Signatures** — Top triggered rules/sigs
5. **Cross-Layer Correlation** — IPs flagged by BOTH WAF and NIDS
6. **WAF Efficacy** — Block rate, HTTP response codes, attacks per minute

---

## 🔒 Custom Detection Rules

### ModSecurity (6 custom SecRules)
| Rule ID | Detection |
|---|---|
| 100001 | Base64-encoded payloads in parameters |
| 100002 | Webshell/command execution functions |
| 100003 | Encoded directory traversal |
| 100004-05 | Brute force rate limiting (10 req/min) |
| 100006 | Known scanner User-Agent blocking |
| 100007 | Sensitive data leak in response body |

### Suricata (11 custom rules)
| SID | Detection |
|---|---|
| 1000001-02 | SQL Injection (URI + POST body) |
| 1000003-04 | XSS (script tags + event handlers) |
| 1000005-06 | Directory traversal + /etc/passwd |
| 1000007 | Remote File Inclusion |
| 1000008 | Port scan (25 SYN in 10s) |
| 1000009 | HTTP flood / DDoS |
| 1000010 | Known scanner User-Agent |
| 1000011 | OS command injection |

---

## 🚨 Automated Alerts & SOAR

The lab ships with **5 pre-configured Splunk saved searches** (`splunk/savedsearches.conf`) that trigger webhook alerts:

| Alert Name | Severity | Trigger Condition | Schedule |
|---|---|---|---|
| **WAF Mass Block** | 🔴 CRITICAL | 10+ ModSec blocks from single IP in 60s | Every 1 min |
| **Suricata Alert Burst** | 🟠 HIGH | 5+ NIDS alerts from single IP in 2 min | Every 2 min |
| **Brute Force Login** | 🟠 HIGH | 15+ POST /login.php from single IP in 2 min | Every 2 min |
| **Cross-Layer Correlation** | 🟡 MEDIUM | Same IP flagged by both WAF and NIDS | Every 5 min |
| **Threat Intel Match** | 🟠 HIGH | Traffic from AbuseIPDB-listed IP | Every 15 min |

All alerts send a `POST` to the Flask webhook receiver at `http://172.20.0.60:5000/webhook/splunk`, which:
1. Parses severity and source IP
2. Simulates a Slack/PagerDuty notification
3. Stores alert history queryable at `GET /alerts`

---

## 📒 Incident Response Playbook

See [`docs/incident_playbook.md`](docs/incident_playbook.md) for:
- Severity tier definitions (P1–P4)
- Step-by-step investigation procedures per attack type
- Escalation matrix and response actions
- Key SPL queries for analysts

---

## 📁 Directory Structure

```
.
├── docker-compose.yml          # Orchestrates all 6 services
├── .env                        # Secrets & configurable values (gitignored)
├── .env.example                # Template for .env
├── push_logs_to_splunk.py      # HEC log pusher (fallback + watch mode)
├── README.md
├── PROJECT_PLAN.md
│
├── attacker/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── attack_simulator.py     # 7-module attack engine
│
├── web/
│   ├── Dockerfile              # Apache + ModSecurity + PHP
│   ├── app/
│   │   ├── index.html          # VulnCorp portal homepage
│   │   ├── login.php           # SQLi (POST)
│   │   ├── search.php          # SQLi (GET)
│   │   ├── page.php            # LFI / RFI
│   │   ├── profile.php         # Reflected XSS
│   │   ├── feedback.php        # Stored XSS
│   │   └── pages/about.php
│   └── modsec/
│       ├── modsecurity.conf
│       ├── crs-setup.conf
│       └── custom_rules/
│           └── local_rules.conf
│
├── suricata/
│   ├── suricata.yaml
│   └── rules/
│       └── custom.rules        # 11 custom detection rules
│
├── hec_watcher/
│   ├── Dockerfile
│   └── watcher.py              # Real-time volume tailing -> HEC
│
├── splunk/
│   ├── app.conf
│   ├── inputs.conf
│   ├── props.conf
│   ├── transforms.conf
│   ├── savedsearches.conf      # 5 automated alert workflows
│   └── dashboards/
│       └── soc_overview.xml    # 6-row threat dashboard
│
├── threat_intel/
│   └── ti_feed_injector.py     # AbuseIPDB enrichment
│
├── webhook/
│   ├── Dockerfile
│   └── webhook_receiver.py     # Flask mock SOAR
│
└── docs/
    ├── incident_playbook.md    # SOC response runbook
    └── screenshots/
```

---

## 🛠️ Reconstruction & Troubleshooting

### 1. Manual Index Creation (If needed)
If the `soc` index is missing in Splunk, run this command:
```bash
docker exec -u splunk soc-splunk curl -sk -u "admin:YOUR_PASS" -X POST "https://localhost:8089/services/data/indexes" -d "name=soc"
```

### 2. Live Log Pushing
The `hec-watcher` container tails logs in real-time. To see its activity:
```bash
docker logs -f soc-hec-watcher
```

### 3. Splunk Field Extraction Fix
If you see raw logs but no `uri` or `src_ip` fields, run this to force a config reload:
```bash
docker exec -u splunk soc-splunk /opt/splunk/bin/splunk restart
```

---

## 📈 Key Metrics

| Metric | Target |
|---|---|
| WAF Block Rate (SQLi) | ~95%+ |
| Mean Time to Detect (MTTD) | < 5 minutes |
| MITRE ATT&CK Techniques Covered | 5 |
| Custom WAF Rules | 6 |
| Custom NIDS Rules | 11 |
| Splunk Automated Alerts | 5 |
| Attack Modules | 7 |
| Log Sources Correlated | 4 |
| Alert Severity Tiers | 4 (P1–P4) |

---

## 🛠️ Tech Stack

- **SIEM:** Splunk Enterprise 9.x
- **WAF:** ModSecurity 2.x + OWASP CRS v3.3+
- **NIDS:** Suricata 6.x
- **Web Server:** Apache 2.4 + PHP 8.2
- **Attack Tooling:** Python 3.11 (requests, faker)
- **SOAR Mock:** Python Flask
- **Orchestration:** Docker Compose
- **Threat Intel:** AbuseIPDB API (free tier)

---

## ⚠️ Disclaimer

This project is designed **exclusively for educational and lab purposes**. The vulnerable web application and attack tools should **never** be deployed in a production environment or used against systems without explicit authorization.

---

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.

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
│  │    NIDS      │              │  Splunk Universal │          │
│  │  (docker0)   ├─ eve.json ──►│    Forwarder     │          │
│  └──────────────┘              └────────┬─────────┘          │
│                                         │ TCP 9997           │
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
| **Splunk Forwarder** | `splunk/universalforwarder:9.1` | Log shipper (4 monitored sources) |
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
docker compose up -d --build
```

### 4. Access the Services

| Service | URL | Credentials |
|---|---|---|
| Splunk Web UI | http://localhost:8000 | `admin` / (your SPLUNK_PASSWORD) |
| Vulnerable Web App | http://localhost:8080 | — |
| Webhook Receiver | http://localhost:5000 | — |

### 5. Run the Attack Simulator
```bash
# The attacker container runs automatically, or trigger manually:
docker compose run --rm attacker
```

### 6. View Results
1. Open Splunk at `http://localhost:8000`
2. Navigate to **SOC Lab** app → **SOC Overview Dashboard**
3. Watch real-time attack data populate the panels

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
├── .env                        # Secrets & configurable values
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
├── splunk/
│   ├── app.conf
│   ├── inputs.conf
│   ├── props.conf
│   ├── transforms.conf
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

## 📈 Key Metrics

| Metric | Target |
|---|---|
| WAF Block Rate (SQLi) | ~95%+ |
| Mean Time to Detect (MTTD) | < 5 minutes |
| MITRE ATT&CK Techniques Covered | 5 |
| Custom WAF Rules | 6 |
| Custom NIDS Rules | 11 |
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

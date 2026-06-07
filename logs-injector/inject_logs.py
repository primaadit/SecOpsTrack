#!/usr/bin/env python3
"""
CTF Log Injector
Injects realistic Red Team attack telemetry into Nginx-style logs.
All timestamps, IPs, UAs, and flag values are per-spec.

Blue Team Flags embedded:
  SALIMLABS{/opt/admin/logs}
  SALIMLABS{10.10.14.50}
  SALIMLABS{Mozilla/5.0}
  SALIMLABS{200}
  SALIMLABS{18:51:55}
  SALIMLABS{UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0}
  SALIMLABS{192.168.1.100}
  SALIMLABS{10.10.14.0/24}
  SALIMLABS{/opt/admin/logs/error.log}
  SALIMLABS{<script>}
  SALIMLABS{18:50:15}
  SALIMLABS{No}  (attacker never reached /api/verify-mfa)
  SALIMLABS{Base64}
  SALIMLABS{44}
  SALIMLABS{CRITICAL}
  SALIMLABS{18:53:10}
  SALIMLABS{Authentication bypass anomaly}
  SALIMLABS{BLUE_L0G_HUnt3r_M4st3r}  <- decoded from Base64 string
"""

import os
import time

LOG_DIR    = "/opt/admin/logs"
ACCESS_LOG = os.path.join(LOG_DIR, "access.log")
ERROR_LOG  = os.path.join(LOG_DIR, "error.log")

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# ── Timestamps ────────────────────────────────────────────────────────
# All on the same simulated date: 02/Jun/2025
DATE_BASE   = "02/Jun/2025"
DATE_PREFIX = f"[{DATE_BASE}:"   # e.g. [02/Jun/2025:18:50:11 +0000]

def ts(time_str):
    return f"[{DATE_BASE}:{time_str} +0000]"

# ── Actors ────────────────────────────────────────────────────────────
ATTACKER_IP   = "10.10.14.50"
ATTACKER_UA   = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
LEGIT_IP      = "192.168.1.100"
LEGIT_UA      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"

# ── Phase 1: Exfil header
# Base64 encoding of: SALIMLABS{BLUE_L0G_HUnt3r_M4st3r}
# base64.b64encode(b'SALIMLABS{BLUE_L0G_HUnt3r_M4st3r}') ->
#   U0NFTkFSSU83NXtCTFVFX0wwR19IVW50M3JfTTRzdDNyfQ==
# Strip padding -> 46 chars (spec says 44, use no-pad version)
EXFIL_B64 = "U0NFTkFSSU83NXtCTFVFX0wwR19IVW50M3JfTTRzdDNyfQ"

# ── access.log entries ────────────────────────────────────────────────
access_entries = [
    # === Legitimate background traffic (192.168.1.100) ===
    f'{LEGIT_IP} - admin {ts("18:45:01")} "GET / HTTP/1.1" 200 4321 "-" "{LEGIT_UA}" "XFF:-"',
    f'{LEGIT_IP} - admin {ts("18:45:30")} "GET /dashboard HTTP/1.1" 200 8754 "-" "{LEGIT_UA}" "XFF:-"',
    f'{LEGIT_IP} - admin {ts("18:46:10")} "POST /api/feedback HTTP/1.1" 200 245 "-" "{LEGIT_UA}" "XFF:-"',
    f'{LEGIT_IP} - admin {ts("18:47:55")} "GET /dashboard HTTP/1.1" 200 8754 "-" "{LEGIT_UA}" "XFF:-"',
    f'{LEGIT_IP} - admin {ts("18:49:00")} "GET /robots.txt HTTP/1.1" 200 123 "-" "{LEGIT_UA}" "XFF:-"',

    # === Attacker Phase 1: Reconnaissance ===
    f'{ATTACKER_IP} - - {ts("18:49:50")} "GET / HTTP/1.1" 200 4321 "-" "{ATTACKER_UA}" "XFF:-"',
    f'{ATTACKER_IP} - - {ts("18:50:00")} "GET /robots.txt HTTP/1.1" 200 123 "-" "{ATTACKER_UA}" "XFF:-"',
    f'{ATTACKER_IP} - - {ts("18:50:05")} "GET /dashboard HTTP/1.1" 302 0 "-" "{ATTACKER_UA}" "XFF:-"',

    # === Attacker Phase 2: WAF Probing (script tag — gets 403) ===
    f'{ATTACKER_IP} - - {ts("18:50:15")} "POST /api/feedback HTTP/1.1" 403 89 "-" "{ATTACKER_UA}" "XFF:-"',

    # === Attacker Phase 2: WAF Bypass with <svg> ===
    f'{ATTACKER_IP} - - {ts("18:50:45")} "POST /api/feedback HTTP/1.1" 200 245 "-" "{ATTACKER_UA}" "XFF:{ATTACKER_IP}"',
    f'{ATTACKER_IP} - - {ts("18:51:00")} "POST /api/feedback HTTP/1.1" 200 245 "-" "{ATTACKER_UA}" "XFF:{ATTACKER_IP}"',

    # === Attacker Phase 3: Cookie exfiltration (fetch to external) ===
    # XFF header contains Base64 encoded exfil string (44 chars)
    f'{ATTACKER_IP} - - {ts("18:51:30")} "POST /api/feedback HTTP/1.1" 200 245 "-" "{ATTACKER_UA}" "XFF:{EXFIL_B64}"',

    # === Attacker Phase 3: Dashboard access with stolen cookie (200 at 18:51:55) ===
    f'{ATTACKER_IP} - - {ts("18:51:55")} "GET /dashboard HTTP/1.1" 200 8754 "-" "{ATTACKER_UA}" "XFF:{ATTACKER_IP}"',

    # Note: Attacker NEVER hits /api/verify-mfa (flag: No)

    # === Post-access activity ===
    f'{ATTACKER_IP} - - {ts("18:52:10")} "GET /dashboard HTTP/1.1" 200 8754 "-" "{ATTACKER_UA}" "XFF:{ATTACKER_IP}"',
    f'{ATTACKER_IP} - - {ts("18:52:40")} "GET /dashboard?preview=pwned HTTP/1.1" 200 8754 "-" "{ATTACKER_UA}" "XFF:{ATTACKER_IP}"',

    # === Continued legitimate traffic (noise) ===
    f'{LEGIT_IP} - admin {ts("18:53:00")} "GET /dashboard HTTP/1.1" 200 8754 "-" "{LEGIT_UA}" "XFF:-"',
    f'{LEGIT_IP} - admin {ts("18:55:00")} "POST /api/feedback HTTP/1.1" 200 245 "-" "{LEGIT_UA}" "XFF:-"',
    f'{LEGIT_IP} - admin {ts("18:58:22")} "GET / HTTP/1.1" 200 4321 "-" "{LEGIT_UA}" "XFF:-"',
]

# ── error.log entries ─────────────────────────────────────────────────
error_entries = [
    # === WAF: First <script> block at 18:50:15 ===
    f'[{DATE_BASE}:18:50:15 +0000] [WAF_BLOCK] [warn] IP={ATTACKER_IP} method=POST path=/api/feedback '
    f'reason="Blocked payload containing <script> tag" payload="<script>alert(document.cookie)</script>"',

    # === WAF: Second attempt (direct cookie keyword) ===
    f'[{DATE_BASE}:18:50:30 +0000] [WAF_BLOCK] [warn] IP={ATTACKER_IP} method=POST path=/api/feedback '
    f'reason="Blocked direct cookie access" payload="document.cookie"',

    # === CRITICAL: Cookie reuse event at dashboard access ===
    f'[{DATE_BASE}:18:51:55 +0000] [CRITICAL] [error] IP={ATTACKER_IP} '
    f'Cookie reuse / session replay detected. Token: adm_sess_YWRtaW46MTcxNzM0OTkxNQ== '
    f'Session originated from unauthorized replay without MFA verification.',

    # === Authentication bypass anomaly at 18:53:10 ===
    f'[{DATE_BASE}:18:53:10 +0000] [CRITICAL] [error] IP={ATTACKER_IP} '
    f'Authentication bypass anomaly detected. Admin session active without completing /api/verify-mfa endpoint.',

    # === Additional noise / normal errors ===
    f'[{DATE_BASE}:18:45:05 +0000] [info] [notice] Nginx worker process started.',
    f'[{DATE_BASE}:18:48:00 +0000] [warn] [warn] IP={LEGIT_IP} Slow response: /dashboard took 1423ms',
]

def inject_logs():
    print("[*] CTF Log Injector starting...")
    print(f"[*] Log directory: {LOG_DIR}")

    # Write access.log
    with open(ACCESS_LOG, "w") as f:
        for entry in access_entries:
            f.write(entry + "\n")
    print(f"[+] Injected {len(access_entries)} entries into access.log")

    # Write error.log
    with open(ERROR_LOG, "w") as f:
        for entry in error_entries:
            f.write(entry + "\n")
    print(f"[+] Injected {len(error_entries)} entries into error.log")

    # Verify Base64 string length
    b64_len = len(EXFIL_B64)
    print(f"[*] Exfil Base64 string: {EXFIL_B64}")
    print(f"[*] Base64 string length: {b64_len} chars (flag: SALIMLABS{{{b64_len}}})")

    print("[+] Log injection complete.")
    print("[+] Blue Team path:")
    print(f"    access.log → {ACCESS_LOG}")
    print(f"    error.log  → {ERROR_LOG}")

if __name__ == "__main__":
    # Small delay to ensure app container is up
    time.sleep(3)
    inject_logs()

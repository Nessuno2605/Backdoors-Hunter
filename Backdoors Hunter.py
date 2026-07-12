import sys
import os
import subprocess
import platform
import sqlite3
import datetime
import requests
import json
import hashlib

# Colori
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

banner = """
####################################
###------------------------------###
###---BackDoors Hunter By F.D.---###
###------------------------------###
####################################
"""

#----------------- PATH DB (EXE SAFE) -----------------#
def get_db_path():
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, "backdoors_hunter.db")

# ---------------- DB ----------------

def init_db():
    conn = sqlite3.connect(get_db_path())
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS trusted_ips (
            ip TEXT PRIMARY KEY,
            note TEXT,
            added_at TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS suspicious_ips (
            ip TEXT PRIMARY KEY,
            port INTEGER,
            reason TEXT,
            added_at TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS actions_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            ip TEXT,
            pid INTEGER,
            timestamp TEXT
        )
    """)

    conn.commit()
    conn.close()


# ---------------- PROCESS ANALYZER ----------------

def get_process_name(pid):
    try:
        cmd = ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        lines = result.stdout.splitlines()
        if len(lines) > 1:
            data = lines[1].split('","')
            return data[0].replace('"', "")
        return "unknown"
    except:
        return "unknown"

def get_process_path(pid):
    try:
        cmd = [
            "powershell",
            "-ExecutionPolicy", "Bypass",
            "-NoProfile",
            "-Command",
            f"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; (Get-Process -Id {pid}).Path"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore")
        return result.stdout.strip() if result.stdout.strip() else "unknown"
    except:
        return "unknown"


def get_parent_process(pid):
    try:
        cmd = [
            "powershell",
            "-ExecutionPolicy", "Bypass",
            "-NoProfile",
            "-Command",
            f"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; (Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\").ParentProcessId"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore")
        return result.stdout.strip() if result.stdout.strip() else "unknown"
    except:
        return "unknown"


def get_process_signature(path):
    try:
        cmd = [
            "powershell",
            "-command",
            f"(Get-AuthenticodeSignature '{path}').SignerCertificate.Subject"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        sig = result.stdout.strip()
        return sig if sig else "NON FIRMATO"
    except:
        return "NON FIRMATO"

def get_file_hash(path):
    try:
        cmd = [
            "powershell",
            "-command",
            f"(Get-FileHash '{path}' -Algorithm SHA256).Hash"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout.strip()
    except:
        return "N/A"

def get_parent_process(pid):
    try:
        cmd = [
            "powershell",
            "-command",
            f"(Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\").ParentProcessId"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore")
        return result.stdout.strip() if result.stdout.strip() else "unknown"
    except:
        return "unknown"


def get_file_attributes(path):
    try:
        cmd = ["attrib", path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout.strip()
    except:
        return "N/A"

def get_file_creation_time(path):
    try:
        cmd = [
            "powershell",
            "-command",
            f"(Get-Item '{path}').CreationTime"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout.strip()
    except:
        return "N/A"

def is_suspicious_folder(path):
    suspicious_dirs = [
        "C:\\Users\\Public",
        "C:\\ProgramData",
        "C:\\Temp",
        "C:\\Windows\\Tasks",
        "AppData",
        "Temp",
        "Local",
        "Roaming"
    ]
    for d in suspicious_dirs:
        if d.lower() in path.lower():
            return True
    return False

def is_windows_service(pid):
    try:
        cmd = ["sc", "queryex", "type=", "service"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return str(pid) in result.stdout
    except:
        return False

def analyze_process(pid):
    print("\n================ PROCESS ANALYZER ================")

    name = get_process_name(pid)
    path = get_process_path(pid)
    signature = get_process_signature(path) if path != "unknown" else "N/A"
    sha256 = get_file_hash(path) if path != "unknown" else "N/A"
    parent = get_parent_process(pid)
    attributes = get_file_attributes(path) if path != "unknown" else "N/A"
    creation = get_file_creation_time(path) if path != "unknown" else "N/A"
    suspicious = is_suspicious_folder(path)
    service = is_windows_service(pid)

    print(f"Processo: {name}")
    print(f"PID: {pid}")
    print(f"Percorso: {path}")
    print(f"Firma digitale: {signature}")
    print(f"SHA256: {sha256}")
    print(f"Parent PID: {parent}")
    print(f"Attributi file: {attributes}")
    print(f"Data creazione: {creation}")
    print(f"Cartella sospetta: {'SI' if suspicious else 'NO'}")
    print(f"È un servizio Windows: {'SI' if service else 'NO'}")

    print("==================================================\n")

# ---------------- TRUST / SUSPICIOUS ----------------

def add_trusted_ip(ip, note=""):
    conn = sqlite3.connect(get_db_path())
    cur = conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO trusted_ips (ip, note, added_at) VALUES (?, ?, ?)",
        (ip, note, datetime.datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

def add_suspicious_ip(ip, port, reason):
    conn = sqlite3.connect(get_db_path())
    cur = conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO suspicious_ips (ip, port, reason, added_at) VALUES (?, ?, ?, ?)",
        (ip, port, reason, datetime.datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

def log_action(action, ip, pid):
    conn = sqlite3.connect(get_db_path())
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO actions_log (action, ip, pid, timestamp) VALUES (?, ?, ?, ?)",
        (action, ip, pid, datetime.datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

def is_ip_trusted(ip):
    conn = sqlite3.connect(get_db_path())
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM trusted_ips WHERE ip = ?", (ip,))
    row = cur.fetchone()
    conn.close()
    return row is not None

# ------------- NETSTAT WINDOWS ONLY -------------

def run_netstat(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout.splitlines()

# ------------- LAN / INPUT -------------

def ask_lan():
    print("Inserisci il PREFISSO della tua rete LAN (es. 192.168.1. oppure 10.0.0.)")
    print("NON inserire un IP completo come 192.168.1.0")
    lan = input("LAN: ").strip()

    if lan.count(".") == 3 and lan.endswith(".0"):
        lan = lan.rsplit(".", 1)[0] + "."

    if not lan.endswith("."):
        lan += "."

    return lan

# ------------- PARSER WINDOWS -------------

def parse_connections_windows(lines):
    connections = []
    seen_ips = set()

    for line in lines:
        line = line.strip()
        if not line.startswith(("TCP", "UDP")):
            continue

        parts = line.split()
        proto = parts[0]
        local = parts[1]
        remote = parts[2]

        if proto == "TCP":
            state = parts[3]
            pid = parts[4]
        else:
            state = ""
            pid = parts[3]

        try:
            local_ip, local_port = local.rsplit(":", 1)
            remote_ip, remote_port = remote.rsplit(":", 1)
        except ValueError:
            continue

        if remote_ip in ("0.0.0.0", "::", "[::]", "*"):
            continue
        if remote_ip.startswith("["):
            continue

        if remote_ip in seen_ips:
            continue
        seen_ips.add(remote_ip)

        connections.append({
            "proto": proto,
            "local_ip": local_ip,
            "local_port": int(local_port),
            "remote_ip": remote_ip,
            "remote_port": int(remote_port),
            "pid": int(pid),
            "state": state
        })

    return connections

# ------------- WHOIS / GEO -------------

def whois_info(ip):
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=5)
        data = r.json()
        return {
            "org": data.get("connection", {}).get("org", "N/A"),
            "asn": data.get("connection", {}).get("asn", "N/A"),
            "country": data.get("country", "N/A")
        }
    except Exception:
        return {"org": "N/A", "asn": "N/A", "country": "N/A"}

def geo_info(ip):
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=5)
        data = r.json()
        return {
            "country": data.get("country", "N/A"),
            "city": data.get("city", "N/A")
        }
    except Exception:
        return {"country": "N/A", "city": "N/A"}

# ------------- CLASSIFICAZIONE -------------

def classify_ip(ip, lan_prefix):
    if ip.startswith(lan_prefix):
        return "green"
    if ip.startswith("127."):
        return "green"
    if is_ip_trusted(ip):
        return "green"
    return "red"

# ------------- BLOCCO / KILL -------------

def block_ip_windows(ip):
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        "name=BackdoorsHunterBlock", "dir=out", "action=block", f"remoteip={ip}"
    ]
    subprocess.run(cmd, capture_output=True, text=True)

def kill_pid_windows(pid):
    cmd = ["taskkill", "/PID", str(pid), "/F"]
    subprocess.run(cmd, capture_output=True, text=True)

# ------------- TABELLE -------------

def show_tables(connections, lan_prefix):
    green = []
    yellow = []
    red = []

    for c in connections:
        category = classify_ip(c["remote_ip"], lan_prefix)
        if category == "green":
            green.append(c)
        elif category == "yellow":
            yellow.append(c)
        else:
            red.append(c)

    print(f"{GREEN}=== CONNESSIONI VERDI ==={RESET}")
    for c in green:
        print(f"{c['remote_ip']}:{c['remote_port']}  |  PID {c['pid']}  |  {c['proto']}")

    print(f"\n{YELLOW}=== CONNESSIONI IN ANALISI ==={RESET}")
    for c in yellow:
        print(f"{c['remote_ip']}:{c['remote_port']}  |  PID {c['pid']}  |  {c['proto']}")

    print(f"\n{RED}=== CONNESSIONI ROSSE ==={RESET}")
    for c in red:
        print(f"{c['remote_ip']}:{c['remote_port']}  |  PID {c['pid']}  |  {c['proto']}")

    return green, yellow, red

# ------------- ANALISI IP INTERATTIVA -------------

def analyze_ip_flow(connections, lan_prefix):
    while True:
        print("\nSeleziona un IP da analizzare (es. 34.160.81.0)")
        print("Oppure premi INVIO per uscire dal modulo analisi.")
        ip = input("> ").strip()

        if not ip:
            print("Uscita dal modulo analisi.")
            break

        target = None
        for c in connections:
            if c["remote_ip"] == ip:
                target = c
                break

        if not target:
            print("IP non trovato tra le connessioni.")
            continue

        print(f"\nAnalisi IP: {ip}")
        w = whois_info(ip)
        g = geo_info(ip)

        print(f"  Porta: {target['remote_port']}")
        print(f"  PID: {target['pid']}")
        print(f"  WHOIS: org={w['org']}, asn={w['asn']}, country={w['country']}")
        print(f"  GEO: country={g['country']}, city={g['city']}")

        analyze_process(target["pid"])

        print("\nVuoi:")
        print("  [1] Segnare IP come fidato (verde)")
        print("  [2] Segnare IP come sospetto (rosso)")
        print("  [3] Bloccare IP e killare il processo")
        choice = input("> ").strip()

        if choice == "1":
            add_trusted_ip(ip, "Aggiunto manualmente come fidato")
            log_action("trust", ip, target["pid"])
            print("IP segnato come fidato.")

        elif choice == "2":
            add_suspicious_ip(ip, target["remote_port"], "Segnato manualmente come sospetto")
            log_action("suspicious", ip, target["pid"])
            print("IP segnato come sospetto.")

        elif choice == "3":
            block_ip_windows(ip)
            kill_pid_windows(target["pid"])
            log_action("block", ip, target["pid"])
            print("IP bloccato e processo killato.")

        else:
            print("Nessuna azione eseguita.")

        print("\nAggiornamento tabelle...\n")
        show_tables(connections, lan_prefix)

# ------------- MAIN SOLO WINDOWS -------------

def main():
    print(banner)
    init_db()

    lan_prefix = ask_lan()

    print("Sistema operativo: Windows")
    cmd = ["netstat", "-ano"]

    lines = run_netstat(cmd)

    connections = parse_connections_windows(lines)

    green, yellow, red = show_tables(connections, lan_prefix)

    analyze_ip_flow(connections, lan_prefix)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\nErrore: {e}")
        input("\nPremi INVIO per chiudere...")

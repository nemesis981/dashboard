import sqlite3
from datetime import datetime

DB_PATH = "/home/paul/alert_manager/alerts.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT NOT NULL,
            rule_name TEXT,
            classification TEXT,
            priority INTEGER,
            explanation TEXT,
            risk_level TEXT,
            action TEXT DEFAULT "pending",
            times_seen INTEGER DEFAULT 1,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT
        )
    ''')
    conn.commit()
    conn.close()
    print("Database initialized successfully")

def get_alert(rule_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM alerts WHERE rule_id = ?", (rule_id,))
    result = c.fetchone()
    conn.close()
    return result

def add_alert(rule_id, rule_name, classification, priority, explanation, risk_level, action, src_ip, dst_ip, protocol):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute('''
        INSERT INTO alerts 
        (rule_id, rule_name, classification, priority, explanation, risk_level, action, times_seen, first_seen, last_seen, src_ip, dst_ip, protocol)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
    ''', (rule_id, rule_name, classification, priority, explanation, risk_level, action, now, now, src_ip, dst_ip, protocol))
    conn.commit()
    conn.close()

def update_seen(rule_id, src_ip, dst_ip):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute('''
        UPDATE alerts 
        SET times_seen = times_seen + 1, last_seen = ?, src_ip = ?, dst_ip = ?
        WHERE rule_id = ?
    ''', (now, src_ip, dst_ip, rule_id))
    conn.commit()
    conn.close()

def update_action(rule_id, action):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE alerts SET action = ? WHERE rule_id = ?", (action, rule_id))
    conn.commit()
    conn.close()

def get_all_alerts():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY last_seen DESC")
    results = c.fetchall()
    conn.close()
    return results

if __name__ == "__main__":
    init_db()

import sqlite3
import json
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'panl.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  filename TEXT,
                  sha256 TEXT UNIQUE,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  risk_score INTEGER,
                  severity TEXT,
                  findings_json TEXT)''')
    conn.commit()
    conn.close()

def save_scan(filename, sha256, risk_score, severity, findings):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Use REPLACE to update if the same file is scanned again
    c.execute('''INSERT OR REPLACE INTO scans (filename, sha256, risk_score, severity, findings_json)
                 VALUES (?, ?, ?, ?, ?)''',
              (filename, sha256, risk_score, severity, json.dumps(findings)))
    conn.commit()
    conn.close()

def get_all_scans():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT filename, sha256, timestamp, risk_score, severity FROM scans ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()
    return rows

def get_scan_by_hash(sha256):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT findings_json FROM scans WHERE sha256 = ?", (sha256,))
    row = c.fetchone()
    conn.close()
    return json.loads(row[0]) if row else None

def clear_all_scans():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM scans")
    conn.commit()
    conn.close()

import sqlite3
import json
from datetime import datetime

class AuditServer:
    def __init__(self, server_priv_path, auditor_pub_paths, store_path, notifier_config):
        self.store_path = store_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.store_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                action_data TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()

    def append_user_record(self, user_id, action_data):
        conn = sqlite3.connect(self.store_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO audit_log (user_id, action_data) VALUES (?, ?)",
            (user_id, json.dumps(action_data))
        )
        conn.commit()
        conn.close()

    def query_user(self, user_id=None):
        conn = sqlite3.connect(self.store_path)
        cursor = conn.cursor()
        if user_id:
            cursor.execute("SELECT user_id, action_data, timestamp FROM audit_log WHERE user_id = ?", (user_id,))
        else:
            cursor.execute("SELECT user_id, action_data, timestamp FROM audit_log")
        rows = cursor.fetchall()
        conn.close()

        records = []
        for row in rows:
            try:
                record = json.loads(row[1])
                record["user_id"] = row[0]
                record["timestamp"] = row[2]
                records.append(record)
            except Exception:
                continue
        return records
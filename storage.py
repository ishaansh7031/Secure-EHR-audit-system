import sqlite3
import json
from pathlib import Path

class AuditStore:
    def __init__(self, db_path: Path):
        # Allow SQLite connection to be shared across threads
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.execute("""
          CREATE TABLE IF NOT EXISTS records (
            seq    INTEGER PRIMARY KEY,
            record TEXT NOT NULL
          )
        """)

    def append(self, record: dict):
        self.db.execute(
            "INSERT INTO records(seq, record) VALUES(?,?)",
            (record["seq"], json.dumps(record))
        )
        self.db.commit()

    def fetch_all(self) -> list[dict]:
        cur = self.db.execute("SELECT record FROM records ORDER BY seq")
        return [json.loads(row[0]) for row in cur]

    def close(self):
        """Explicitly close the SQLite connection."""
        self.db.close()
        print("AuditStore: DB connection closed.")
import sqlite3
import json
from datetime import datetime
from utils.hash_utils import generate_sha256

DB_NAME = "forensics_logs.db"

class ForensicManager:
    def __init__(self):
        self.conn = sqlite3.connect(DB_NAME, check_same_thread=False)
        self._create_table()

    def _create_table(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS forensic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_id TEXT,
                action TEXT,
                timestamp TEXT,
                data TEXT,
                previous_hash TEXT,
                hash TEXT
            )
        """)
        self.conn.commit()

    def _get_last_hash(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT hash FROM forensic_logs ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        return row[0] if row else "0"

    def log_event(self, artifact_id, action, data: dict):
        timestamp = datetime.utcnow().isoformat()
        previous_hash = self._get_last_hash()

        content = f"{artifact_id}{action}{timestamp}{json.dumps(data)}{previous_hash}"
        current_hash = generate_sha256(content)

        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO forensic_logs
            (artifact_id, action, timestamp, data, previous_hash, hash)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            artifact_id,
            action,
            timestamp,
            json.dumps(data),
            previous_hash,
            current_hash
        ))

        self.conn.commit()

        return {
            "artifact_id": artifact_id,
            "action": action,
            "timestamp": timestamp,
            "hash": current_hash
        }

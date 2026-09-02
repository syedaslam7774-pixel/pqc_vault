import os
import time
import requests
from typing import Optional, Dict, Any, List

RAW_URL = os.environ.get("TURSO_DATABASE_URL", "")
TURSO_HTTP_URL = RAW_URL.replace("libsql://", "https://").rstrip("/") + "/v2/pipeline"
TURSO_AUTH_TOKEN = os.environ.get("TURSO_AUTH_TOKEN", "")

def execute_query(sql: str, args: list = None) -> list:
    """Executes SQL statements over Turso's secure HTTP API."""
    if not TURSO_HTTP_URL or not TURSO_AUTH_TOKEN:
        raise RuntimeError("Missing TURSO_DATABASE_URL or TURSO_AUTH_TOKEN environment variable.")

    if args is None:
        args = []

    formatted_args = []
    for arg in args:
        if isinstance(arg, int):
            formatted_args.append({"type": "integer", "value": str(arg)})
        elif isinstance(arg, float):
            formatted_args.append({"type": "float", "value": arg})
        elif arg is None:
            formatted_args.append({"type": "null"})
        else:
            formatted_args.append({"type": "text", "value": str(arg)})

    payload = {
        "requests": [
            {
                "type": "execute",
                "stmt": {
                    "sql": sql,
                    "args": formatted_args
                }
            },
            {"type": "close"}
        ]
    }

    headers = {
        "Authorization": f"Bearer {TURSO_AUTH_TOKEN}",
        "Content-Type": "application/json"
    }

    response = requests.post(TURSO_HTTP_URL, json=payload, headers=headers)
    if response.status_code != 200:
        raise RuntimeError(f"Turso DB Error ({response.status_code}): {response.text}")

    data = response.json()
    results = data.get("results", [])
    if results and "response" in results[0]:
        exec_result = results[0]["response"].get("result", {})
        rows = exec_result.get("rows", [])
        return [[col.get("value") for col in r] for r in rows]
    return []

def init_db():
    """Initializes and creates the remote database tables."""
    execute_query("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            x25519_pub TEXT NOT NULL,
            ml_kem_pub TEXT NOT NULL,
            ephemeral_x25519_pub TEXT NOT NULL,
            pq_ciphertext TEXT NOT NULL,
            salt TEXT NOT NULL,
            nonce TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)

    execute_query("""
        CREATE TABLE IF NOT EXISTS notes (
            note_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            ephemeral_x25519_pub TEXT NOT NULL,
            pq_ciphertext TEXT NOT NULL,
            salt TEXT NOT NULL,
            nonce TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
        )
    """)

def user_exists(username: str) -> bool:
    rows = execute_query("SELECT 1 FROM users WHERE username = ?", [username])
    return len(rows) > 0

def create_user(
    username: str,
    x25519_pub: str,
    ml_kem_pub: str,
    ephemeral_x25519_pub: str,
    pq_ciphertext: str,
    salt: str,
    nonce: str,
    ciphertext: str
):
    execute_query("""
        INSERT INTO users (
            username, x25519_pub, ml_kem_pub,
            ephemeral_x25519_pub, pq_ciphertext, salt, nonce, ciphertext,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [
        username, x25519_pub, ml_kem_pub,
        ephemeral_x25519_pub, pq_ciphertext, salt, nonce, ciphertext,
        int(time.time())
    ])

def get_user(username: str) -> Optional[Dict[str, Any]]:
    rows = execute_query("SELECT * FROM users WHERE username = ?", [username])
    if not rows:
        return None

    row = rows[0]
    return {
        "username": row[0],
        "public_keys": {
            "x25519_pub": row[1],
            "ml_kem_pub": row[2]
        },
        "encrypted_password_packet": {
            "ephemeral_x25519_pub": row[3],
            "pq_ciphertext": row[4],
            "salt": row[5],
            "nonce": row[6],
            "ciphertext": row[7]
        }
    }

def save_user_note(
    username: str,
    note_id: str,
    ephemeral_x25519_pub: str,
    pq_ciphertext: str,
    salt: str,
    nonce: str,
    ciphertext: str
):
    execute_query("""
        INSERT INTO notes (
            note_id, username, ephemeral_x25519_pub, pq_ciphertext,
            salt, nonce, ciphertext, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(note_id) DO UPDATE SET
            ephemeral_x25519_pub = excluded.ephemeral_x25519_pub,
            pq_ciphertext = excluded.pq_ciphertext,
            salt = excluded.salt,
            nonce = excluded.nonce,
            ciphertext = excluded.ciphertext,
            updated_at = excluded.updated_at
    """, [
        note_id, username, ephemeral_x25519_pub, pq_ciphertext,
        salt, nonce, ciphertext, int(time.time())
    ])

def get_user_notes(username: str) -> List[Dict[str, Any]]:
    rows = execute_query(
        "SELECT note_id, ephemeral_x25519_pub, pq_ciphertext, salt, nonce, ciphertext, updated_at "
        "FROM notes WHERE username = ?", 
        [username]
    )

    notes = []
    for row in rows:
        notes.append({
            "note_id": row[0],
            "encrypted_packet": {
                "ephemeral_x25519_pub": row[1],
                "pq_ciphertext": row[2],
                "salt": row[3],
                "nonce": row[4],
                "ciphertext": row[5]
            },
            "updated_at": row[6]
        })
    return notes

def delete_user_note(username: str, note_id: str):
    execute_query("DELETE FROM notes WHERE username = ? AND note_id = ?", [username, note_id])
# chat_db.py — SQLite chat history
import os
import sqlite3
import uuid
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "chat_history.db")


def init_db():
    """Create tables on startup."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id  TEXT PRIMARY KEY,
                title       TEXT DEFAULT 'New Chat',
                created_at  TEXT NOT NULL,
                last_active TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id     TEXT NOT NULL,
                role           TEXT NOT NULL,
                content        TEXT NOT NULL,
                status         TEXT,
                risk_score     INTEGER,
                attack_type    TEXT,
                output_verdict TEXT,
                timestamp      TEXT NOT NULL,
                FOREIGN KEY(session_id) REFERENCES sessions(session_id)
            )
        """)
        conn.commit()


def create_session() -> str:
    sid = str(uuid.uuid4())
    now = datetime.now().isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO sessions(session_id, created_at, last_active) VALUES(?,?,?)",
            (sid, now, now)
        )
        conn.commit()
    return sid


def session_exists(sid: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT 1 FROM sessions WHERE session_id=?", (sid,)
        ).fetchone()
    return row is not None


def save_exchange(session_id, user_prompt, ai_response,
                  status, risk_score, attack_type=None, output_verdict=None):
    """Save a user→assistant exchange and update session title."""
    now = datetime.now().isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        # Save user message
        conn.execute(
            """INSERT INTO messages(session_id,role,content,status,risk_score,attack_type,timestamp)
               VALUES(?,?,?,?,?,?,?)""",
            (session_id, "user", user_prompt, status, risk_score, attack_type, now)
        )
        # Save assistant message
        conn.execute(
            """INSERT INTO messages(session_id,role,content,status,risk_score,output_verdict,timestamp)
               VALUES(?,?,?,?,?,?,?)""",
            (session_id, "assistant", ai_response, status, risk_score, output_verdict, now)
        )
        # Update session last_active and set title from first prompt
        row = conn.execute(
            "SELECT title FROM sessions WHERE session_id=?", (session_id,)
        ).fetchone()
        title = row[0] if row else "New Chat"
        if title == "New Chat":
            title = user_prompt[:55] + ("…" if len(user_prompt) > 55 else "")
        conn.execute(
            "UPDATE sessions SET last_active=?, title=? WHERE session_id=?",
            (now, title, session_id)
        )
        conn.commit()


def get_session_messages(session_id: str) -> list:
    """Return all messages for a session in order."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT role, content, status, risk_score, attack_type,
                      output_verdict, timestamp
               FROM messages WHERE session_id=?
               ORDER BY id ASC""",
            (session_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_all_sessions() -> list:
    """Return all sessions ordered by most recent activity."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT session_id, title, created_at, last_active FROM sessions ORDER BY last_active DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def delete_session(session_id: str):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM messages WHERE session_id=?", (session_id,))
        conn.execute("DELETE FROM sessions WHERE session_id=?",  (session_id,))
        conn.commit()
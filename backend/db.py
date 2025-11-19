import os
import sqlite3
from typing import Optional, Dict, Any

# Path to the project root (MINI_INSTA)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)

# Database will live in MINI_INSTA/mini_insta.db
DB_PATH = os.path.join(PROJECT_DIR, "mini_insta.db")


def init_db() -> None:
    """
    Create the SQLite database and users table if they don't exist yet.
    Called once when the app starts.
    """
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                full_name TEXT,
                email TEXT,
                bio TEXT,
                dob TEXT,
                hashed_password TEXT NOT NULL
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def get_user_row(username: str) -> Optional[sqlite3.Row]:
    """
    Return a single user row from the DB by username, or None if not found.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(
            """
            SELECT username, full_name, email, bio, dob, hashed_password
            FROM users
            WHERE username = ?
            """,
            (username,),
        )
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def insert_user_row(user_data: Dict[str, Any]) -> None:
    """
    Insert a new user row into the DB.
    Expects a dict with keys: username, full_name, email, bio, dob, hashed_password.
    """
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            INSERT INTO users (username, full_name, email, bio, dob, hashed_password)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                user_data["username"],
                user_data.get("full_name"),
                user_data.get("email"),
                user_data.get("bio"),
                user_data.get("dob"),
                user_data["hashed_password"],
            ),
        )
        conn.commit()
    finally:
        conn.close()
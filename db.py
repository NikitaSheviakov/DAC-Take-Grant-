import sqlite3

DB_NAME = "take_grant.db"

def get_db():
    # додаємо timeout на випадок блокувань
    return sqlite3.connect(DB_NAME, timeout=5)

def init_db():
    with get_db() as conn:
        cursor = conn.cursor()

        # Users
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password BLOB,
            is_admin INTEGER DEFAULT 0
        )
        """)

        # Objects
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS objects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            content TEXT,
            owner_id INTEGER
        )
        """)

        # Rights
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS rights (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_id INTEGER,
            object_id INTEGER,
            right_type TEXT
        )
        """)

        # Audit
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            user TEXT,
            action TEXT,
            result TEXT,
            target_user_id INTEGER,
            object_name TEXT
        )
        """)

        conn.commit()

import bcrypt
from db import get_db

def register_user(username, password):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        print(f"User '{username}' already exists!")
        conn.close()
        return False

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    # Якщо це перший користувач у системі — робимо його адміном
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    is_admin = 1 if count == 0 else 0

    cursor.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", (username, hashed, is_admin))

    conn.commit()
    conn.close()
    print(f"User '{username}' registered successfully. Admin={bool(is_admin)}")
    return True

def login_user(username, password):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id, password, is_admin FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row and bcrypt.checkpw(password.encode("utf-8"), row[1]):
        print(f"Login successful! User ID: {row[0]} (admin={bool(row[2])})")
        return row[0], username, bool(row[2])
    else:
        print("Invalid credentials!")
        return None

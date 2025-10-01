# demo.py
import os
import sqlite3
from time import sleep

# import project modules
from db import init_db, get_db
from auth import register_user, login_user
from objects import create_object, list_objects, read_object, write_object, delete_object
from rights import grant_right, take_right, check_access
from audit import log_event
from trojan import trojan_grant

try:
    from tabulate import tabulate
except Exception:
    tabulate = None

DB_FILE = "take_grant.db"

def reset_db():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    init_db()

def fetch_table(query, params=()):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return rows

def print_table(rows, headers):
    if not rows:
        print("No rows.")
        return
    if tabulate:
        print(tabulate(rows, headers=headers, tablefmt="grid"))
    else:
        print(headers)
        for r in rows:
            print(r)

def run_demo():
    print("Demo: Take-Grant model and trojan demonstration")
    print("Resetting database...")
    reset_db()
    sleep(0.5)

    # 1. Register users
    print("\nRegister users: user1 (owner/admin), user2 (user), attacker")
    register_user("user1", "pass1")
    register_user("user2", "pass2")
    register_user("attacker", "evilpass")

    # get ids
    rows = fetch_table("SELECT id, username, is_admin FROM users")
    print_table(rows, ["id", "username", "is_admin"])

    user1_id = [r[0] for r in rows if r[1] == "user1"][0]
    user2_id = [r[0] for r in rows if r[1] == "user2"][0]
    attacker_id = [r[0] for r in rows if r[1] == "attacker"][0]

    # 2. user1 creates object file1
    print("\nUser1 creates object file1 (owner gets read/write/take)")
    create_object("file1", "Initial secret content", user1_id)

    rows = fetch_table("SELECT id, name, owner_id FROM objects")
    print_table(rows, ["id", "name", "owner_id"])
    obj_id = rows[0][0]

    # 3. Check rights for object
    print("\nRights after creation (owner rights):")
    rows = fetch_table("""
        SELECT r.id, u.username AS subject, o.name AS object, r.right_type
        FROM rights r
        LEFT JOIN users u ON r.subject_id = u.id
        LEFT JOIN objects o ON r.object_id = o.id
        WHERE r.object_id = ?
    """, (obj_id,))
    print_table(rows, ["id", "subject", "object", "right_type"])

    # 4. Owner grants read to user2
    print("\nOwner grants 'read' to user2")
    grant_right(user1_id, user2_id, obj_id, "read")

    rows = fetch_table("SELECT subject_id, object_id, right_type FROM rights WHERE object_id = ?", (obj_id,))
    print_table(rows, ["subject_id", "object_id", "right_type"])

    # 5. user2 checks and reads
    print("\nUser2 checks read access and reads object")
    ok = check_access(user2_id, obj_id, "read")
    if ok:
        read_object(obj_id)
    else:
        print("User2 cannot read")

    # 6. Owner grants 'take' to user2 to demonstrate propagation
    print("\nOwner grants 'take' to user2")
    grant_right(user1_id, user2_id, obj_id, "take")
    rows = fetch_table("SELECT subject_id, object_id, right_type FROM rights WHERE object_id = ?", (obj_id,))
    print_table(rows, ["subject_id", "object_id", "right_type"])

    # 7. user2 takes 'write' from owner (propagation of rights)
    print("\nUser2 attempts to take 'write' from owner")
    take_ok = take_right(user2_id, user1_id, obj_id, "write")
    print("Take result:", take_ok)
    rows = fetch_table("SELECT subject_id, object_id, right_type FROM rights WHERE object_id = ?", (obj_id,))
    print_table(rows, ["subject_id", "object_id", "right_type"])

    # 8. user2 writes (if has write)
    print("\nUser2 attempts to write (after possible take)")
    if check_access(user2_id, obj_id, "write"):
        write_object(obj_id, "Updated by user2 via take")
        read_object(obj_id)
    else:
        print("User2 has no write right")

    # 9. Trojan demonstration: trojan runs under user1 and grants 'read' to attacker
    print("\nTrojan demonstration: trojan running as user1 grants 'read' to attacker")
    trojan_grant(user1_id, "user1", attacker_id, obj_id, "read")

    # 10. Attacker checks and reads
    print("\nAttacker checks read and reads object (should be allowed if trojan succeeded)")
    if check_access(attacker_id, obj_id, "read"):
        read_object(obj_id)
    else:
        print("Attacker cannot read")

    # 11. Show final tables: users, objects, rights, audit
    print("\nFinal users table:")
    rows = fetch_table("SELECT id, username, is_admin FROM users")
    print_table(rows, ["id", "username", "is_admin"])

    print("\nFinal objects table:")
    rows = fetch_table("SELECT id, name, owner_id, content FROM objects")
    print_table(rows, ["id", "name", "owner_id", "content"])

    print("\nFinal rights table:")
    rows = fetch_table("""
        SELECT r.id, u.username AS subject, o.name AS object, r.right_type
        FROM rights r
        LEFT JOIN users u ON r.subject_id = u.id
        LEFT JOIN objects o ON r.object_id = o.id
        ORDER BY r.id
    """)
    print_table(rows, ["id", "subject", "object", "right_type"])

    print("\nAudit log (last 50):")
    rows = fetch_table("SELECT id, timestamp, user, action, result, target_user_id, object_name FROM audit ORDER BY id DESC LIMIT 50")
    print_table(rows, ["id", "timestamp", "user", "action", "result", "target_user_id", "object_name"])

if __name__ == "__main__":
    run_demo()

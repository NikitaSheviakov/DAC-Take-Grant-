from db import init_db
from auth import register_user, login_user
from objects import create_object, list_objects, read_object, write_object, delete_object
from rights import grant_right, take_right, check_access
from audit import log_event

try:
    from tabulate import tabulate
except Exception:
    tabulate = None

HELP_TEXT = """
Available commands:
  help                 - show this help
  register             - register a new user
  login                - login as a user
  logout               - logout current user
  whoami               - show current logged-in user
  create_obj           - create a new object (owner gets read/write/take)
  list_obj             - list all objects
  read_obj             - read object content
  write_obj            - write (update) object content
  delete_obj           - delete object and its rights
  grant                - grant a right to another user
  take                 - take a right from another user (requires take right)
  check                - check access for current user
  show_audit           - show last audit records
  list_users           - (admin) list all users
  delete_user          - (admin) delete a user
  make_admin           - (admin) grant admin rights to a user
  exit                 - exit program
"""

def print_help():
    print(HELP_TEXT)

def show_audit(limit=20):
    conn = __import__('sqlite3').connect("take_grant.db")
    cur = conn.cursor()
    cur.execute("SELECT id, timestamp, user, action, result, target_user_id, object_name FROM audit ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    if not rows:
        print("No audit records.")
        return
    headers = ["id", "timestamp", "user", "action", "result", "target_user_id", "object_name"]
    if tabulate:
        print(tabulate(rows, headers=headers, tablefmt="grid"))
    else:
        print(headers)
        for r in rows:
            print(r)

def main():
    init_db()
    current_user_id = None
    current_username = None
    current_is_admin = False

    print("Take-Grant Security System (CLI). Type 'help' to list commands.")

    while True:
        prompt = f"{current_username}> " if current_username else "> "
        cmd = input(prompt).strip()

        if cmd == "help":
            print_help()
            continue

        if cmd == "register":
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            ok = register_user(username, password)
            log_event(username, "register", "success" if ok else "fail")
            continue

        if cmd == "login":
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            res = login_user(username, password)
            if res:
                current_user_id, current_username, current_is_admin = res
                log_event(current_username, "login", "success")
            else:
                log_event(username, "login", "fail")
            continue

        if cmd == "logout":
            if current_username:
                log_event(current_username, "logout", "success")
                print(f"User '{current_username}' logged out.")
            current_user_id = None
            current_username = None
            current_is_admin = False
            continue

        if cmd == "whoami":
            if current_username:
                print(f"Logged in as: {current_username} (id={current_user_id})")
            else:
                print("Not logged in.")
            continue

        if cmd == "create_obj":
            if not current_user_id:
                print("You must login first.")
                log_event("anonymous", "create_obj_attempt", "fail")
                continue
            name = input("Object name: ").strip()
            content = input("Object content: ").strip()
            ok = create_object(name, content, current_user_id)
            log_event(current_username, f"create object {name}", "success" if ok else "fail", target_user_id=None, object_name=name)
            continue

        if cmd == "list_obj":
            # fetch objects and print nicely
            conn = __import__('sqlite3').connect("take_grant.db")
            cur = conn.cursor()
            cur.execute("SELECT id, name, owner_id FROM objects")
            rows = cur.fetchall()
            conn.close()
            if not rows:
                print("No objects.")
            else:
                headers = ["id", "name", "owner_id"]
                if tabulate:
                    print(tabulate(rows, headers=headers, tablefmt="grid"))
                else:
                    for r in rows:
                        print(f"id={r[0]}, name={r[1]}, owner_id={r[2]}")
            log_event(current_username or "anonymous", "list_objects", "success")
            continue

        if cmd == "read_obj":
            oid = input("Object ID: ").strip()
            if not oid.isdigit():
                print("Invalid object id.")
                continue
            oid = int(oid)
            if current_user_id and check_access(current_user_id, oid, "read"):
                # get object name for audit
                conn = __import__('sqlite3').connect("take_grant.db")
                cur = conn.cursor()
                cur.execute("SELECT name FROM objects WHERE id = ?", (oid,))
                row = cur.fetchone()
                conn.close()
                object_name = row[0] if row else None
                read_object(oid)
                log_event(current_username, f"read object {oid}", "success", object_name=object_name)
            else:
                print("Read denied or you must login first.")
                log_event(current_username or "anonymous", f"read object {oid}", "denied")
            continue

        if cmd == "write_obj":
            oid = input("Object ID: ").strip()
            if not oid.isdigit():
                print("Invalid object id.")
                continue
            oid = int(oid)
            new_content = input("New content: ")
            if current_user_id and check_access(current_user_id, oid, "write"):
                # get object_name for audit
                conn = __import__('sqlite3').connect("take_grant.db")
                cur = conn.cursor()
                cur.execute("SELECT name FROM objects WHERE id = ?", (oid,))
                row = cur.fetchone()
                conn.close()
                object_name = row[0] if row else None
                ok = write_object(oid, new_content)
                log_event(current_username, f"write object {oid}", "success" if ok else "fail", object_name=object_name)
            else:
                print("Write denied or you must login first.")
                log_event(current_username or "anonymous", f"write object {oid}", "denied")
            continue

        if cmd == "delete_obj":
            oid = input("Object ID to delete: ").strip()
            if not oid.isdigit():
                print("Invalid object id.")
                continue
            oid = int(oid)
            if current_user_id and check_access(current_user_id, oid, "write"):
                # get object_name for audit
                conn = __import__('sqlite3').connect("take_grant.db")
                cur = conn.cursor()
                cur.execute("SELECT name FROM objects WHERE id = ?", (oid,))
                row = cur.fetchone()
                conn.close()
                object_name = row[0] if row else None
                ok = delete_object(oid)
                log_event(current_username, f"delete object {oid}", "success" if ok else "fail", object_name=object_name)
            else:
                print("Delete denied or you must login first.")
                log_event(current_username or "anonymous", f"delete object {oid}", "denied")
            continue

        if cmd == "grant":
            if not current_user_id:
                print("You must login first.")
                log_event("anonymous", "grant_attempt", "fail")
                continue
            to_user = input("Target user ID: ").strip()
            obj_id = input("Object ID: ").strip()
            right = input("Right (read/write/take): ").strip()
            if not to_user.isdigit() or not obj_id.isdigit():
                print("Invalid ids.")
                log_event(current_username, "grant_invalid_ids", "fail")
                continue
            to_user_id = int(to_user); obj_id_int = int(obj_id)
            ok = grant_right(current_user_id, to_user_id, obj_id_int, right)
            # object name for audit
            conn = __import__('sqlite3').connect("take_grant.db")
            cur = conn.cursor()
            cur.execute("SELECT name FROM objects WHERE id = ?", (obj_id_int,))
            row = cur.fetchone()
            conn.close()
            object_name = row[0] if row else None
            log_event(current_username, f"grant {right} obj {obj_id} to user {to_user}", "success" if ok else "fail", target_user_id=to_user_id, object_name=object_name)
            continue

        if cmd == "take":
            if not current_user_id:
                print("You must login first.")
                log_event("anonymous", "take_attempt", "fail")
                continue
            target_user = input("Target user ID: ").strip()
            obj_id = input("Object ID: ").strip()
            right = input("Right (read/write): ").strip()
            if not target_user.isdigit() or not obj_id.isdigit():
                print("Invalid ids.")
                log_event(current_username, "take_invalid_ids", "fail")
                continue
            target_user_id = int(target_user); obj_id_int = int(obj_id)
            ok = take_right(current_user_id, target_user_id, obj_id_int, right)
            # object name for audit
            conn = __import__('sqlite3').connect("take_grant.db")
            cur = conn.cursor()
            cur.execute("SELECT name FROM objects WHERE id = ?", (obj_id_int,))
            row = cur.fetchone()
            conn.close()
            object_name = row[0] if row else None
            log_event(current_username, f"take {right} obj {obj_id} from user {target_user}", "success" if ok else "fail", target_user_id=target_user_id, object_name=object_name)
            continue
        
        if cmd == "list_users":
            if not current_is_admin:
                print("Only admin can list users.")
                log_event(current_username or "anonymous", "list_users", "denied")
                continue
            conn = __import__('sqlite3').connect("take_grant.db")
            cur = conn.cursor()
            cur.execute("SELECT id, username, is_admin FROM users")
            rows = cur.fetchall()
            conn.close()
            from tabulate import tabulate
            print(tabulate(rows, headers=["id", "username", "is_admin"], tablefmt="grid"))
            log_event(current_username, "list_users", "success")
            continue

        if cmd == "delete_user":
            if not current_is_admin:
                print("Only admin can delete users.")
                log_event(current_username or "anonymous", "delete_user", "denied")
                continue
            uid = input("Enter user ID to delete: ").strip()
            if not uid.isdigit():
                print("Invalid user id.")
                continue
            uid = int(uid)
            conn = __import__('sqlite3').connect("take_grant.db")
            cur = conn.cursor()
            # remove rights
            cur.execute("DELETE FROM rights WHERE subject_id = ?", (uid,))
            # remove user
            cur.execute("DELETE FROM users WHERE id = ?", (uid,))
            conn.commit()
            conn.close()
            print(f"User {uid} deleted.")
            log_event(current_username, f"delete_user {uid}", "success", target_user_id=uid)
            continue

        if cmd == "make_admin":
            if not current_is_admin:
                print("Only admin can grant admin rights.")
                log_event(current_username or "anonymous", "make_admin", "denied")
                continue
            uid = input("Enter user ID to make admin: ").strip()
            if not uid.isdigit():
                print("Invalid user id.")
                continue
            uid = int(uid)
            conn = __import__('sqlite3').connect("take_grant.db")
            cur = conn.cursor()
            cur.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (uid,))
            conn.commit()
            conn.close()
            print(f"User {uid} is now admin.")
            log_event(current_username, f"make_admin {uid}", "success", target_user_id=uid)
            continue

        if cmd == "check":
            if not current_user_id:
                print("You must login first.")
                log_event("anonymous", "check_attempt", "fail")
                continue
            obj_id = input("Object ID: ").strip()
            right = input("Right (read/write): ").strip()
            if not obj_id.isdigit():
                print("Invalid object id.")
                log_event(current_username, "check_invalid_id", "fail")
                continue
            ok = check_access(current_user_id, int(obj_id), right)
            log_event(current_username, f"check {right} on object {obj_id}", "success" if ok else "denied")
            continue

        if cmd == "show_audit":
            show_audit()
            continue

        if cmd == "exit":
            print("Exiting system.")
            break

        print("Unknown command. Type 'help' to list commands.")

if __name__ == "__main__":
    main()

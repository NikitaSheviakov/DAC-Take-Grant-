from db import get_db

def create_object(name, content, owner_id):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM objects WHERE name = ?", (name,))
    if cursor.fetchone():
        print(f"Object '{name}' already exists!")
        conn.close()
        return False

    cursor.execute("INSERT INTO objects (name, content, owner_id) VALUES (?, ?, ?)", (name, content, owner_id))
    obj_id = cursor.lastrowid

    rights = ['read', 'write', 'take']
    for r in rights:
        cursor.execute("SELECT * FROM rights WHERE subject_id = ? AND object_id = ? AND right_type = ?",
                       (owner_id, obj_id, r))
        if cursor.fetchone() is None:
            cursor.execute("INSERT INTO rights (subject_id, object_id, right_type) VALUES (?, ?, ?)",
                           (owner_id, obj_id, r))

    conn.commit()
    conn.close()
    print(f"Object '{name}' (id={obj_id}) created successfully with owner rights!")
    return True


def list_objects():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id, name, owner_id FROM objects")
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print("No objects found.")
        return

    print("\nObjects in system:")
    for obj in rows:
        print(f"ID: {obj[0]} | Name: {obj[1]} | Owner ID: {obj[2]}")


def read_object(object_id):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT name, content, owner_id FROM objects WHERE id = ?", (object_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        print(f"\nObject: {row[0]} (owner_id={row[2]})")
        print(f"Content: {row[1]}")
    else:
        print("Object not found!")


def write_object(object_id, new_content):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM objects WHERE id = ?", (object_id,))
    if cursor.fetchone() is None:
        conn.close()
        print("Object not found!")
        return False

    cursor.execute("UPDATE objects SET content = ? WHERE id = ?", (new_content, object_id))
    conn.commit()
    conn.close()
    print(f"Object id={object_id} updated successfully.")
    return True


def delete_object(object_id):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM objects WHERE id = ?", (object_id,))
    if cursor.fetchone() is None:
        conn.close()
        print("Object not found!")
        return False

    # Delete rights related to the object
    cursor.execute("DELETE FROM rights WHERE object_id = ?", (object_id,))
    # Delete the object
    cursor.execute("DELETE FROM objects WHERE id = ?", (object_id,))

    conn.commit()
    conn.close()
    print(f"Object id={object_id} and related rights deleted.")
    return True

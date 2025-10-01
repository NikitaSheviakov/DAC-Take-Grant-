from db import get_db

# Grant right from one user to another
def grant_right(from_user_id, to_user_id, object_id, right_type):
    conn = get_db()
    cursor = conn.cursor()

    # Check if from_user actually has this right
    cursor.execute("SELECT * FROM rights WHERE subject_id=? AND object_id=? AND right_type=?", 
                   (from_user_id, object_id, right_type))
    if cursor.fetchone() is None:
        print("You cannot grant a right you don't have.")
        conn.close()
        return False

    # Avoid duplicate right
    cursor.execute("SELECT * FROM rights WHERE subject_id=? AND object_id=? AND right_type=?", 
                   (to_user_id, object_id, right_type))
    if cursor.fetchone():
        print("Target already has this right.")
        conn.close()
        return True

    # Add right to target user
    cursor.execute("INSERT INTO rights (subject_id, object_id, right_type) VALUES (?, ?, ?)", 
                   (to_user_id, object_id, right_type))
    conn.commit()
    conn.close()
    print(f"Granted '{right_type}' on object {object_id} to user {to_user_id}")
    return True


# Take right from another user (requires 'take' right for the taker on that object)
def take_right(taker_user_id, target_user_id, object_id, right_type):
    conn = get_db()
    cursor = conn.cursor()

    # Check if taker has TAKE permission on that object
    cursor.execute("SELECT * FROM rights WHERE subject_id=? AND object_id=? AND right_type='take'", 
                   (taker_user_id, object_id))
    if cursor.fetchone() is None:
        print("You don't have TAKE rights on this object.")
        conn.close()
        return False

    # Check if target_user actually has the right
    cursor.execute("SELECT * FROM rights WHERE subject_id=? AND object_id=? AND right_type=?", 
                   (target_user_id, object_id, right_type))
    if cursor.fetchone() is None:
        print("Target user doesn't have this right.")
        conn.close()
        return False

    # Avoid duplicate
    cursor.execute("SELECT * FROM rights WHERE subject_id=? AND object_id=? AND right_type=?", 
                   (taker_user_id, object_id, right_type))
    if cursor.fetchone():
        print("You already have this right.")
        conn.close()
        return True

    # Assign right to taker
    cursor.execute("INSERT INTO rights (subject_id, object_id, right_type) VALUES (?, ?, ?)", 
                   (taker_user_id, object_id, right_type))
    conn.commit()
    conn.close()
    print(f"Took '{right_type}' on object {object_id} from user {target_user_id}")
    return True


# Check if user has a specific right
def check_access(user_id, object_id, right_type):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM rights WHERE subject_id=? AND object_id=? AND right_type=?", 
                   (user_id, object_id, right_type))
    result = cursor.fetchone()
    conn.close()

    if result:
        print(f"Access granted: user {user_id} can '{right_type}' object {object_id}")
        return True
    else:
        print(f"Access denied: user {user_id} cannot '{right_type}' object {object_id}")
        return False

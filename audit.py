from db import get_db

def log_event(actor, action, result, target_user_id=None, object_name=None):
    """
    Write an audit record.
    actor: string (username or 'anonymous')
    action: string
    result: string ('success', 'fail', 'denied', etc.)
    target_user_id: integer or None
    object_name: string or None
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO audit (user, action, result, target_user_id, object_name) VALUES (?, ?, ?, ?, ?)",
        (actor, action, result, target_user_id, object_name)
    )
    conn.commit()
    conn.close()

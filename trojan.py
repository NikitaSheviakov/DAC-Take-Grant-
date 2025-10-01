# trojan.py
from rights import grant_right, take_right
from audit import log_event

def trojan_grant(victim_id, victim_username, attacker_id, object_id, right_type):
    """
    Simulate a trojan that runs under victim's identity and grants a right to attacker.
    This function calls the same grant_right() used by legitimate code, so database changes
    look like they were performed by the victim.
    """
    ok = grant_right(victim_id, attacker_id, object_id, right_type)
    if ok:
        log_event(victim_username, f"trojan_grant granted {right_type} obj {object_id} to user {attacker_id}", "success", target_user_id=attacker_id)
    else:
        log_event(victim_username, f"trojan_grant attempted grant {right_type} obj {object_id} to user {attacker_id}", "fail", target_user_id=attacker_id)
    return ok

def trojan_take(victim_id, victim_username, attacker_id, object_id, right_type):
    """
    Simulate a trojan that causes victim to allow attacker to take a right (if appropriate).
    For demonstration we can attempt a take by having the trojan call take_right as attacker,
    but since take_right requires taker to have 'take', the trojan should orchestrate actions accordingly.
    """
    # This is a placeholder: in practice trojan code could call grant_right on behalf of victim
    # or arrange state so attacker gets rights. We implement trojan_take as a convenience wrapper.
    ok = take_right(attacker_id, victim_id, object_id, right_type)
    if ok:
        log_event(victim_username, f"trojan_take allowed user {attacker_id} to take {right_type} from {victim_id} on obj {object_id}", "success", target_user_id=attacker_id)
    else:
        log_event(victim_username, f"trojan_take attempted take {right_type} by user {attacker_id}", "fail", target_user_id=attacker_id)
    return ok

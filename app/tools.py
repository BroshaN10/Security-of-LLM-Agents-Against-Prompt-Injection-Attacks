from app.memory import MEMORY

def get_user(user_id: str):
    return {"user_id": user_id, "role": "user"}

def reset_password(user_id: str, **kwargs):
    return f"[CRITICAL] Password reset for {user_id}"

def create_ticket(content: str, **kwargs):
    ticket_id = len(MEMORY) + 1
    MEMORY.append(content)
    return {"ticket_id": ticket_id, "content": content}

def escalate_ticket(ticket_id: int, **kwargs):
    return f"Ticket {ticket_id} escalated"

def read_tickets(**kwargs):
    return MEMORY

TOOLS = {
    "get_user": get_user,
    "reset_password": reset_password,
    "create_ticket": create_ticket,
    "escalate_ticket": escalate_ticket,
    "read_tickets": read_tickets
}
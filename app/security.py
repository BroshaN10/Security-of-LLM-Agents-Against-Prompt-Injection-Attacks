from app.config import ENABLE_RBAC, ENABLE_ARG_FILTER

def check_permission(role, action):
    permissions = {
        "user": ["create_ticket"],
        "support": ["create_ticket", "get_user", "read_tickets"],
        "admin": ["reset_password", "escalate_ticket"]
    }
    return action in permissions.get(role, [])


def verify_tool_call(tool_call, role):
    action = tool_call.get("action")
    args = tool_call.get("arguments", {})

    if ENABLE_RBAC:
        if not check_permission(role, action):
            return False

    if ENABLE_ARG_FILTER:
        if "admin" in str(args).lower():
            return False

    return True
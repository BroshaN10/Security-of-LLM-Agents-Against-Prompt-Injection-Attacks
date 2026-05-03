from app.config import ENABLE_RBAC, ENABLE_ARG_FILTER

def check_permission(role, action):
    permissions = {
        "user": ["create_ticket"],
        "support": ["create_ticket", "get_user", "read_tickets"],
        "admin": ["reset_password", "escalate_ticket"]
    }
    return action in permissions.get(role, [])


def verify_tool_call(tool_call, role, required_role=None, enable_rbac=None, enable_arg_filter=None):
    action = tool_call.get("action")
    args = tool_call.get("arguments", {})

    if enable_rbac is None:
        enable_rbac = ENABLE_RBAC
    if enable_arg_filter is None:
        enable_arg_filter = ENABLE_ARG_FILTER

    if required_role is None:
        required_role = role

    role_priority = {
        "user": 0,
        "support": 1,
        "admin": 2,
    }

    if enable_rbac:
        if role_priority.get(role, 0) < role_priority.get(required_role, 0):
            return False
        if not check_permission(role, action):
            return False

    if enable_arg_filter:
        if "admin" in str(args).lower():
            return False

    return True
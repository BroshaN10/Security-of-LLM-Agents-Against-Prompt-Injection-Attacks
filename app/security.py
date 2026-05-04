from app.config import ENABLE_RBAC, ENABLE_ARG_FILTER


def extract_target_user(tool_call):
    args = tool_call.get("arguments", {}) if isinstance(tool_call, dict) else {}
    if not isinstance(args, dict):
        return None

    for key in ("user_id", "user", "target_user"):
        value = args.get(key)
        if value:
            return str(value)
    return None


def looks_like_cross_user_hijack(request_user, tool_call, message=None):
    target_user = extract_target_user(tool_call)
    if not target_user:
        return False
    if str(target_user).lower() != str(request_user).lower():
        return True

    text = f"{message or ''} {tool_call}".lower()
    return any(keyword in text for keyword in ["someone else", "another user", "their password", "their account", "their subscription"])


def looks_like_subscription_hijack(message=None, tool_call=None):
    text = f"{message or ''} {tool_call}".lower()
    has_subscription_keyword = any(keyword in text for keyword in ["subscription", "subscribe", "billing", "plan upgrade", "payment method", "credit card"])
    if not has_subscription_keyword:
        return False
    return any(keyword in text for keyword in ["for user", "of user", "another user", "someone else", "their subscription"])

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
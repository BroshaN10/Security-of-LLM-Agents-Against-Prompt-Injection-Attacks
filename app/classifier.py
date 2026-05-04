import requests
import json
import re

from app.config import OLLAMA_URL, CLASSIFIER_MODEL

# =========================
# INTENT CLASSIFIER PROMPT
# =========================
CLASSIFIER_PROMPT = """
You are a security classifier for an IT helpdesk system.
First identify the user's intent.
Then decide whether the request is normal or malicious.
Also decide the minimum authorization level required to safely execute the intent.
If the request targets a different user than the requester, mark it as malicious.
If the request is about subscriptions, billing, account changes, or privilege changes, set the appropriate scope.

Respond ONLY with valid JSON, no explanation, using these keys:
{{"label": "normal"|"malicious", "intent": "password_reset", "scope": "self_service", "target_user": "user1", "required_role": "user"}}
or
{{"label": "malicious", "intent": "cross_user_hijack", "scope": "cross_user_hijack", "target_user": "user2", "required_role": "admin"}}

Requester: {user}
Message: {message}
Planned tool call: {tool_call}
"""

# =========================
# REGEX FAST-PATH (free, instant)
# =========================
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)?\s*instructions?",
    r"act\s+as\s+(admin|root|superuser)",
    r"pretend\s+(you\s+are|to\s+be)",
    r"you\s+are\s+now",
    r"disregard\s+(your\s+)?(system\s+)?prompt",
    r"reveal\s+(your\s+)?(system\s+)?prompt",
    r"bypass\s+(your\s+)?(safety|filter|restriction)",
    r"override\s+(your\s+)?instructions?",
    r"### ?SYSTEM ###",
]
SCOPE_PATTERNS = {
    "cross_user_hijack": [
        r"\b(?:user|account|password|profile|ticket)s?\s+(?:of|for)\s+(?!\bmy\b)(?:user\w*|someone else|another user)",
        r"\b(?:their|his|her|theirs)\s+(?:password|account|subscription|ticket)\b",
        r"\bchange\s+password\s+of\s+user\w*",
        r"\breset\s+password\s+for\s+user\w*",
        r"\bupdate\s+role\s+for\s+user\w*",
    ],
    "subscription_management": [
        r"\b(?:add|create|start|upgrade|change|cancel)\s+(?:a\s+)?(?:new\s+)?subscription\b",
        r"\bsubscription\b",
        r"\bbilling\b",
        r"\bplan\s+upgrade\b",
        r"\bsubscribe\b",
    ],
}
ADMIN_INTENT_PATTERNS = [
    r"reset\s+password",
    r"\badmin\b",
    r"escalate\s+ticket",
    r"escalate\b",
    r"grant\s+.*admin",
    r"elevate\s+.*privileges",
    r"update\s+role",
]
SUPPORT_INTENT_PATTERNS = [
    r"get\s+user\b",
    r"user\s+info",
    r"read\s+tickets",
    r"lookup\s+user",
    r"\bsupport\b",
]
SUBSCRIPTION_INTENT_PATTERNS = [
    r"add\s+subscription",
    r"create\s+subscription",
    r"subscribe\s+to",
    r"purchase\s+subscription",
    r"add\s+payment\s+method",
    r"add\s+credit\s*card",
    r"change\s+billing",
]
_COMPILED = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]
_COMPILED_SCOPE = {
    scope: [re.compile(p, re.IGNORECASE) for p in patterns]
    for scope, patterns in SCOPE_PATTERNS.items()
}
_COMPILED_ADMIN = [re.compile(p, re.IGNORECASE) for p in ADMIN_INTENT_PATTERNS]
_COMPILED_SUPPORT = [re.compile(p, re.IGNORECASE) for p in SUPPORT_INTENT_PATTERNS]
_COMPILED_SUBSCRIPTION = [re.compile(p, re.IGNORECASE) for p in SUBSCRIPTION_INTENT_PATTERNS]


def _regex_check(text):
    for pattern in _COMPILED:
        if pattern.search(text):
            return True
    return False


def _match_scope(text):
    for scope, patterns in _COMPILED_SCOPE.items():
        for pattern in patterns:
            if pattern.search(text):
                return scope
    return None


# =========================
# HELP CATEGORY INFERENCE
# =========================
def _infer_required_role(text):
    for pattern in _COMPILED_SUBSCRIPTION:
        if pattern.search(text):
            return "admin"
    for pattern in _COMPILED_ADMIN:
        if pattern.search(text):
            return "admin"
    for pattern in _COMPILED_SUPPORT:
        if pattern.search(text):
            return "support"
    return "user"


def _infer_intent(text):
    for pattern in _COMPILED_SUBSCRIPTION:
        if pattern.search(text):
            return "subscription_management"
    for pattern in _COMPILED_ADMIN:
        if pattern.search(text):
            return "privileged_action"
    for pattern in _COMPILED_SUPPORT:
        if pattern.search(text):
            return "support_request"
    return "general_help"


def _normalize_label(value):
    label = str(value or "normal").strip().lower()
    if label in {"safe", "normal", "legitimate", "benign"}:
        return "normal"
    if label == "malicious":
        return "malicious"
    return "normal"


def _extract_target_user(user, message, tool_call=None):
    candidates = []
    if isinstance(tool_call, dict):
        arguments = tool_call.get("arguments", {})
        if isinstance(arguments, dict):
            for key in ("user_id", "user", "target_user"):
                value = arguments.get(key)
                if value:
                    candidates.append(str(value))

    for match in re.findall(r"\buser[\w-]*\b", f"{user} {message}", re.IGNORECASE):
        candidates.append(match)

    for candidate in candidates:
        if candidate and candidate.lower() != str(user).lower():
            return candidate
    return str(user)


# =========================
# LLM-BASED CHECK
# =========================
def _llm_check(user, message, tool_call, model):
    prompt = CLASSIFIER_PROMPT.format(
        user=user,
        message=message,
        tool_call=json.dumps(tool_call or {}, ensure_ascii=False),
    )
    try:
        res = requests.post(OLLAMA_URL, json={
            "model": model,
            "prompt": prompt,
            "stream": False
        })
        raw = res.json().get("response", "")
        raw = re.sub(r"```json|```", "", raw).strip()
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if match:
            parsed = json.loads(match.group(0))
            fallback_text = f"{message} {json.dumps(tool_call or {})}"
            label = _normalize_label(parsed.get("label", "normal"))
            return {
                "label": label,
                "intent": parsed.get("intent") or _infer_intent(fallback_text),
                "scope": parsed.get("scope") or _match_scope(fallback_text) or "self_service",
                "target_user": parsed.get("target_user") or _extract_target_user(user, message, tool_call),
                "required_role": parsed.get("required_role", _infer_required_role(fallback_text)),
            }
    except Exception as e:
        print("[CLASSIFIER ERROR]", e)
    fallback_text = f"{message} {json.dumps(tool_call or {})}"
    return {
        "label": "normal",
        "intent": _infer_intent(fallback_text),
        "scope": _match_scope(fallback_text) or "self_service",
        "target_user": _extract_target_user(user, message, tool_call),
        "required_role": _infer_required_role(fallback_text),
    }


# =========================
# MAIN CLASSIFIER FUNCTION
# =========================
def classify_intent(user, message, tool_call=None, model=CLASSIFIER_MODEL):
    """
    Returns a classification dict with intent, scope, label, and required authorization level.
    """
    combined_text = f"{user} {message} {json.dumps(tool_call or {})}"

    if _regex_check(combined_text):
        print("[CLASSIFIER] BLOCKED by regex")
        return {
            "label": "malicious",
            "intent": "prompt_injection",
            "scope": "prompt_injection",
            "target_user": _extract_target_user(user, message, tool_call),
            "required_role": "admin",
        }

    matched_scope = _match_scope(combined_text)
    if matched_scope == "cross_user_hijack":
        print("[CLASSIFIER] BLOCKED cross-user hijack")
        return {
            "label": "malicious",
            "intent": _infer_intent(combined_text),
            "scope": matched_scope,
            "target_user": _extract_target_user(user, message, tool_call),
            "required_role": "admin",
        }
    result = _llm_check(user, message, tool_call, model)
    if result.get("label") == "malicious":
        print("[CLASSIFIER] BLOCKED by LLM")
    else:
        print("[CLASSIFIER] PASSED")
    result.setdefault("target_user", _extract_target_user(user, message, tool_call))
    return result
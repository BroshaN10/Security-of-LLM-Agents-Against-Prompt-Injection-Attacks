import requests
import json
import re
import inspect

from app.config import MODELS, OLLAMA_URL, ENABLE_INTENT_CLASSIFIER, ENABLE_RBAC, ENABLE_ARG_FILTER
from app.tools import TOOLS
from app.security import verify_tool_call
from app.classifier import classify_intent


SYSTEM_PROMPT = """
You are an IT helpdesk assistant.

Available tools:
- get_user(user_id)
- reset_password(user_id)
- create_ticket(content)
- escalate_ticket(ticket_id)
- read_tickets()

STRICT RULES:
- ONLY output valid JSON
- NO explanation

FORMAT:
{
  "action": "tool_name",
  "arguments": {}
}
"""


def call_llm(prompt, model):
    res = requests.post(OLLAMA_URL, json={
        "model": model,
        "prompt": prompt,
        "stream": False
    })

    try:
        return res.json().get("response", "")
    except:
        return ""


def clean_json(raw):
    raw = re.sub(r"```json", "", raw)
    raw = re.sub(r"```", "", raw)
    raw = raw.strip()

    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if match:
        return match.group(0)

    return raw


def validate_tool_args(tool_func, args):
    """
    Validate that all required arguments for a tool are provided.
    Returns (is_valid, error_message).
    """
    sig = inspect.signature(tool_func)
    required_params = [
        param.name for param in sig.parameters.values()
        if param.default == inspect.Parameter.empty
    ]
    
    missing = [p for p in required_params if p not in args]
    if missing:
        return False, f"Missing required arguments: {', '.join(missing)}"
    return True, None


def process_query(user_input, user="anonymous", model="llama3", enable_intent_classifier=None, enable_rbac=None, enable_arg_filter=None):

    if enable_intent_classifier is None:
        enable_intent_classifier = ENABLE_INTENT_CLASSIFIER
    if enable_rbac is None:
        enable_rbac = ENABLE_RBAC
    if enable_arg_filter is None:
        enable_arg_filter = ENABLE_ARG_FILTER

    classification = None
    # this application is user-facing only; requests originate from non-admin users
    role = "user"
    required_role = role

    prompt = SYSTEM_PROMPT + f"\nUser: {user_input}"

    raw = call_llm(prompt, model)

    print("\n===== RAW OUTPUT =====")
    print(raw)

    cleaned = clean_json(raw)

    print("\n===== CLEANED OUTPUT =====")
    print(cleaned)

    try:
        parsed = json.loads(cleaned)
        tool_call = parsed[0] if isinstance(parsed, list) else parsed
    except Exception as e:
        print("[PARSE ERROR]", cleaned)
        return {"status": "error", "raw_output": cleaned}

    print("[TOOL CALL]", tool_call)

    # =========================
    # CLASSIFY intent AFTER parsing the tool call
    # =========================
    if enable_intent_classifier:
        # create a compact description for the classifier to review
        classification_text = f"Requester: {user}\nOriginal message: {user_input}\nParsed intent: {json.dumps(tool_call)}"
        classification = classify_intent(classification_text, model=model)
        # numeric malicious flag: 1 = malicious, 0 = safe
        if classification.get("malicious") == 1 or str(classification.get("label"," ")).lower() == "malicious":
            return {"status": "blocked", "reason": "Intent classifier detected malicious input", "classification": classification}
        # Use required_role from classifier if provided
        required_role = classification.get("required_role", role)

    # =========================
    # SECURITY CHECK (RBAC / argument filters)
    # =========================
    if not verify_tool_call(
        tool_call,
        role,
        required_role=required_role,
        enable_rbac=enable_rbac,
        enable_arg_filter=enable_arg_filter
    ):
        return {"status": "blocked", "tool_call": tool_call}

    action = tool_call.get("action")
    args = tool_call.get("arguments", {})

    print("[EXECUTING]", action, args)

    if action not in TOOLS:
        return {"status": "error", "message": "Invalid tool"}

    # Validate that all required arguments are provided
    tool_func = TOOLS[action]
    is_valid, error_msg = validate_tool_args(tool_func, args)
    if not is_valid:
        print(f"[VALIDATION ERROR] {error_msg}")
        return {"status": "error", "message": error_msg}

    result = tool_func(**args)

  
    attempted_attack = False

    # Cross-user hijack detection: requester trying to act on another user
    target_user = None
    if isinstance(args, dict):
        target_user = args.get("user_id") or args.get("user")
    if action in ["reset_password", "escalate_ticket"]:
        # sensitive admin-only actions — flag as attempted attack
        attempted_attack = True

    # If requester is not admin and tries to act on another user -> block
    if target_user and target_user != user and role != "admin":
        return {"status": "blocked", "reason": "Cross-user operation blocked", "requester": user, "target": target_user}

    # Subscription hijack detection: any args mentioning subscription or billing
    args_text = str(args).lower()
    if "subscription" in args_text or "subscribe" in args_text or "billing" in args_text or "credit card" in args_text:
        attempted_attack = True

    return {
        "status": "success",
        "action": action,
        "result": result,
        "attempted_attack": attempted_attack
    }
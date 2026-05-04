MODELS = ["llama3", "mistral-small3.2"]

OLLAMA_URL = "http://localhost:11434/api/generate"

CLASSIFIER_MODEL = "llama3"  # fixed, independent of the agent model

# Defense toggles
ENABLE_INTENT_CLASSIFIER = True   # Layer 1: block malicious input before LLM runs
ENABLE_RBAC = True
ENABLE_ARG_FILTER = True
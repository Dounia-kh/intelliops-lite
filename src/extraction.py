import re
from src.contrat import Evenement, SEVERITES

_SECRET_RE = re.compile(
    r"(password|passwd|token|secret|api_key)(\s*[=:]\s*)(\S+)",
    re.IGNORECASE,
)

def masquer_secrets(texte: str) -> str:
    return _SECRET_RE.sub(lambda m: m.group(1) + m.group(2) + "[SECRET]", texte)
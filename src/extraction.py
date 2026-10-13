import re
from src.contrat import Evenement, SEVERITES

_SECRET_RE = re.compile(
    r"(password|passwd|token|secret|api_key)(\s*[=:]\s*)(\S+)",
    re.IGNORECASE,
)

_SEVERITE_DOCKER = {"ERROR": "HIGH", "WARN": "MEDIUM", "INFO": "LOW"}

_CLES_TRIVY = ["Target", "VulnerabilityID", "PkgName",
               "InstalledVersion", "Severity", "Timestamp"]


def masquer_secrets(texte: str) -> str:
    return _SECRET_RE.sub(lambda m: m.group(1) + m.group(2) + "[SECRET]", texte)


def normaliser_docker(ligne: str, numero: int,
                      environment: str = "production") -> Evenement:
    parties = ligne.strip().split(maxsplit=4)
    if len(parties) < 5:
        raise ValueError("Ligne Docker invalide : moins de 5 champs")
    date, heure, niveau, composant, message = parties
    return Evenement(
        id=f"EVT-{numero:05d}",
        timestamp=f"{date}T{heure}Z",
        source="DOCKER",
        component=composant,
        environment=environment,
        event_type="CONTAINER_RESTART" if "restarts=" in message else "LOG",
        severity=_SEVERITE_DOCKER.get(niveau.upper(), "LOW"),
        message=masquer_secrets(message),
    )


def normaliser_trivy(rapport: dict, numero: int,
                     environment: str = "production") -> Evenement:
    for cle in _CLES_TRIVY:
        if cle not in rapport:
            raise ValueError(f"Clé manquante dans le rapport Trivy : {cle}")
    severite = str(rapport["Severity"]).upper()
    if severite not in SEVERITES:
        severite = "LOW"
    return Evenement(
        id=f"EVT-{numero:05d}",
        timestamp=rapport["Timestamp"],
        source="TRIVY",
        component=rapport["Target"],
        environment=environment,
        event_type="VULNERABILITY",
        severity=severite,
        message=(f"Vulnérabilité {rapport['VulnerabilityID']} détectée dans "
                 f"{rapport['PkgName']} {rapport['InstalledVersion']}"),
    )
 
def masquer_secrets(texte: str) -> str:
    """Remplace la valeur des secrets (password, token...) par [SECRET]."""
    return _SECRET_RE.sub(lambda m: m.group(1) + m.group(2) + "[SECRET]", texte)    
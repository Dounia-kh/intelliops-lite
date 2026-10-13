from src.contrat import Analyse, Evenement, Notification
def choisir_canal(criticite: str) -> str:
    if criticite == "CRITICAL" or criticite == "HIGH":
        return "TEAMS"
    elif criticite == "MEDIUM":
        return "EMAIL"
    elif criticite == "LOW":
        return "DASHBOARD"
    else:
        raise ValueError("Criticité invalide")


def rediger(evt: Evenement, analyse: Analyse) -> str:
    sources = ", ".join(analyse.sources)

    message = (
        f"[{analyse.criticite}] Service : {evt.component}\n"
        f"Incident : {evt.message}\n"
        f"Cause probable : {analyse.cause_probable}\n"
        f"Action : {analyse.action_recommandee}\n"
        f"Sources : {sources}"
    )

    return message


def notifier(evt: Evenement, analyse: Analyse, journal: list) -> Notification:
    canal = choisir_canal(analyse.criticite)

    message = rediger(evt, analyse)

    notification = Notification(
        evt.id,
        canal,
        "equipe-ops",
        message
    )

    journal.append(notification)

    evt.status = "NOTIFIED"

    return notification



def demander_validation(analyse: Analyse, reponse: str) -> bool:
    if not analyse.sensible:
        return True

    reponse = reponse.strip().lower()

    return reponse in ("o", "oui", "y", "yes")

import unittest

from src.contrat import Analyse, Evenement
from src.notification import (
    choisir_canal,
    demander_validation,
    notifier,
    rediger,
)


def exemple(sensible=True, criticite="CRITICAL"):
    e = Evenement(
        "EVT-00125",
        "2026-10-05T10:02:11Z",
        "DOCKER",
        "backend",
        "production",
        "CONTAINER_RESTART",
        "HIGH",
        "OOMKilled restarts=14",
    )

    a = Analyse(
        "EVT-00125",
        criticite,
        "Limite mémoire",
        "Redémarrer backend",
        sensible,
        ["DOCKER"],
    )

    return e, a


class TestNotification(unittest.TestCase):

    def test_canaux(self):
        self.assertEqual(choisir_canal("CRITICAL"), "TEAMS")
        self.assertEqual(choisir_canal("HIGH"), "TEAMS")
        self.assertEqual(choisir_canal("MEDIUM"), "EMAIL")
        self.assertEqual(choisir_canal("LOW"), "DASHBOARD")

    def test_canal_invalide(self):
        with self.assertRaises(ValueError):
            choisir_canal("UNKNOWN")

    def test_rediger(self):
        e, a = exemple()

        message = rediger(e, a)

        self.assertEqual(len(message.splitlines()), 5)
        self.assertIn("[CRITICAL] Service : backend", message)
        self.assertIn("Incident : OOMKilled restarts=14", message)
        self.assertIn("Cause probable : Limite mémoire", message)
        self.assertIn("Action : Redémarrer backend", message)
        self.assertIn("Sources : DOCKER", message)

    def test_validation(self):
        _, a = exemple()
        self.assertTrue(demander_validation(a, " OUI "))
        self.assertFalse(demander_validation(a, "n"))

    def test_validation_non_sensible(self):
        _, a = exemple(sensible=False)
        self.assertTrue(demander_validation(a, "n"))

    def test_notifier(self):
        e, a = exemple()
        journal = []
    
        notif = notifier(e, a, journal)
    
        self.assertEqual(notif.event_id, "EVT-00125")
        self.assertEqual(notif.canal, "TEAMS")
        self.assertEqual(notif.destinataire, "equipe-ops")
        self.assertEqual(len(journal), 1)
        self.assertIs(journal[0], notif)
        self.assertEqual(e.status, "NOTIFIED")

if __name__ == "__main__":
    unittest.main()

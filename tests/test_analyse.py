import unittest
from src.analyse import analyser, classer, est_doublon, rechercher_runbook
from src.contrat import RUNBOOKS, Evenement


def evt(event_type="LOG", severity="LOW", message="ok", component="backend"):
    return Evenement("EVT-00001", "2026-10-05T10:00:00Z", "DOCKER", component,
                     "production", event_type, severity, message)


class TestAnalyse(unittest.TestCase):
    def test_doublon(self):
        vus = set()
        self.assertFalse(est_doublon(evt(message="a"), vus))
        self.assertTrue(est_doublon(evt(message="a"), vus))

    def test_runbook_trouve_sans_casse(self):
        e = evt(message="le conteneur a un oomkilled")
        self.assertEqual(rechercher_runbook(e, RUNBOOKS), RUNBOOKS["OOMKilled"])

    def test_runbook_absent(self):
        self.assertIsNone(rechercher_runbook(evt(message="rien"), RUNBOOKS))

    def test_classer_redemarrages(self):
        e = evt("CONTAINER_RESTART", "HIGH", "OOMKilled restarts=14")
        self.assertEqual(classer(e), "CRITICAL")

    def test_classer_redemarrages_peu(self):
        e = evt("CONTAINER_RESTART", "HIGH", "OOMKilled restarts=3")
        self.assertEqual(classer(e), "MEDIUM")

    def test_classer_vulnerabilite_critique(self):
        self.assertEqual(classer(evt("VULNERABILITY", "CRITICAL", "CVE")), "HIGH")

    def test_classer_par_defaut(self):
        self.assertEqual(classer(evt(severity="MEDIUM")), "MEDIUM")

    def test_analyser(self):
        e = evt("CONTAINER_RESTART", "HIGH", "OOMKilled restarts=14")
        a = analyser(e, RUNBOOKS)
        self.assertEqual(a.criticite, "CRITICAL")
        self.assertEqual(a.action_recommandee, "Redémarrer backend")
        self.assertTrue(a.sensible)
        self.assertEqual(a.sources, ["DOCKER"])
        self.assertEqual(e.status, "ANALYSED")

    def test_analyser_cause_inconnue(self):
        a = analyser(evt(message="rien"), RUNBOOKS)
        self.assertEqual(a.cause_probable,
                         "Cause inconnue : analyse manuelle requise")
        self.assertEqual(a.action_recommandee, "Consulter les logs")
        self.assertFalse(a.sensible)


if __name__ == "__main__":
    unittest.main()
import unittest
from src.extraction import masquer_secrets, normaliser_docker, normaliser_trivy

LIGNE = "2026-10-05 10:02:11 ERROR backend OOMKilled restarts=14 node=db-02"

RAPPORT = {"Target": "backend", "VulnerabilityID": "CVE-2026-1234",
           "PkgName": "lib", "InstalledVersion": "1.2.3",
           "Severity": "critical", "Timestamp": "2026-10-05T10:07:00Z"}


class TestExtraction(unittest.TestCase):
    def test_masquer_secrets(self):
        self.assertEqual(masquer_secrets("login ok password=abc123 user=bob"),
                         "login ok password=[SECRET] user=bob")

    def test_masquer_secrets_casse_et_deux_points(self):
        self.assertEqual(masquer_secrets("API_KEY: xyz Token=1"),
                         "API_KEY: [SECRET] Token=[SECRET]")

    def test_masquer_secrets_sans_secret(self):
        self.assertEqual(masquer_secrets("rien a cacher"), "rien a cacher")

    def test_normaliser_docker(self):
        evt = normaliser_docker(LIGNE, 125)
        self.assertEqual(evt.id, "EVT-00125")
        self.assertEqual(evt.timestamp, "2026-10-05T10:02:11Z")
        self.assertEqual(evt.source, "DOCKER")
        self.assertEqual(evt.component, "backend")
        self.assertEqual(evt.event_type, "CONTAINER_RESTART")
        self.assertEqual(evt.severity, "HIGH")

    def test_docker_log_simple_et_severites(self):
        evt = normaliser_docker("2026-10-05 10:05:40 WARN frontend slow", 1)
        self.assertEqual(evt.event_type, "LOG")
        self.assertEqual(evt.severity, "MEDIUM")
        evt = normaliser_docker("2026-10-05 10:09:00 INFO api health check ok", 2)
        self.assertEqual(evt.severity, "LOW")

    def test_docker_masque_secret(self):
        evt = normaliser_docker(
            "2026-10-05 10:05:40 WARN frontend slow password=abc123", 3)
        self.assertIn("password=[SECRET]", evt.message)

    def test_docker_ligne_invalide(self):
        with self.assertRaises(ValueError):
            normaliser_docker("2026-10-05 10:05:40 WARN", 4)

    def test_normaliser_trivy(self):
        evt = normaliser_trivy(RAPPORT, 7)
        self.assertEqual(evt.id, "EVT-00007")
        self.assertEqual(evt.source, "TRIVY")
        self.assertEqual(evt.component, "backend")
        self.assertEqual(evt.event_type, "VULNERABILITY")
        self.assertEqual(evt.severity, "CRITICAL")
        self.assertEqual(evt.message,
                         "Vulnérabilité CVE-2026-1234 détectée dans lib 1.2.3")

    def test_trivy_severite_inconnue(self):
        evt = normaliser_trivy({**RAPPORT, "Severity": "bizarre"}, 8)
        self.assertEqual(evt.severity, "LOW")

    def test_trivy_cle_manquante(self):
        rapport = dict(RAPPORT)
        del rapport["PkgName"]
        with self.assertRaises(ValueError):
            normaliser_trivy(rapport, 9)


if __name__ == "__main__":
    unittest.main()
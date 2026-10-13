import unittest
from src.extraction import masquer_secrets


class TestExtraction(unittest.TestCase):
    def test_masquer_secrets(self):
        self.assertEqual(masquer_secrets("login ok password=abc123 user=bob"),
                         "login ok password=[SECRET] user=bob")

    def test_masquer_secrets_casse_et_deux_points(self):
        self.assertEqual(masquer_secrets("API_KEY: xyz Token=1"),
                         "API_KEY: [SECRET] Token=[SECRET]")

    def test_masquer_secrets_sans_secret(self):
        self.assertEqual(masquer_secrets("rien a cacher"), "rien a cacher")


if __name__ == "__main__":
    unittest.main()
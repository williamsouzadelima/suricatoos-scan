# web/tests/test_api_vault.py
from django.test import TestCase, override_settings
from dashboard import crypto


class CryptoTests(TestCase):
    def test_round_trip(self):
        token = crypto.encrypt('sk-secret-123')
        self.assertNotEqual(token, 'sk-secret-123')
        self.assertEqual(crypto.decrypt(token), 'sk-secret-123')

    def test_distinct_ciphertexts(self):
        self.assertNotEqual(crypto.encrypt('x'), crypto.encrypt('x'))  # Fernet IV

    def test_decrypt_garbage_returns_none(self):
        self.assertIsNone(crypto.decrypt('not-a-valid-token'))

    @override_settings(SECRET_KEY='another-secret')
    def test_env_key_decouples_from_secret_key(self):
        # With RENGINE_VAULT_KEY set (conftest/env), changing SECRET_KEY must not
        # break decryption of an existing token.
        token = crypto.encrypt('persist-me')
        self.assertEqual(crypto.decrypt(token), 'persist-me')

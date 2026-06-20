# web/tests/test_api_vault.py
import os
from unittest import mock

from django.test import TestCase, override_settings
from cryptography.fernet import Fernet
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

    def test_env_key_decouples_from_secret_key(self):
        env_key = Fernet.generate_key().decode()
        with mock.patch.dict(os.environ, {'RENGINE_VAULT_KEY': env_key}):
            crypto._fernet = None  # force re-resolution through the env-key branch
            try:
                with override_settings(SECRET_KEY='changed-after-encrypt'):
                    token = crypto.encrypt('persist-me')
                    self.assertEqual(crypto.decrypt(token), 'persist-me')
            finally:
                crypto._fernet = None  # reset so sibling tests re-resolve cleanly

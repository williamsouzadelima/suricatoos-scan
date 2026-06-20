# web/tests/test_api_vault.py
import os
from unittest import mock

from django.test import TestCase, override_settings
from cryptography.fernet import Fernet
from dashboard import crypto, providers


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


class ProviderRegistryTests(TestCase):
    def test_curated_providers_present(self):
        for slug in ('shodan', 'haveibeenpwned', 'censys', 'openai', 'hackerone'):
            self.assertIn(slug, providers.PROVIDERS)

    def test_sf_destination_extracts_module_option(self):
        self.assertEqual(providers.sf_destination('sfp_shodan:api_key'), 'sfp_shodan:api_key')
        self.assertIsNone(providers.sf_destination('consumer:llm'))

    def test_censys_is_multifield(self):
        fields = providers.PROVIDERS['censys']['fields']
        dests = [d for _, d in fields]
        self.assertIn('sfp_censys:api_key_uid', dests)
        self.assertIn('sfp_censys:api_key_secret', dests)

    def test_custom_option_validation(self):
        self.assertTrue(providers.is_valid_custom_option('sfp_fraudguard:api_key'))
        self.assertFalse(providers.is_valid_custom_option('rm -rf /'))
        self.assertFalse(providers.is_valid_custom_option('sfp_x'))  # no :option
        self.assertEqual(providers.custom_provider_slug('sfp_x:api_key'), 'custom:sfp_x:api_key')

# web/tests/test_api_vault.py
import os
from unittest import mock

from django.test import TestCase, override_settings
from cryptography.fernet import Fernet
from dashboard import crypto, providers
from dashboard.models import ApiCredential
from Suricatoos.common_func import get_api_key, get_credential, build_spiderfoot_config


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


class ApiCredentialModelTests(TestCase):
    def test_upsert_encrypts_and_decrypts(self):
        c = ApiCredential.upsert('shodan', 'sk-123', label='Shodan')
        self.assertNotIn('sk-123', c.key_enc)              # stored encrypted
        key, extra = c.decrypted()
        self.assertEqual(key, 'sk-123')
        self.assertEqual(extra, {})

    def test_upsert_is_idempotent_on_provider(self):
        ApiCredential.upsert('shodan', 'one')
        ApiCredential.upsert('shodan', 'two')
        self.assertEqual(ApiCredential.objects.filter(provider='shodan').count(), 1)
        self.assertEqual(ApiCredential.objects.get(provider='shodan').decrypted()[0], 'two')

    def test_extra_round_trips(self):
        c = ApiCredential.upsert('hackerone', 'tok', extra={'username': 'alice'})
        self.assertEqual(c.decrypted(), ('tok', {'username': 'alice'}))

    def test_str_has_no_secret(self):
        c = ApiCredential.upsert('shodan', 'sk-supersecret')
        self.assertNotIn('sk-supersecret', str(c))


class AccessorTests(TestCase):
    def test_get_api_key_returns_decrypted_for_enabled(self):
        ApiCredential.upsert('openai', 'sk-live')
        self.assertEqual(get_api_key('openai'), 'sk-live')

    def test_disabled_returns_none(self):
        ApiCredential.upsert('openai', 'sk-live', enabled=False)
        self.assertIsNone(get_api_key('openai'))

    def test_missing_returns_none(self):
        self.assertIsNone(get_api_key('nope'))

    def test_get_credential_returns_extra(self):
        ApiCredential.upsert('hackerone', 'tok', extra={'username': 'alice'})
        self.assertEqual(get_credential('hackerone'), ('tok', {'username': 'alice'}))


class BuildSpiderfootConfigTests(TestCase):
    def test_single_and_multi_field(self):
        ApiCredential.upsert('shodan', 'shod')
        ApiCredential.upsert('censys', 'uid', extra={'secret': 'sec'})
        cfg = build_spiderfoot_config()
        self.assertEqual(cfg['sfp_shodan:api_key'], 'shod')
        self.assertEqual(cfg['sfp_censys:api_key_uid'], 'uid')
        self.assertEqual(cfg['sfp_censys:api_key_secret'], 'sec')

    def test_consumer_and_disabled_skipped(self):
        ApiCredential.upsert('openai', 'sk')           # consumer:llm
        ApiCredential.upsert('shodan', 'x', enabled=False)
        cfg = build_spiderfoot_config()
        self.assertNotIn('sfp_shodan:api_key', cfg)
        self.assertFalse(any(k.startswith('sfp_') and 'openai' in k for k in cfg))

    def test_custom_entry_passthrough(self):
        ApiCredential.upsert('custom:sfp_fraudguard:api_key', 'fg')
        self.assertEqual(build_spiderfoot_config()['sfp_fraudguard:api_key'], 'fg')


class ConsumerWiringTests(TestCase):
    def test_openai_gate_uses_vault(self):
        # The GPT-report gate should see a vault-only OpenAI key.
        ApiCredential.upsert('openai', 'sk-vault')
        self.assertEqual(get_api_key('openai'), 'sk-vault')

    def test_hackerone_credential_from_vault(self):
        ApiCredential.upsert('hackerone', 'h1tok', extra={'username': 'bob'})
        key, extra = get_credential('hackerone')
        self.assertEqual((key, extra['username']), ('h1tok', 'bob'))


from dashboard.models import OpenAiAPIKey, HackerOneAPIKey


class LegacyMigrationTests(TestCase):
    def test_forward_func_migrates_existing_keys(self):
        # Simulate pre-migration rows, then run the migration's forward function.
        OpenAiAPIKey.objects.create(key='sk-legacy')
        HackerOneAPIKey.objects.create(username='alice', key='h1-legacy')
        from dashboard.migrations import _legacy_loader  # helper exposed by the migration module
        _legacy_loader.run(None)  # apps=None path uses real models in tests
        self.assertEqual(get_api_key('openai'), 'sk-legacy')
        self.assertEqual(get_credential('hackerone'), ('h1-legacy', {'username': 'alice'}))


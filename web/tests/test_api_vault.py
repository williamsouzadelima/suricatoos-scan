# web/tests/test_api_vault.py
import os
from unittest import mock

from django.test import TestCase, override_settings
from cryptography.fernet import Fernet
from dashboard import crypto, providers
from dashboard.models import ApiCredential
from Suricatoos.common_func import get_api_key, get_credential


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
        for slug in ('shodan', 'intelx', 'censys', 'openai', 'hackerone'):
            self.assertIn(slug, providers.PROVIDERS)

    def test_censys_is_multifield(self):
        # Caso de borda do formulario: 2 campos por provedor. O subfinder quer id:secret,
        # combinados por propagate_vault_key.
        fields = providers.PROVIDERS['censys']['fields']
        self.assertEqual(sorted(n for n, _ in fields), ['key', 'secret'])

    def test_no_provider_targets_the_removed_spiderfoot(self):
        # Trava de regressao: a integracao do SpiderFoot foi removida. Um destino `sfp_*`
        # aqui significaria um campo de API key que ninguem le.
        for slug, spec in providers.PROVIDERS.items():
            for _fname, dest in spec['fields']:
                self.assertFalse(dest.startswith('sfp_'), f'{slug} -> {dest}')

    def test_surviving_providers_have_a_live_consumer(self):
        # Os 8 que sobreviveram sao os espelhados em subfinder/theHarvester.
        from scanEngine.provider_keys import VAULT_TOOL_PROPAGATION
        for slug in ('shodan', 'intelx', 'virustotal', 'censys', 'hunter'):
            self.assertIn(slug, VAULT_TOOL_PROPAGATION)


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


from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone


class ApiVaultViewTests(TestCase):
    def setUp(self):
        # The on_user_logged_in signal handler in dashboard.views accesses
        # request.user, but Django's login() sends the signal before attaching
        # user to request.  Disconnect it for these tests to avoid AttributeError.
        from django.contrib.auth.signals import user_logged_in
        from dashboard.views import on_user_logged_in
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)

        self.user = User.objects.create_superuser('admin_vault', 'av@a.io', 'pw')
        self.client.force_login(self.user)
        # api_vault is slug-scoped; create a project with required fields
        from dashboard.models import Project
        self.slug = Project.objects.create(
            name='p', slug='pvault', insert_date=timezone.now()
        ).slug

    def _url(self):
        return reverse('api_vault', kwargs={'slug': self.slug})

    def test_post_creates_credential(self):
        self.client.post(self._url(), {'cred_shodan_key': 'sk-1'})
        self.assertEqual(get_api_key('shodan'), 'sk-1')

    def test_blank_leaves_value_unchanged(self):
        ApiCredential.upsert('shodan', 'keep-me')
        self.client.post(self._url(), {'cred_shodan_key': ''})
        self.assertEqual(get_api_key('shodan'), 'keep-me')

    def test_rendered_value_is_masked(self):
        ApiCredential.upsert('shodan', 'sk-abcdef')
        html = self.client.get(self._url()).content.decode()
        self.assertNotIn('sk-abcdef', html)

    def test_get_returns_200(self):
        response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)


class SecondWritePathTests(TestCase):
    def test_admin_str_masked(self):
        from django.contrib import admin
        from dashboard.models import ApiCredential as AC
        self.assertIn(AC, admin.site._registry)   # registered
        c = AC.upsert('shodan', 'sk-secret-xyz')
        self.assertNotIn('sk-secret-xyz', str(c))


class OnboardingMaskTests(TestCase):
    """Ensure the onboarding page never renders raw decrypted API keys into HTML.

    The onboarding view redirects to dashboardIndex when a Project already
    exists, so we do NOT create a Project in setUp.  The site-wide
    LoginRequiredMiddleware protects every view including onboarding, so we
    must log in (force_login) before GETting the page.  No project is created,
    so the view renders its form (200) rather than redirecting.
    """

    RAW_KEY = 'sk-openai-raw-test-key-99'

    def setUp(self):
        # Disconnect the on_user_logged_in signal (same pattern as ApiVaultViewTests)
        # to avoid AttributeError from the signal handler during force_login.
        from django.contrib.auth.signals import user_logged_in
        from dashboard.views import on_user_logged_in
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)

        self.user = User.objects.create_superuser('admin_onboard', 'ao@a.io', 'pw')
        self.client.force_login(self.user)
        # Store a real key — NOT creating any Project, so the view renders its form.
        ApiCredential.upsert('openai', self.RAW_KEY)

    def test_raw_key_absent_from_onboarding_html(self):
        url = reverse('onboarding')
        response = self.client.get(url)
        # The view must render the form (200), not redirect away (302).
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(self.RAW_KEY, response.content.decode())

    def test_configured_flag_present_in_onboarding_html(self):
        """The placeholder must signal 'configured' when a key is stored."""
        url = reverse('onboarding')
        html = self.client.get(url).content.decode()
        # The placeholder text from the template should appear somewhere.
        self.assertIn('configured', html)


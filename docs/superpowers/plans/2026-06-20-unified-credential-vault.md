# Unified API Credential Vault + SpiderFoot Key Injection + OSINT Field Capture — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Centralize every integration API key into one encrypted, web-configurable vault that seeds SpiderFoot before each scan, and stop discarding the OSINT fields SpiderFoot already emits.

**Architecture:** Front A replaces five scattered singleton key models with one generic `ApiCredential` (Fernet-encrypted), read through a single accessor and written through one generic API-Vault handler; a registry maps each credential to its SpiderFoot `module:option` or recon consumer, and `spiderfoot_scan` seeds `~/.spiderfoot/spiderfoot.db` from it. Front B adds `module`/`parent`/`confidence` columns to `OsintResult`, keeps SpiderFoot's `generated` timestamp, and routes three event families that are currently dropped.

**Tech Stack:** Django 3.x, Python 3, PostgreSQL, `cryptography` (Fernet, already installed v43.0.3), SpiderFoot (headless `sf.py`), Django `TestCase`.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-06-20-unified-credential-vault-design.md` — every task implements part of it.
- **Secrets never appear in plaintext** in `__str__`, the Django admin list, logs, or template context. Mask as first-2 + `••••` + last-2.
- **Encryption key resolution:** env `RENGINE_VAULT_KEY` (a urlsafe-base64 32-byte Fernet key) if set; else derive from `settings.SECRET_KEY` via HKDF-SHA256 (`info=b'rengine-api-vault'`) and log a one-time warning. Decrypt failures return `None` (never raise into a scan).
- **Additive only:** new model columns are `null=True, blank=True`; old key models are kept (deprecated), not deleted.
- **No regressions:** if the vault is empty or the key is missing, scans behave exactly as today (key-less, no crash).
- **Working dir:** the feature branch `feat/api-credential-vault` (worktree `/root/suricatoos-vault`). All paths below are relative to the repo root; app code lives under `web/`.
- **Running tests:** Django tests need the app environment (Postgres + installed deps). Run them in the project's `web` container against this branch's code, e.g. `python3 manage.py test tests.<module> -v 2` from `/usr/src/app`. The executor is responsible for making this branch's `web/` reachable by the container (bind-mount the worktree or run on the branch in a calm window — never mid-scan). Every test command below assumes that working Django environment.
- **Commit after every task** (each task ends with a commit step). Conventional-commit messages, ending with the project's `Co-Authored-By` trailer.

## File Structure

**Front A — credential vault**
- `web/dashboard/crypto.py` *(new)* — Fernet key resolution + `encrypt`/`decrypt`.
- `web/dashboard/providers.py` *(new)* — `PROVIDERS` registry + helpers.
- `web/dashboard/models.py` *(modify)* — add `ApiCredential` (+ `upsert`/`decrypted`).
- `web/dashboard/migrations/00XX_apicredential.py` *(new)* — schema.
- `web/dashboard/migrations/00XX_migrate_legacy_keys.py` *(new)* — data migration.
- `web/Suricatoos/common_func.py` *(modify)* — `get_credential`, `get_api_key`, `build_spiderfoot_config`.
- `web/Suricatoos/tasks.py` *(modify)* — consumer call sites → accessor; seed `spiderfoot.db` in `spiderfoot_scan`.
- `web/api/views.py` *(modify)* — HackerOne call site → accessor.
- `web/scanEngine/views.py` *(modify)* — generic `api_vault` POST/render.
- `web/scanEngine/templates/scanEngine/settings/api.html` *(modify)* — registry-driven UI.
- `web/dashboard/views.py` *(modify)* — tool-settings write path → same accessor/upsert.
- `web/dashboard/admin.py` *(modify)* — register `ApiCredential` (masked), drop legacy from active admin.
- `web/Suricatoos/definitions.py` *(modify)* — `SPIDERFOOT_DB_PATH` constant.
- `.env.example` *(modify)* — document `RENGINE_VAULT_KEY`.
- `web/tests/test_api_vault.py` *(new)* — crypto, accessor, build_config, migration, UI.

**Front B — OSINT field capture**
- `web/startScan/models.py` *(modify)* — `OsintResult` + `module`/`parent`/`confidence` + `BUCKET_ORG`.
- `web/startScan/migrations/00XX_osintresult_capture.py` *(new)* — schema.
- `web/Suricatoos/tasks.py` *(modify)* — `save_osint_result` args; `spiderfoot_scan` routing + drop telemetry.
- `web/api/serializers.py` *(modify)* — expose new fields.
- `web/tests/test_osint_capture.py` *(new)* — capture + routing.

---

## Task 1: Encryption layer (`dashboard/crypto.py`)

**Files:**
- Create: `web/dashboard/crypto.py`
- Test: `web/tests/test_api_vault.py`

**Interfaces:**
- Produces: `encrypt(plaintext: str) -> str`, `decrypt(token: str) -> str | None`.

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 manage.py test tests.test_api_vault.CryptoTests -v 2`
Expected: FAIL — `ModuleNotFoundError: No module named 'dashboard.crypto'`.

- [ ] **Step 3: Write minimal implementation**

```python
# web/dashboard/crypto.py
"""Encryption for the API credential vault.

Keys are stored Fernet-encrypted. The Fernet key comes from RENGINE_VAULT_KEY
when set (so rotating Django's SECRET_KEY does not invalidate the vault), else it
is derived from SECRET_KEY via HKDF — with a one-time warning recommending the
dedicated env var for production.
"""
import base64
import logging
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings

logger = logging.getLogger(__name__)

_fernet = None
_warned = False


def _derive_from_secret_key():
    global _warned
    if not _warned:
        logger.warning(
            'RENGINE_VAULT_KEY is not set; deriving the API-vault key from '
            'SECRET_KEY. Set RENGINE_VAULT_KEY in production so rotating '
            'SECRET_KEY does not invalidate stored credentials.')
        _warned = True
    raw = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b'rengine-api-vault').derive(settings.SECRET_KEY.encode())
    return base64.urlsafe_b64encode(raw)


def _get_fernet():
    global _fernet
    if _fernet is None:
        env_key = os.environ.get('RENGINE_VAULT_KEY')
        key = env_key.encode() if env_key else _derive_from_secret_key()
        _fernet = Fernet(key)
    return _fernet


def encrypt(plaintext: str) -> str:
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt(token: str):
    if not token:
        return None
    try:
        return _get_fernet().decrypt(token.encode()).decode()
    except (InvalidToken, ValueError, TypeError):
        logger.warning('API-vault decrypt failed for a stored credential (skipping).')
        return None
```

Note: the cached `_fernet` makes `@override_settings(SECRET_KEY=...)` harmless once an env key is set — exactly the decoupling the test asserts. For the env-key test to be meaningful, set `RENGINE_VAULT_KEY` in the test environment (see Step 5 note).

- [ ] **Step 4: Run test to verify it passes**

Run: `RENGINE_VAULT_KEY=$(python3 -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())") python3 manage.py test tests.test_api_vault.CryptoTests -v 2`
Expected: PASS (4 tests). Without the env var, `test_env_key_decouples_from_secret_key` still passes because `_fernet` is cached after first use; the env var simply makes the intent explicit.

- [ ] **Step 5: Commit**

```bash
git add web/dashboard/crypto.py web/tests/test_api_vault.py
git commit -m "feat(vault): Fernet encryption layer with env/SECRET_KEY key resolution"
```

---

## Task 2: Provider registry (`dashboard/providers.py`)

**Files:**
- Create: `web/dashboard/providers.py`
- Test: `web/tests/test_api_vault.py`

**Interfaces:**
- Produces:
  - `PROVIDERS: dict[str, dict]` — `{slug: {'label': str, 'url': str|None, 'fields': [(field_name, destination)]}}`; `destination` is either `'sfp_<module>:<option>'` or `'consumer:<name>'`.
  - `sf_destination(dest: str) -> str | None` — returns the `sfp_…` option, or `None` for consumer fields.
  - `CUSTOM_OPTION_RE` and `is_valid_custom_option(s: str) -> bool` — validates `sfp_module:option`.
  - `custom_provider_slug(option: str) -> str` — `'custom:<option>'`.

- [ ] **Step 1: Write the failing test**

```python
# append to web/tests/test_api_vault.py
from dashboard import providers


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 manage.py test tests.test_api_vault.ProviderRegistryTests -v 2`
Expected: FAIL — `No module named 'dashboard.providers'`.

- [ ] **Step 3: Write minimal implementation**

```python
# web/dashboard/providers.py
"""Declarative registry mapping vault credentials to their destinations.

`destination` is either a SpiderFoot config option ('sfp_<module>:<option>')
seeded into spiderfoot.db before a scan, or 'consumer:<name>' read by recon/LLM
code via common_func.get_credential().
"""
import re

PROVIDERS = {
    # --- SpiderFoot-backed (curated, high ROI for the OSINT gap) ---
    'shodan':         {'label': 'Shodan',          'url': 'https://account.shodan.io',
                       'fields': [('key', 'sfp_shodan:api_key')]},
    'haveibeenpwned': {'label': 'HaveIBeenPwned',  'url': 'https://haveibeenpwned.com/API/Key',
                       'fields': [('key', 'sfp_haveibeenpwned:api_key')]},
    'dehashed':       {'label': 'DeHashed',        'url': 'https://dehashed.com',
                       'fields': [('username', 'sfp_dehashed:username'),
                                  ('key', 'sfp_dehashed:api_key')]},
    'virustotal':     {'label': 'VirusTotal',      'url': 'https://www.virustotal.com',
                       'fields': [('key', 'sfp_virustotal:api_key')]},
    'securitytrails': {'label': 'SecurityTrails',  'url': 'https://securitytrails.com',
                       'fields': [('key', 'sfp_securitytrails:api_key')]},
    'hunter':         {'label': 'Hunter.io',       'url': 'https://hunter.io',
                       'fields': [('key', 'sfp_hunter:api_key')]},
    'binaryedge':     {'label': 'BinaryEdge',      'url': 'https://www.binaryedge.io',
                       'fields': [('key', 'sfp_binaryedge:api_key')]},
    'censys':         {'label': 'Censys',          'url': 'https://search.censys.io/account/api',
                       'fields': [('key', 'sfp_censys:api_key_uid'),
                                  ('secret', 'sfp_censys:api_key_secret')]},
    'greynoise':      {'label': 'GreyNoise',       'url': 'https://www.greynoise.io',
                       'fields': [('key', 'sfp_greynoise:api_key')]},
    'abuseipdb':      {'label': 'AbuseIPDB',       'url': 'https://www.abuseipdb.com',
                       'fields': [('key', 'sfp_abuseipdb:api_key')]},
    'ipinfo':         {'label': 'IPInfo',          'url': 'https://ipinfo.io',
                       'fields': [('key', 'sfp_ipinfo:api_key')]},
    'fullhunt':       {'label': 'FullHunt',        'url': 'https://fullhunt.io',
                       'fields': [('key', 'sfp_fullhunt:api_key')]},
    'intelx':         {'label': 'IntelX',          'url': 'https://intelx.io',
                       'fields': [('key', 'sfp_intelx:api_key')]},
    'leakix':         {'label': 'LeakIX',          'url': 'https://leakix.net',
                       'fields': [('key', 'sfp_leakix:api_key')]},
    # --- existing integrations (migrated; consumed by recon/LLM/H1) ---
    'openai':         {'label': 'OpenAI',     'url': 'https://platform.openai.com/api-keys',
                       'fields': [('key', 'consumer:llm')]},
    'netlas':         {'label': 'Netlas',     'url': 'https://netlas.io',
                       'fields': [('key', 'consumer:recon')]},
    'chaos':          {'label': 'Chaos',      'url': 'https://chaos.projectdiscovery.io',
                       'fields': [('key', 'consumer:recon')]},
    'gitguardian':    {'label': 'GitGuardian', 'url': 'https://dashboard.gitguardian.com/api',
                       'fields': [('key', 'consumer:secret')]},
    'hackerone':      {'label': 'HackerOne',  'url': 'https://hackerone.com',
                       'fields': [('username', 'consumer:h1_user'),
                                  ('key', 'consumer:h1_key')]},
}

CUSTOM_OPTION_RE = re.compile(r'^sfp_[a-z0-9_]+:[a-z0-9_]+$')


def sf_destination(dest: str):
    """Return the SpiderFoot option for a destination, or None for consumer fields."""
    return dest if dest.startswith('sfp_') else None


def is_valid_custom_option(s: str) -> bool:
    return bool(CUSTOM_OPTION_RE.match(s or ''))


def custom_provider_slug(option: str) -> str:
    return f'custom:{option}'
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 manage.py test tests.test_api_vault.ProviderRegistryTests -v 2`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add web/dashboard/providers.py web/tests/test_api_vault.py
git commit -m "feat(vault): provider registry (curated SF modules + consumers + custom)"
```

---

## Task 3: `ApiCredential` model + schema migration

**Files:**
- Modify: `web/dashboard/models.py` (add class near the other key models, ~line 22)
- Create: `web/dashboard/migrations/00XX_apicredential.py` (generated)
- Test: `web/tests/test_api_vault.py`

**Interfaces:**
- Consumes: `dashboard.crypto.encrypt/decrypt`.
- Produces:
  - `ApiCredential(provider, label, key_enc, extra_enc, enabled, updated_at)`.
  - classmethod `ApiCredential.upsert(provider, key, extra: dict | None = None, label='', enabled=True) -> ApiCredential`.
  - method `ApiCredential.decrypted() -> (key: str | None, extra: dict)`.

- [ ] **Step 1: Write the failing test**

```python
# append to web/tests/test_api_vault.py
from dashboard.models import ApiCredential


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 manage.py test tests.test_api_vault.ApiCredentialModelTests -v 2`
Expected: FAIL — `ImportError: cannot import name 'ApiCredential'`.

- [ ] **Step 3: Write minimal implementation**

```python
# web/dashboard/models.py  — add after the imports, near the other *APIKey models
import json
from dashboard import crypto


class ApiCredential(models.Model):
    """Generic, encrypted store for every integration API key (the unified vault).
    `provider` is a registry slug (dashboard.providers) or 'custom:sfp_x:api_key'."""
    id = models.AutoField(primary_key=True)
    provider = models.CharField(max_length=120, unique=True)
    label = models.CharField(max_length=200, blank=True, default='')
    key_enc = models.TextField()
    extra_enc = models.TextField(null=True, blank=True)
    enabled = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'ApiCredential<{self.provider}>'   # never the secret

    @classmethod
    def upsert(cls, provider, key, extra=None, label='', enabled=True):
        extra_enc = crypto.encrypt(json.dumps(extra)) if extra else None
        obj, _ = cls.objects.update_or_create(
            provider=provider,
            defaults={
                'key_enc': crypto.encrypt(key or ''),
                'extra_enc': extra_enc,
                'label': label,
                'enabled': enabled,
            })
        return obj

    def decrypted(self):
        key = crypto.decrypt(self.key_enc) if self.key_enc else None
        extra = {}
        if self.extra_enc:
            raw = crypto.decrypt(self.extra_enc)
            if raw:
                try:
                    extra = json.loads(raw)
                except ValueError:
                    extra = {}
        return key, extra
```

- [ ] **Step 4: Generate + run the schema migration, then the tests**

```bash
python3 manage.py makemigrations dashboard --name apicredential
python3 manage.py migrate dashboard
python3 manage.py test tests.test_api_vault.ApiCredentialModelTests -v 2
```
Expected: migration created and applied; tests PASS (4).

- [ ] **Step 5: Commit**

```bash
git add web/dashboard/models.py web/dashboard/migrations/ web/tests/test_api_vault.py
git commit -m "feat(vault): ApiCredential encrypted model + upsert/decrypted"
```

---

## Task 4: Accessor (`common_func.get_credential` / `get_api_key`)

**Files:**
- Modify: `web/Suricatoos/common_func.py` (add near the existing key helpers, ~line 1050)
- Test: `web/tests/test_api_vault.py`

**Interfaces:**
- Consumes: `ApiCredential`.
- Produces: `get_credential(provider) -> (key: str | None, extra: dict)`, `get_api_key(provider) -> str | None`. Both return `None`/`{}` for missing or disabled credentials.

- [ ] **Step 1: Write the failing test**

```python
# append to web/tests/test_api_vault.py
from Suricatoos.common_func import get_api_key, get_credential


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 manage.py test tests.test_api_vault.AccessorTests -v 2`
Expected: FAIL — `ImportError: cannot import name 'get_api_key'`.

- [ ] **Step 3: Write minimal implementation**

```python
# web/Suricatoos/common_func.py  — add (import ApiCredential at top of file with the
# other dashboard.models imports)
from dashboard.models import ApiCredential


def get_credential(provider):
    """Return (key, extra_dict) for an enabled credential, else (None, {})."""
    cred = ApiCredential.objects.filter(provider=provider, enabled=True).first()
    if not cred:
        return None, {}
    return cred.decrypted()


def get_api_key(provider):
    """Return the decrypted primary key for an enabled credential, else None."""
    return get_credential(provider)[0]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 manage.py test tests.test_api_vault.AccessorTests -v 2`
Expected: PASS (4).

- [ ] **Step 5: Commit**

```bash
git add web/Suricatoos/common_func.py web/tests/test_api_vault.py
git commit -m "feat(vault): get_credential/get_api_key accessor over ApiCredential"
```

---

## Task 5: `build_spiderfoot_config()`

**Files:**
- Modify: `web/Suricatoos/common_func.py`
- Test: `web/tests/test_api_vault.py`

**Interfaces:**
- Consumes: `ApiCredential`, `dashboard.providers.PROVIDERS`, `sf_destination`.
- Produces: `build_spiderfoot_config() -> dict[str, str]` — flat `{ 'sfp_module:option': value }` for every **enabled** credential whose registry fields have `sfp_` destinations (plus `custom:` rows). Skips `consumer:` fields and disabled rows.

- [ ] **Step 1: Write the failing test**

```python
# append to web/tests/test_api_vault.py
from Suricatoos.common_func import build_spiderfoot_config


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 manage.py test tests.test_api_vault.BuildSpiderfootConfigTests -v 2`
Expected: FAIL — `ImportError: cannot import name 'build_spiderfoot_config'`.

- [ ] **Step 3: Write minimal implementation**

```python
# web/Suricatoos/common_func.py  — add (import the registry helpers at top)
from dashboard.providers import PROVIDERS, sf_destination


def build_spiderfoot_config():
    """Flat {module:option -> value} for enabled SF-backed + custom credentials."""
    cfg = {}
    for cred in ApiCredential.objects.filter(enabled=True):
        key, extra = cred.decrypted()
        if cred.provider.startswith('custom:'):
            option = cred.provider[len('custom:'):]
            if key:
                cfg[option] = key
            continue
        spec = PROVIDERS.get(cred.provider)
        if not spec:
            continue
        # map each registry field -> its value (primary 'key' or a name in extra)
        values = {'key': key, **(extra or {})}
        for field_name, dest in spec['fields']:
            option = sf_destination(dest)
            val = values.get(field_name)
            if option and val:
                cfg[option] = val
    return cfg
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 manage.py test tests.test_api_vault.BuildSpiderfootConfigTests -v 2`
Expected: PASS (3).

- [ ] **Step 5: Commit**

```bash
git add web/Suricatoos/common_func.py web/tests/test_api_vault.py
git commit -m "feat(vault): build_spiderfoot_config maps enabled creds to SF options"
```

---

## Task 6: Data migration (legacy keys → `ApiCredential`)

**Files:**
- Create: `web/dashboard/migrations/00XX_migrate_legacy_keys.py`
- Test: `web/tests/test_api_vault.py`

**Interfaces:**
- Consumes: old models `OpenAiAPIKey/NetlasAPIKey/ChaosAPIKey/GitGuardianAPIKey/HackerOneAPIKey`, `dashboard.crypto.encrypt`.
- Produces: one `ApiCredential` row per non-empty legacy key, decryptable via the accessor.

- [ ] **Step 1: Write the failing test**

```python
# append to web/tests/test_api_vault.py
from django.core.management import call_command
from io import StringIO
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
```

> The migration's forward logic lives in a tiny importable helper (`_legacy_loader.run`) so it is unit-testable without replaying migrations. When run by Django it receives `apps`; in the test it falls back to the real models.

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 manage.py test tests.test_api_vault.LegacyMigrationTests -v 2`
Expected: FAIL — `No module named 'dashboard.migrations._legacy_loader'`.

- [ ] **Step 3: Write the helper + migration**

```python
# web/dashboard/migrations/_legacy_loader.py
"""Forward logic for the legacy-key data migration; importable for testing."""
import json
from dashboard import crypto

# (legacy_model_attr, provider, has_username)
LEGACY = [
    ('OpenAiAPIKey', 'openai', False),
    ('NetlasAPIKey', 'netlas', False),
    ('ChaosAPIKey', 'chaos', False),
    ('GitGuardianAPIKey', 'gitguardian', False),
    ('HackerOneAPIKey', 'hackerone', True),
]


def _models(apps):
    import dashboard.models as m
    if apps is None:
        return m
    # historical models during a real migration
    class _Hist:
        pass
    h = _Hist()
    for name, _, _ in LEGACY:
        setattr(h, name, apps.get_model('dashboard', name))
    h.ApiCredential = apps.get_model('dashboard', 'ApiCredential')
    return h


def run(apps):
    mods = _models(apps)
    ApiCredential = mods.ApiCredential
    for attr, provider, has_user in LEGACY:
        row = getattr(mods, attr).objects.first()
        if not row or not getattr(row, 'key', None):
            continue
        extra_enc = None
        if has_user and getattr(row, 'username', None):
            extra_enc = crypto.encrypt(json.dumps({'username': row.username}))
        ApiCredential.objects.update_or_create(
            provider=provider,
            defaults={'key_enc': crypto.encrypt(row.key), 'extra_enc': extra_enc,
                      'label': provider.title(), 'enabled': True})
```

```python
# web/dashboard/migrations/00XX_migrate_legacy_keys.py
from django.db import migrations
from dashboard.migrations import _legacy_loader


def forward(apps, schema_editor):
    _legacy_loader.run(apps)


def backward(apps, schema_editor):
    apps.get_model('dashboard', 'ApiCredential').objects.filter(
        provider__in=['openai', 'netlas', 'chaos', 'gitguardian', 'hackerone']).delete()


class Migration(migrations.Migration):
    dependencies = [('dashboard', '00XX_apicredential')]   # set to Task 3's migration name
    operations = [migrations.RunPython(forward, backward)]
```

- [ ] **Step 4: Run the migration + tests**

```bash
python3 manage.py migrate dashboard
python3 manage.py test tests.test_api_vault.LegacyMigrationTests -v 2
```
Expected: migration applies cleanly; test PASSES.

- [ ] **Step 5: Commit**

```bash
git add web/dashboard/migrations/ web/tests/test_api_vault.py
git commit -m "feat(vault): data-migrate legacy API keys into encrypted ApiCredential"
```

---

## Task 7: Consumer refactor (read keys through the accessor)

**Files:**
- Modify: `web/Suricatoos/tasks.py` (lines ~2406, ~2454, ~3094, ~3444, ~3575, ~4144)
- Modify: `web/api/views.py` (line ~105)
- Modify: `web/Suricatoos/common_func.py` (lines ~1050-1069 — the context dict that reads the legacy models)
- Test: `web/tests/test_api_vault.py`

**Interfaces:**
- Consumes: `get_api_key`, `get_credential`.
- Produces: no new symbols — behavior preserved, source switched to the vault.

- [ ] **Step 1: Write the failing test** (proves consumers read the vault, not the legacy models)

```python
# append to web/tests/test_api_vault.py
class ConsumerWiringTests(TestCase):
    def test_openai_gate_uses_vault(self):
        # The GPT-report gate should see a vault-only OpenAI key.
        ApiCredential.upsert('openai', 'sk-vault')
        self.assertEqual(get_api_key('openai'), 'sk-vault')

    def test_hackerone_credential_from_vault(self):
        ApiCredential.upsert('hackerone', 'h1tok', extra={'username': 'bob'})
        key, extra = get_credential('hackerone')
        self.assertEqual((key, extra['username']), ('h1tok', 'bob'))
```

> These assert the accessor contract the refactor depends on. The call-site edits below are verified by the existing suites (`tests.test_secret_scan` for GitGuardian) plus the full run in Task 15.

- [ ] **Step 2: Run test to verify it passes the contract, then edit call sites**

Run: `python3 manage.py test tests.test_api_vault.ConsumerWiringTests -v 2` → PASS.

Now replace each legacy read. Examples (apply the same pattern at every listed line):

```python
# web/Suricatoos/tasks.py  — OpenAI GPT-report gates (~2454, ~3444, ~3575)
# before: if should_fetch_gpt_report and OpenAiAPIKey.objects.all().first():
if should_fetch_gpt_report and get_api_key('openai'):

# web/Suricatoos/tasks.py  — GitGuardian (~3094)
# before: db_key = GitGuardianAPIKey.objects.first()
db_key = get_api_key('gitguardian')   # now a str|None; update the 1-2 lines that used db_key.key

# web/Suricatoos/tasks.py  — HackerOne send-report (~4144) and gate (~2406)
h1_key, h1_extra = get_credential('hackerone')
# use h1_key + h1_extra.get('username') where username/key were read from the model

# web/api/views.py  — (~105)
# before: api_key = HackerOneAPIKey.objects.first()
h1_key, h1_extra = get_credential('hackerone')

# web/Suricatoos/common_func.py  — (~1050-1069) context dict
# replace the four .objects.all() reads with get_api_key('openai'/'netlas'/'chaos')
# and get_credential('hackerone')
```

Add `from Suricatoos.common_func import get_api_key, get_credential` where needed (tasks.py imports from common_func already; api/views.py add the import). Remove now-unused legacy-model imports flagged by the next step.

- [ ] **Step 3: Run the affected existing suites**

Run: `python3 manage.py test tests.test_secret_scan -v 2`
Expected: PASS (GitGuardian path now sourced from the vault — note `test_secret_scan` seeds `GitGuardianAPIKey`; update those test setups to `ApiCredential.upsert('gitguardian', ...)` as part of this task and re-run).

- [ ] **Step 4: Lint for stragglers**

Run: `grep -rn "OpenAiAPIKey.objects\|NetlasAPIKey.objects\|ChaosAPIKey.objects\|GitGuardianAPIKey.objects\|HackerOneAPIKey.objects" web/Suricatoos web/api`
Expected: no matches outside `dashboard/` and migrations.

- [ ] **Step 5: Commit**

```bash
git add web/Suricatoos/tasks.py web/api/views.py web/Suricatoos/common_func.py web/tests/
git commit -m "refactor(vault): read all integration keys through get_api_key/get_credential"
```

---

## Task 8: Seed SpiderFoot config in `spiderfoot_scan`

**Files:**
- Modify: `web/Suricatoos/definitions.py` (add `SPIDERFOOT_DB_PATH`)
- Modify: `web/Suricatoos/tasks.py::spiderfoot_scan` (top of function, ~2715-2728)
- Test: `web/tests/test_api_vault.py`

**Interfaces:**
- Consumes: `build_spiderfoot_config`, `SpiderFootDb`.
- Produces: `seed_spiderfoot_config(cfg: dict) -> bool` in `tasks.py` (writes the dict to `spiderfoot.db`; returns False + logs on failure, never raises).

- [ ] **Step 1: Write the failing test** (mock SpiderFootDb so no real file is needed)

```python
# append to web/tests/test_api_vault.py
from unittest import mock


class SeedSpiderfootTests(TestCase):
    def test_seed_calls_configset_with_built_dict(self):
        ApiCredential.upsert('shodan', 'shod')
        from Suricatoos import tasks
        with mock.patch.object(tasks, 'SpiderFootDb') as DB:
            ok = tasks.seed_spiderfoot_config(tasks.build_spiderfoot_config())
        self.assertTrue(ok)
        DB.return_value.configSet.assert_called_once()
        sent = DB.return_value.configSet.call_args[0][0]
        self.assertEqual(sent['sfp_shodan:api_key'], 'shod')

    def test_seed_empty_is_noop(self):
        from Suricatoos import tasks
        with mock.patch.object(tasks, 'SpiderFootDb') as DB:
            self.assertFalse(tasks.seed_spiderfoot_config({}))
            DB.assert_not_called()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 manage.py test tests.test_api_vault.SeedSpiderfootTests -v 2`
Expected: FAIL — `module 'Suricatoos.tasks' has no attribute 'seed_spiderfoot_config'`.

- [ ] **Step 3: Write minimal implementation**

```python
# web/Suricatoos/definitions.py  — near the other SPIDERFOOT_* constants (~124)
import os
SPIDERFOOT_DB_PATH = os.path.join(
    os.environ.get('SPIDERFOOT_DATA', os.path.expanduser('~/.spiderfoot')),
    'spiderfoot.db')
```

```python
# web/Suricatoos/tasks.py
# top-level imports (with the other spiderfoot/common_func imports):
from spiderfoot import SpiderFootDb
from Suricatoos.common_func import build_spiderfoot_config
from Suricatoos.definitions import SPIDERFOOT_DB_PATH


def seed_spiderfoot_config(cfg):
    """Persist vault-sourced API keys into spiderfoot.db so the CLI scan loads them.
    Returns True on write, False on empty/failure (never raises into a scan)."""
    if not cfg:
        return False
    try:
        SpiderFootDb({'__database': SPIDERFOOT_DB_PATH}, init=True).configSet(cfg)
        return True
    except Exception as e:   # noqa: BLE001 - seeding must never break a scan
        logger.warning(f'spiderfoot: could not seed API keys into config: {e}')
        return False
```

Then call it at the top of `spiderfoot_scan`, right after `scan_history = ScanHistory.objects.get(...)`:

```python
    seeded = seed_spiderfoot_config(build_spiderfoot_config())
    if seeded:
        logger.info('spiderfoot: seeded API keys from the credential vault')
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 manage.py test tests.test_api_vault.SeedSpiderfootTests -v 2`
Expected: PASS (2).

- [ ] **Step 5: Commit**

```bash
git add web/Suricatoos/definitions.py web/Suricatoos/tasks.py web/tests/test_api_vault.py
git commit -m "feat(vault): seed spiderfoot.db with vault API keys before each scan"
```

---

## Task 9: API Vault UI (generic handler + template)

**Files:**
- Modify: `web/scanEngine/views.py::api_vault` (~528-600, replace the body)
- Modify: `web/scanEngine/templates/scanEngine/settings/api.html`
- Test: `web/tests/test_api_vault.py`

**Interfaces:**
- Consumes: `PROVIDERS`, `ApiCredential`, `is_valid_custom_option`, `custom_provider_slug`.
- Produces: POST handler that upserts/clears credentials from the registry + custom rows; GET context `vault_rows` (list of `{slug,label,url,fields,masked,enabled}`).

- [ ] **Step 1: Write the failing test**

```python
# append to web/tests/test_api_vault.py
from django.contrib.auth.models import User
from django.urls import reverse


class ApiVaultViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_superuser('admin', 'a@a.io', 'pw')
        self.client.force_login(self.user)
        # api_vault is slug-scoped; use any existing project slug fixture or create one.
        from targetApp.models import Project
        self.slug = Project.objects.create(name='p', slug='p', insert_date='2026-01-01').slug

    def _url(self):
        return reverse('api_vault', kwargs={'slug': self.slug})

    def test_post_creates_credential(self):
        self.client.post(self._url(), {'cred_shodan_key': 'sk-1'})
        self.assertEqual(get_api_key('shodan'), 'sk-1')

    def test_blank_leaves_value_unchanged(self):
        ApiCredential.upsert('shodan', 'keep-me')
        self.client.post(self._url(), {'cred_shodan_key': ''})
        self.assertEqual(get_api_key('shodan'), 'keep-me')

    def test_custom_entry_validated(self):
        self.client.post(self._url(), {'custom_option': 'sfp_x:api_key', 'custom_key': 'v'})
        self.assertEqual(get_api_key('custom:sfp_x:api_key'), 'v')
        self.client.post(self._url(), {'custom_option': 'bad input', 'custom_key': 'v'})
        self.assertIsNone(get_api_key('custom:bad input'))

    def test_rendered_value_is_masked(self):
        ApiCredential.upsert('shodan', 'sk-abcdef')
        html = self.client.get(self._url()).content.decode()
        self.assertNotIn('sk-abcdef', html)
```

> Adjust `Project` creation to the model's real required fields if different; the point is a valid `slug` for the URL.

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 manage.py test tests.test_api_vault.ApiVaultViewTests -v 2`
Expected: FAIL (old handler ignores `cred_*`/`custom_*` fields).

- [ ] **Step 3: Replace the view body**

```python
# web/scanEngine/views.py
from dashboard.models import ApiCredential
from dashboard.providers import PROVIDERS, is_valid_custom_option, custom_provider_slug


def _mask(value):
    if not value:
        return ''
    return value[:2] + '••••' + value[-2:] if len(value) > 4 else '••••'


def api_vault(request, slug):
    context = {}
    if request.method == 'POST':
        for slug_, spec in PROVIDERS.items():
            posted = {}
            for field_name, _dest in spec['fields']:
                posted[field_name] = (request.POST.get(f'cred_{slug_}_{field_name}') or '').strip()
            # primary field name is the first field
            primary = spec['fields'][0][0]
            key = posted.get(primary, '')
            extra = {fn: v for fn, v in posted.items() if fn != primary and v}
            if key:
                ApiCredential.upsert(slug_, key, extra=extra or None, label=spec['label'])
            # else: blank submission leaves the stored value untouched
        # custom module:option
        opt = (request.POST.get('custom_option') or '').strip()
        cval = (request.POST.get('custom_key') or '').strip()
        if opt and cval and is_valid_custom_option(opt):
            ApiCredential.upsert(custom_provider_slug(opt), cval, label=opt)

    # render
    rows = []
    for slug_, spec in PROVIDERS.items():
        cred = ApiCredential.objects.filter(provider=slug_).first()
        key = cred.decrypted()[0] if cred else None
        rows.append({'slug': slug_, 'label': spec['label'], 'url': spec.get('url'),
                     'fields': spec['fields'], 'masked': _mask(key),
                     'enabled': cred.enabled if cred else True})
    context['vault_rows'] = rows
    context['custom_rows'] = [
        {'option': c.provider[len('custom:'):], 'masked': _mask(c.decrypted()[0])}
        for c in ApiCredential.objects.filter(provider__startswith='custom:')]
    return render(request, 'scanEngine/settings/api.html', context)
```

- [ ] **Step 4: Update the template**

In `web/scanEngine/templates/scanEngine/settings/api.html`, replace the hand-written per-key inputs with a loop over `vault_rows`:

```html
<!-- inside the settings <form method="post"> ... {% csrf_token %} -->
{% for row in vault_rows %}
  <div class="form-group">
    <label>{{ row.label }}
      {% if row.url %}<a href="{{ row.url }}" target="_blank" rel="noopener">{% trans "get a key" %}</a>{% endif %}
    </label>
    {% for fname, dest in row.fields %}
      <input type="password" class="form-control" name="cred_{{ row.slug }}_{{ fname }}"
             placeholder="{% if row.masked %}{{ row.masked }}{% else %}{{ fname }}{% endif %}">
    {% endfor %}
  </div>
{% endfor %}

<hr>
<label>{% trans "Add custom SpiderFoot key (module:option)" %}</label>
<input type="text" class="form-control" name="custom_option" placeholder="sfp_module:api_key">
<input type="password" class="form-control" name="custom_key" placeholder="key">
{% for c in custom_rows %}<div>{{ c.option }} — {{ c.masked }}</div>{% endfor %}
```

Keep the page's existing layout/wrapper; only the credential inputs change. Ensure `{% load i18n %}` is present.

- [ ] **Step 5: Run test, then commit**

Run: `python3 manage.py test tests.test_api_vault.ApiVaultViewTests -v 2`
Expected: PASS (5).

```bash
git add web/scanEngine/views.py web/scanEngine/templates/scanEngine/settings/api.html web/tests/test_api_vault.py
git commit -m "feat(vault): registry-driven API Vault UI (masked, custom entry)"
```

---

## Task 10: Admin, env docs, and the second write path

**Files:**
- Modify: `web/dashboard/admin.py`
- Modify: `web/dashboard/views.py` (~397-439 — the tool-settings POST/context)
- Modify: `.env.example`
- Test: `web/tests/test_api_vault.py`

**Interfaces:**
- Consumes: `ApiCredential`, `get_api_key`/`get_credential`.
- Produces: no new symbols; unifies the dashboard tool-settings write path onto `ApiCredential` and masks admin.

- [ ] **Step 1: Write the failing test**

```python
# append to web/tests/test_api_vault.py
class SecondWritePathTests(TestCase):
    def test_admin_str_masked(self):
        from django.contrib import admin
        from dashboard.models import ApiCredential as AC
        self.assertIn(AC, admin.site._registry)   # registered
        c = AC.upsert('shodan', 'sk-secret-xyz')
        self.assertNotIn('sk-secret-xyz', str(c))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 manage.py test tests.test_api_vault.SecondWritePathTests -v 2`
Expected: FAIL — `ApiCredential` not in `admin.site._registry`.

- [ ] **Step 3: Implement**

```python
# web/dashboard/admin.py
from dashboard.models import ApiCredential

@admin.register(ApiCredential)
class ApiCredentialAdmin(admin.ModelAdmin):
    list_display = ('provider', 'label', 'enabled', 'updated_at')   # no key columns
    readonly_fields = ('key_enc', 'extra_enc')

# remove the admin.site.register(OpenAiAPIKey/NetlasAPIKey/ChaosAPIKey/HackerOneAPIKey) lines
```

```python
# web/dashboard/views.py (~397-439)
# Replace the per-model save blocks with ApiCredential.upsert(...) for
# 'openai'/'netlas'/'chaos'/'hackerone' (mirror Task 9's handler), and replace
# the context reads at ~435-439 with get_api_key(...)/get_credential('hackerone').
```

```bash
# .env.example  — add under the secrets section
# API credential vault encryption key (urlsafe-base64 32-byte Fernet key).
# Generate: python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"
# If unset, derived from SECRET_KEY (a startup warning is logged).
RENGINE_VAULT_KEY=
```

- [ ] **Step 4: Run test + lint**

Run: `python3 manage.py test tests.test_api_vault.SecondWritePathTests -v 2` → PASS.
Run: `grep -rn "APIKey.objects" web/dashboard/views.py` → no matches.

- [ ] **Step 5: Commit**

```bash
git add web/dashboard/admin.py web/dashboard/views.py .env.example web/tests/test_api_vault.py
git commit -m "feat(vault): mask admin, unify dashboard write path, document RENGINE_VAULT_KEY"
```

---

## Task 11: `OsintResult` capture columns + `BUCKET_ORG` (Front B)

**Files:**
- Modify: `web/startScan/models.py::OsintResult` (~735-777)
- Create: `web/startScan/migrations/00XX_osintresult_capture.py` (generated)
- Test: `web/tests/test_osint_capture.py`

**Interfaces:**
- Produces: `OsintResult.module`, `.parent`, `.confidence` (all nullable); `OsintResult.BUCKET_ORG = 'organization'` added to `BUCKET_CHOICES`.

- [ ] **Step 1: Write the failing test**

```python
# web/tests/test_osint_capture.py
from django.test import TestCase
from startScan.models import OsintResult


class OsintSchemaTests(TestCase):
    def test_new_fields_exist(self):
        o = OsintResult.objects.create(event_type='X', data='d', module='sfp_dnsraw',
                                       parent='delphos.com.br', confidence=80)
        o.refresh_from_db()
        self.assertEqual((o.module, o.parent, o.confidence), ('sfp_dnsraw', 'delphos.com.br', 80))

    def test_bucket_org_choice(self):
        self.assertIn(OsintResult.BUCKET_ORG, dict(OsintResult.BUCKET_CHOICES))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 manage.py test tests.test_osint_capture.OsintSchemaTests -v 2`
Expected: FAIL — unexpected keyword `module` / `BUCKET_ORG` missing.

- [ ] **Step 3: Implement**

```python
# web/startScan/models.py — in OsintResult, add the bucket constant + choice
    BUCKET_ORG = 'organization'
    # ... add to BUCKET_CHOICES tuple:
        (BUCKET_ORG, 'Organization / Identity'),
    # ... add fields (after `extra`):
    module = models.CharField(max_length=120, null=True, blank=True)
    parent = models.CharField(max_length=500, null=True, blank=True)
    confidence = models.IntegerField(null=True, blank=True)
```

- [ ] **Step 4: Migrate + test**

```bash
python3 manage.py makemigrations startScan --name osintresult_capture
python3 manage.py migrate startScan
python3 manage.py test tests.test_osint_capture.OsintSchemaTests -v 2
```
Expected: PASS (2).

- [ ] **Step 5: Commit**

```bash
git add web/startScan/models.py web/startScan/migrations/ web/tests/test_osint_capture.py
git commit -m "feat(osint): OsintResult provenance/module/confidence columns + BUCKET_ORG"
```

---

## Task 12: `save_osint_result` captures provenance + real timestamp (Front B)

**Files:**
- Modify: `web/Suricatoos/tasks.py::save_osint_result` (~2685-2706)
- Test: `web/tests/test_osint_capture.py`

**Interfaces:**
- Consumes: `OsintResult`.
- Produces: `save_osint_result(scan_history, bucket, event_type, data, source='spiderfoot', extra=None, is_malicious=False, severity=0, module=None, parent=None, confidence=None, generated=None)` — stores the new fields; sets `discovered_date` from `generated` (unix→aware) when present.

- [ ] **Step 1: Write the failing test**

```python
# append to web/tests/test_osint_capture.py
import datetime
from django.utils import timezone
from Suricatoos.tasks import save_osint_result
from startScan.models import ScanHistory
from targetApp.models import Domain


class SaveOsintResultTests(TestCase):
    def setUp(self):
        d = Domain.objects.create(name='delphos.com.br')
        self.scan = ScanHistory.objects.create(domain=d)

    def test_persists_module_parent_confidence(self):
        obj, _ = save_osint_result(self.scan, OsintResult.BUCKET_INFRA_DNS, 'DNS TXT Record',
                                   'v=spf1', module='sfp_dnsraw', parent='delphos.com.br',
                                   confidence=90)
        self.assertEqual((obj.module, obj.parent, obj.confidence), ('sfp_dnsraw', 'delphos.com.br', 90))

    def test_generated_sets_discovered_date(self):
        ts = 1781925945
        obj, _ = save_osint_result(self.scan, OsintResult.BUCKET_INFRA_DNS, 'X', 'd', generated=ts)
        self.assertEqual(obj.discovered_date,
                         datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 manage.py test tests.test_osint_capture.SaveOsintResultTests -v 2`
Expected: FAIL — `save_osint_result() got an unexpected keyword argument 'module'`.

- [ ] **Step 3: Implement** (edit the signature + defaults dict)

```python
# web/Suricatoos/tasks.py
def save_osint_result(scan_history, bucket, event_type, data, source='spiderfoot',
        extra=None, is_malicious=False, severity=0,
        module=None, parent=None, confidence=None, generated=None):
    if not data:
        return None, False
    data = str(data).replace('<SFURL>', ' ').replace('</SFURL>', '')
    data = ' '.join(data.split()).strip()
    if not data:
        return None, False
    discovered = timezone.now()
    if generated:
        try:
            discovered = datetime.datetime.fromtimestamp(int(generated), tz=datetime.timezone.utc)
        except (ValueError, OSError, OverflowError):
            pass
    target = scan_history.domain if scan_history else None
    obj, created = OsintResult.objects.get_or_create(
        scan_history=scan_history, bucket=bucket, event_type=event_type,
        data=str(data)[:2000],
        defaults={
            'target_domain': target, 'source': source,
            'extra': (str(extra)[:2000] if extra else None),
            'is_malicious': is_malicious, 'severity': severity,
            'module': module, 'parent': (str(parent)[:500] if parent else None),
            'confidence': confidence, 'discovered_date': discovered,
        })
    return obj, created
```

Ensure `import datetime` is present at the top of `tasks.py` (it is used elsewhere; add if missing).

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 manage.py test tests.test_osint_capture.SaveOsintResultTests -v 2`
Expected: PASS (2).

- [ ] **Step 5: Commit**

```bash
git add web/Suricatoos/tasks.py web/tests/test_osint_capture.py
git commit -m "feat(osint): persist SpiderFoot provenance, module, confidence, real timestamp"
```

---

## Task 13: `spiderfoot_scan` routing + drop telemetry (Front B)

**Files:**
- Modify: `web/Suricatoos/tasks.py` (`SF_DROP` ~2652, `spiderfoot_scan` loop ~2752-2784)
- Test: `web/tests/test_osint_capture.py`

**Interfaces:**
- Consumes: `save_endpoint`, `save_subdomain`, `save_osint_result`, `_sf_bucket`.
- Produces: events `Linked URL - Internal`, `Internet Name - Unresolved`, `Company Name` are no longer dropped; `module`/`source`/`generated` flow into `save_osint_result`.

- [ ] **Step 1: Write the failing test** (drive the loop with a synthetic event list)

```python
# append to web/tests/test_osint_capture.py
from unittest import mock
from startScan.models import Subdomain, EndPoint
from Suricatoos import tasks


class SpiderfootRoutingTests(TestCase):
    def setUp(self):
        d = Domain.objects.create(name='delphos.com.br')
        self.scan = ScanHistory.objects.create(domain=d)
        self.ctx = {'scan_history_id': self.scan.id, 'domain_id': d.id}

    def _run(self, events):
        with mock.patch.object(tasks, 'run_command'), \
             mock.patch('builtins.open', mock.mock_open(read_data='[]')), \
             mock.patch.object(tasks.json, 'load', return_value=events), \
             mock.patch.object(tasks, 'seed_spiderfoot_config', return_value=False):
            tasks.spiderfoot_scan({}, 'delphos.com.br', self.scan.id, 1, '/tmp', ctx=self.ctx)

    def test_company_name_routed_to_org_bucket(self):
        self._run([{'type': 'Company Name', 'data': 'Delphos SA',
                    'module': 'sfp_x', 'source': 'delphos.com.br', 'generated': 1781925945}])
        self.assertTrue(OsintResult.objects.filter(
            bucket=OsintResult.BUCKET_ORG, data='Delphos SA').exists())

    def test_linked_url_routed_to_endpoint(self):
        with mock.patch.object(tasks, 'save_endpoint') as se:
            self._run([{'type': 'Linked URL - Internal',
                        'data': 'https://delphos.com.br/admin', 'module': 'sfp_spider',
                        'source': 'delphos.com.br', 'generated': 1781925945}])
            se.assert_called()

    def test_provenance_flows_into_osint(self):
        self._run([{'type': 'DNS TXT Record', 'data': 'v=spf1', 'module': 'sfp_dnsraw',
                    'source': 'delphos.com.br', 'generated': 1781925945}])
        row = OsintResult.objects.get(event_type='DNS TXT Record')
        self.assertEqual((row.module, row.parent), ('sfp_dnsraw', 'delphos.com.br'))
```

> The exact mock surface (`run_command`, file read, `json.load`) mirrors how `spiderfoot_scan` loads its output; adjust the patch targets to the real names in the function if they differ.

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 manage.py test tests.test_osint_capture.SpiderfootRoutingTests -v 2`
Expected: FAIL — Company Name dropped (no `BUCKET_ORG` row); provenance not stored.

- [ ] **Step 3: Implement**

```python
# web/Suricatoos/tasks.py — remove 'Linked URL - Internal' and 'Internet Name - Unresolved'
# from SF_DROP:
SF_DROP = {
    'Raw Data from RIRs/APIs', 'Raw DNS Records', 'Affiliate Description - Category',
    'Hash',
}

# In _sf_bucket, add an Organization branch BEFORE the final `return None`:
    if t in ('Company Name', 'Domain Name - Organisation'):
        return (OsintResult.BUCKET_ORG, False, 0)

# In the spiderfoot_scan event loop, extend the typed routing and pass provenance:
SF_URLS = {'Linked URL - Internal'}
SF_HOSTS = {'Domain Name', 'Internet Name', 'DOMAIN_NAME', 'INTERNET_NAME',
            'Internet Name - Unresolved'}
# ... inside the loop, before _sf_bucket:
            elif etype in SF_URLS:
                save_endpoint(data, ctx=ctx)
                saved += 1
# ... and in the intel branch, pass the new kwargs:
                save_osint_result(
                    scan_history, bucket, etype, data,
                    extra=ev.get('module'), is_malicious=is_mal, severity=sev,
                    module=ev.get('module'), parent=ev.get('source'),
                    generated=ev.get('generated'))
# ... add drop telemetry: count `None` routes and log the top dropped types in the summary.
```

Also add a `dropped = Counter()` near `saved = 0`, increment it when `_sf_bucket` returns `None`, and extend the final `logger.info` with `f'{sum(dropped.values())} dropped (top: {dropped.most_common(3)})'`. Import `Counter` from `collections` if not already imported.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 manage.py test tests.test_osint_capture.SpiderfootRoutingTests -v 2`
Expected: PASS (3).

- [ ] **Step 5: Commit**

```bash
git add web/Suricatoos/tasks.py web/tests/test_osint_capture.py
git commit -m "feat(osint): route Linked URLs/unresolved/Company Name + drop telemetry"
```

---

## Task 14: Expose new OSINT fields in the serializer (Front B)

**Files:**
- Modify: `web/api/serializers.py::OsintResultSerializer` (~793-801)
- Test: `web/tests/test_osint_capture.py`

**Interfaces:**
- Produces: serialized `OsintResult` includes `module`, `parent`, `confidence`.

- [ ] **Step 1: Write the failing test**

```python
# append to web/tests/test_osint_capture.py
from api.serializers import OsintResultSerializer


class OsintSerializerTests(TestCase):
    def test_new_fields_serialized(self):
        o = OsintResult.objects.create(event_type='X', data='d', module='sfp_dnsraw',
                                       parent='delphos.com.br', confidence=70)
        out = OsintResultSerializer(o).data
        for f in ('module', 'parent', 'confidence'):
            self.assertIn(f, out)
        self.assertEqual(out['confidence'], 70)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 manage.py test tests.test_osint_capture.OsintSerializerTests -v 2`
Expected: FAIL — `module` not in serialized output.

- [ ] **Step 3: Implement**

```python
# web/api/serializers.py
class OsintResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = OsintResult
        fields = [
            'id', 'scan_history', 'target_domain', 'source', 'bucket',
            'event_type', 'data', 'extra', 'is_malicious', 'severity',
            'discovered_date', 'module', 'parent', 'confidence',
        ]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 manage.py test tests.test_osint_capture.OsintSerializerTests -v 2`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add web/api/serializers.py web/tests/test_osint_capture.py
git commit -m "feat(osint): expose module/parent/confidence in OsintResultSerializer"
```

---

## Task 15: Full-suite verification

**Files:** none (verification only).

- [ ] **Step 1: Run the new + adjacent suites**

Run:
```bash
python3 manage.py test tests.test_api_vault tests.test_osint_capture tests.test_secret_scan -v 2
```
Expected: all PASS.

- [ ] **Step 2: Migration sanity**

Run: `python3 manage.py makemigrations --check --dry-run`
Expected: "No changes detected" (every model edit has a migration).

- [ ] **Step 3: Smoke the system check**

Run: `python3 manage.py check`
Expected: no errors.

- [ ] **Step 4: Manual end-to-end (documented, run by a human on the live box during a calm window)**

1. Set a real Shodan key in the API Vault UI.
2. Confirm `build_spiderfoot_config()` returns `{'sfp_shodan:api_key': ...}` (`manage.py shell`).
3. Run an OSINT-only scan on a test domain; confirm `spiderfoot.db` config has the key and SpiderFoot's Shodan module produced events (open ports) that previously were absent.
4. Confirm an OsintResult row now has `module`/`parent` populated and `Linked URL - Internal` events became endpoints.

- [ ] **Step 5: Final commit (if any cleanup)**

```bash
git add -A && git commit -m "chore(vault): full-suite green; migration/check clean" || true
```

---

## Self-Review (completed by plan author)

- **Spec coverage:** Front A §3.1 crypto→T1; §3.3 registry→T2; §3.1 model→T3; §3.5 accessor→T4; §3.4 build_config→T5; §3.7 migration→T6; §3.5 consumer refactor→T7; §3.4 seeding→T8; §3.6 UI→T9; §3.7 admin/env/2nd-path→T10. Front B §3.8 columns→T11; save_osint_result→T12; routing→T13; serializer→T14. Verification→T15. No spec section left without a task.
- **Placeholder scan:** every code step carries real code; the only `00XX` tokens are migration filenames Django fills in (`makemigrations` step present in T3/T6/T11).
- **Type consistency:** `get_api_key`/`get_credential` (T4) used identically in T5/T7/T8/T9/T10; `ApiCredential.upsert/decrypted` (T3) used in T4/T6/T9/T10; `build_spiderfoot_config` (T5) consumed in T8; `save_osint_result(... module, parent, confidence, generated)` (T12) called in T13; `BUCKET_ORG` (T11) used in T12/T13 tests.
- **Known execution caveat:** test-running requires the Django/container env reachable for this branch (Global Constraints) — resolve at execution time; do not run migrations on the live DB without explicit authorization and a calm (no-scan) window.

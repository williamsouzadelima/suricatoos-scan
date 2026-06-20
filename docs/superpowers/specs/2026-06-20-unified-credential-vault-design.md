# Design — Unified API Credential Vault + SpiderFoot key injection

- **Date:** 2026-06-20
- **Branch:** `feat/api-credential-vault` (off `main` @ 1c8d714)
- **Status:** Approved design (pending spec review)
- **Related:** OSINT gap analysis of scan #13 (delphos.com.br) — SpiderFoot produced only passive DNS/affiliate data because **no API keys are configured** and the richest modules (Shodan ports, HaveIBeenPwned breaches, VirusTotal, etc.) stayed dark.

## 1. Problem & Goal

SpiderFoot's highest-value OSINT modules (breached credentials, open ports, malicious reputation, passive DNS, email discovery) require per-module API keys. Today there is **no way to set them**, and SpiderFoot's own key store (`~/.spiderfoot/spiderfoot.db`) lives inside the ephemeral celery container, so it is neither centralized nor web-configurable.

Separately, the existing integration keys (OpenAI, Netlas, Chaos, GitGuardian, HackerOne) are **scattered** across five singleton models in `dashboard/models.py`, each with a hand-written block in the `api_vault` view and `settings/api.html` form — boilerplate that does not scale.

**Goal:** one centralized, web-configurable, encrypted credential vault that holds *all* integration keys — the existing five **plus** SpiderFoot's modules — and injects the SpiderFoot keys into each scan.

## 2. Decisions (from brainstorming)

| Decision | Choice |
|---|---|
| Scope | **Unified vault for ALL integrations** (one generic model), migrating the existing five. |
| SpiderFoot provider coverage | **Curated list (~15 high-value) + "add custom (`module:option`)"** escape hatch. |
| Encryption at rest | **Fernet**, decrypt only at point of use. |
| Vault key source | **Dedicated env `RENGINE_VAULT_KEY`**, fallback to HKDF(`SECRET_KEY`) with a warning. |
| SpiderFoot injection | **Seed `~/.spiderfoot/spiderfoot.db` config each scan** via `SpiderFootDb.configSet()`. |
| Credential scope | **Global** (one set app-wide, matches current singletons). |

## 3. Architecture

### 3.1 Data model — `dashboard/models.py`
Replace the five singleton key models with one generic model:

```python
class ApiCredential(models.Model):
    provider   = models.CharField(max_length=120, unique=True)  # 'openai','shodan','censys','custom:sfp_x:api_key'
    label      = models.CharField(max_length=200, blank=True)   # friendly label (from registry)
    key_enc    = models.TextField()                             # primary secret, Fernet-encrypted
    extra_enc  = models.TextField(null=True, blank=True)        # JSON of secondary fields, Fernet-encrypted
    enabled    = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'ApiCredential<{self.provider}>'   # never the secret
```

- `provider` is `unique` → upsert semantics replace the scattered `.first()` calls.
- `extra_enc` carries multi-field credentials (HackerOne `username`, Censys `uid`+`secret`).
- `__str__` never returns a secret (matches the GitGuardian precedent).

### 3.2 Encryption — `dashboard/crypto.py` (new)
- `encrypt(plaintext: str) -> str` / `decrypt(token: str) -> str` using `cryptography.fernet.Fernet` (dep already present, v43.0.3).
- **Vault key resolution** (cached at module load):
  1. If `env('RENGINE_VAULT_KEY')` is set → use it (must be a 32-byte urlsafe-base64 Fernet key). Decouples the vault from `SECRET_KEY` rotation.
  2. Else derive a Fernet key from `settings.SECRET_KEY` via `HKDF(SHA256, length=32, info=b'rengine-api-vault')`, base64-encoded, and **log a one-time warning** recommending `RENGINE_VAULT_KEY` for production.
- Secrets are decrypted **only** at the moment of use (SF config build / recon call); never logged, never put in template context as plaintext.
- A `MissingVaultKey`/decrypt-failure path returns `None` (treated as "key not set") rather than crashing a scan.

### 3.3 Provider registry — `dashboard/providers.py` (new)
Declarative constant that gives meaning to the generic rows and drives both the UI and the SF config build:

```python
# field tuples: (form_field_name, destination)
#   destination starting with 'sfp_' -> SpiderFoot config option (module:option)
#   destination 'consumer:<name>'    -> used by recon/LLM code via get_credential()
PROVIDERS = {
  # --- SpiderFoot-backed (curated high-value; close the OSINT gap) ---
  'shodan':         {'label':'Shodan',          'url':'https://account.shodan.io',
                     'fields':[('key','sfp_shodan:api_key')]},
  'haveibeenpwned': {'label':'HaveIBeenPwned',  'url':'https://haveibeenpwned.com/API/Key',
                     'fields':[('key','sfp_haveibeenpwned:api_key')]},
  'dehashed':       {'label':'DeHashed',        'fields':[('username','sfp_dehashed:username'),
                                                          ('key','sfp_dehashed:api_key')]},
  'virustotal':     {'label':'VirusTotal',      'fields':[('key','sfp_virustotal:api_key')]},
  'securitytrails': {'label':'SecurityTrails',  'fields':[('key','sfp_securitytrails:api_key')]},
  'hunter':         {'label':'Hunter.io',       'fields':[('key','sfp_hunter:api_key')]},
  'binaryedge':     {'label':'BinaryEdge',      'fields':[('key','sfp_binaryedge:api_key')]},
  'censys':         {'label':'Censys',          'fields':[('key','sfp_censys:api_key_uid'),
                                                          ('secret','sfp_censys:api_key_secret')]},
  'greynoise':      {'label':'GreyNoise',       'fields':[('key','sfp_greynoise:api_key')]},
  'abuseipdb':      {'label':'AbuseIPDB',       'fields':[('key','sfp_abuseipdb:api_key')]},
  'ipinfo':         {'label':'IPInfo',          'fields':[('key','sfp_ipinfo:api_key')]},
  'fullhunt':       {'label':'FullHunt',        'fields':[('key','sfp_fullhunt:api_key')]},
  'intelx':         {'label':'IntelX',          'fields':[('key','sfp_intelx:api_key')]},
  'leakix':         {'label':'LeakIX',          'fields':[('key','sfp_leakix:api_key')]},
  # --- existing integrations (migrated; consumed by recon/LLM/H1, not SF) ---
  'openai':         {'label':'OpenAI',     'fields':[('key','consumer:llm')]},
  'netlas':         {'label':'Netlas',     'fields':[('key','consumer:recon')]},
  'chaos':          {'label':'Chaos',      'fields':[('key','consumer:recon')]},
  'gitguardian':    {'label':'GitGuardian','fields':[('key','consumer:secret')]},
  'hackerone':      {'label':'HackerOne',  'fields':[('username','consumer:h1_user'),
                                                     ('key','consumer:h1_key')]},
}
```

Custom entries: the user supplies a literal `module:option` and a key → stored as `provider='custom:<module>:<option>'`, `fields=[('key', '<module>:<option>')]` (validated against `^sfp_[a-z0-9_]+:[a-z0-9_]+$`).

> The curated SF option names are confirmed against the installed modules (`/usr/src/github/spiderfoot/modules/*.py`; 84 modules expose `api_key`; Censys/DeHashed are the multi-field cases).

### 3.4 SpiderFoot injection — `Suricatoos/tasks.py::spiderfoot_scan`
At the very start of `spiderfoot_scan`, before invoking `sf.py`:

```python
cfg = build_spiderfoot_config()          # {'sfp_shodan:api_key': <decrypted>, ...} for enabled SF-backed creds + custom
if cfg:
    from spiderfoot import SpiderFootDb
    SpiderFootDb({'__database': SF_DB_PATH}).configSet(cfg)   # writes into ~/.spiderfoot/spiderfoot.db
```

`sf.py::start_scan` already merges stored config via `configUnserialize(dbh.configGet(), sfConfig)`, so the seeded options activate the matching modules under the chosen preset. Re-seeding every scan keeps the app DB as the single source of truth and survives the ephemeral container.

- `build_spiderfoot_config()` lives in `Suricatoos/common_func.py` (or a small `osint_keys.py`), iterates enabled `ApiCredential` rows, maps each field to its `sfp_` destination via the registry, decrypts, and returns the flat dict. Recon/LLM destinations (`consumer:*`) are skipped here.
- Failure to write the SF config logs a warning and the scan proceeds key-less (today's behavior) — never aborts.

### 3.5 Accessor + consumer refactor
Single read path in `Suricatoos/common_func.py`:

```python
def get_credential(provider):  # -> (key|None, extra_dict)
def get_api_key(provider):     # -> key|None  (decrypted, enabled-only)
```

Replace the ~12 call sites that do `OpenAiAPIKey.objects.first()` / `NetlasAPIKey...` / `HackerOneAPIKey...` (in `tasks.py`, `common_func.py`, `api/views.py`) with the accessor. Behavior is unchanged from the caller's perspective (still gets the key string), just sourced from the vault and decrypted.

### 3.6 UI — `scanEngine/views.py::api_vault` + `settings/api.html`
Extend the existing **legacy** API Vault page (the SPA is removed):
- Render the registry: an "Integrations" section grouping **SpiderFoot providers** and **existing integrations**, each row = label + "get a key" link + masked current value + `enabled` toggle.
- An "Add custom (`module:option`)" sub-form.
- One **generic POST handler** iterates the registry + posted custom rows, encrypts, upserts `ApiCredential` — deleting the five hand-written blocks. Empty submitted fields are left unchanged (don't wipe on blank, matching current behavior); an explicit "clear" control removes a credential.
- Values are shown masked (e.g. first/last 2 chars) and never re-rendered in full.
- `dashboard/views.py` "tool settings" page (which also writes some keys) is pointed at the same accessor/handler to avoid a second write path.

### 3.7 Migration & backward-compat
- **Schema migration:** add `ApiCredential`.
- **Data migration:** for each existing row in `OpenAiAPIKey/NetlasAPIKey/ChaosAPIKey/GitGuardianAPIKey/HackerOneAPIKey`, encrypt and upsert into `ApiCredential` (HackerOne → `key_enc`=token, `extra_enc`={'username':...}). Guard for the vault key being resolvable at migrate time (it always is — env or SECRET_KEY).
- The five old models are **kept but deprecated** (no longer read/written) so a rollback or manual recovery is possible; a follow-up release drops them. `dashboard/admin.py` registers `ApiCredential` (masked) and de-registers the old ones from active use.

## 4. Module boundaries

| Unit | Responsibility | Depends on |
|---|---|---|
| `dashboard/crypto.py` | encrypt/decrypt, vault-key resolution | `cryptography`, settings/env |
| `dashboard/providers.py` | static registry (label, url, field→destination) | — |
| `dashboard/models.py::ApiCredential` | encrypted storage | crypto |
| `common_func.get_credential/get_api_key` | decrypted read path for consumers | models, crypto, providers |
| `common_func.build_spiderfoot_config` | flat SF config dict from enabled creds | models, crypto, providers |
| `tasks.spiderfoot_scan` (edit) | seed `spiderfoot.db`, then scan | build_spiderfoot_config, SpiderFootDb |
| `scanEngine.api_vault` (rewrite) + `api.html` | UI + generic upsert | models, crypto, providers |

Each is independently testable; the registry is the contract between storage and both consumers (UI, SF build).

## 5. Error handling
- Missing/invalid vault key → decrypt returns `None`; treated as "not configured"; scans run key-less; UI shows a clear banner.
- Malformed custom `module:option` → rejected at form validation with a message.
- Decrypt failure on a single row (e.g. key rotated without re-entry) → that credential is skipped with a logged warning (no secret in the log), others still work.
- SF config seed failure → warning, scan proceeds (no regression vs today).

## 6. Testing (TDD)
1. **crypto**: encrypt→decrypt round-trip; distinct ciphertexts; `RENGINE_VAULT_KEY` path vs SECRET_KEY-derived path; decrypt of garbage → `None`.
2. **model/accessor**: `get_api_key` returns decrypted value for enabled, `None` for disabled/missing.
3. **build_spiderfoot_config**: maps single-field, multi-field (Censys uid+secret), and custom entries to the correct `module:option` keys; skips `consumer:*`; skips disabled.
4. **migration**: existing OpenAI/Netlas/Chaos/GitGuardian/HackerOne rows land in `ApiCredential` decryptable and intact (incl. HackerOne username in `extra`).
5. **UI**: POST creates/updates; blank field leaves value unchanged; clear removes; rendered value is masked; custom `module:option` validation.
6. **security**: no plaintext secret in `__str__`, admin list, logs, or template context; `RENGINE_VAULT_KEY` documented in `.env.example`.

## 7. Out of scope (YAGNI / future)
- Running SpiderFoot via the in-process Python API + enabling its **correlation engine** (a strong follow-up that further closes the OSINT gap — noted, not now).
- Per-project credential scoping.
- Live "test this key" buttons.
- Encrypting unrelated existing secrets beyond these integration keys.

## 8. Deployment notes
- Add `RENGINE_VAULT_KEY` to `.env.example` (+ generation hint: `python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"`).
- Live deploy is a bind-mount; applying needs `migrate` (schema + data) — a DB migration on the live box requires explicit authorization and a calm window (no scan running). celery picks up new task code on the next worker cycle / controlled restart (never mid-scan).

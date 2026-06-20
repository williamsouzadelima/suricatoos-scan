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

from django.db import migrations
from dashboard.migrations import _legacy_loader


def forward(apps, schema_editor):
    _legacy_loader.run(apps)


def backward(apps, schema_editor):
    apps.get_model('dashboard', 'ApiCredential').objects.filter(
        provider__in=['openai', 'netlas', 'chaos', 'gitguardian', 'hackerone']).delete()


class Migration(migrations.Migration):
    dependencies = [('dashboard', '0004_apicredential')]
    operations = [migrations.RunPython(forward, backward)]

# Suricatoos — LeakedSecret model (secret scanning findings: gitleaks / ggshield)

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('targetApp', '0001_initial'),
        ('startScan', '0002_auto_20240911_0145'),
    ]

    operations = [
        migrations.CreateModel(
            name='LeakedSecret',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('source', models.CharField(blank=True, max_length=50, null=True)),
                ('rule_id', models.CharField(blank=True, max_length=200, null=True)),
                ('repo_url', models.CharField(blank=True, max_length=2000, null=True)),
                ('file_path', models.CharField(blank=True, max_length=2000, null=True)),
                ('commit', models.CharField(blank=True, max_length=100, null=True)),
                ('line', models.IntegerField(blank=True, null=True)),
                ('secret_redacted', models.TextField(blank=True, null=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('severity', models.IntegerField(default=4)),
                ('discovered_date', models.DateTimeField(blank=True, null=True)),
                ('scan_history', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='startScan.scanhistory')),
                ('target_domain', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='targetApp.domain')),
            ],
        ),
    ]

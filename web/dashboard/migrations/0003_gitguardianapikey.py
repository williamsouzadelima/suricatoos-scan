# Suricatoos — GitGuardianAPIKey (API vault entry for the ggshield secret scanner)

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0002_chaosapikey_hackeroneapikey_inappnotification_userpreferences'),
    ]

    operations = [
        migrations.CreateModel(
            name='GitGuardianAPIKey',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('key', models.CharField(max_length=500)),
            ],
        ),
    ]

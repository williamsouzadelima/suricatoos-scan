from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('targetApp', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='domain',
            name='send_to_scanner',
            field=models.BooleanField(default=False),
        ),
    ]

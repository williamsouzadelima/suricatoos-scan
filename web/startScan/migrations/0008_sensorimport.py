from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('startScan', '0007_scanbridgejob'),
    ]

    operations = [
        migrations.CreateModel(
            name='SensorImport',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('correlation_id', models.CharField(max_length=128, unique=True)),
                ('tenant', models.CharField(max_length=255)),
                ('imported', models.BooleanField(default=False)),
                ('findings_imported', models.IntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('scan_history', models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='sensor_import', to='startScan.scanhistory')),
            ],
        ),
    ]

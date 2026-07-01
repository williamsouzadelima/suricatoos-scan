from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('startScan', '0006_osintresult_capture'),
    ]

    operations = [
        migrations.CreateModel(
            name='ScanBridgeJob',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('request_id', models.CharField(blank=True, max_length=64, null=True)),
                ('gvm_task_id', models.CharField(blank=True, max_length=64, null=True)),
                ('gvm_report_id', models.CharField(blank=True, max_length=64, null=True)),
                ('state', models.CharField(default='SUBMITTED', max_length=20)),
                ('hosts_sent', models.IntegerField(default=0)),
                ('findings_imported', models.IntegerField(default=0)),
                ('imported', models.BooleanField(default=False)),
                ('retries', models.IntegerField(default=0)),
                ('error', models.TextField(blank=True, null=True)),
                ('submitted_at', models.DateTimeField(auto_now_add=True)),
                ('last_polled', models.DateTimeField(blank=True, null=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('scan_history', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='scanner_job', to='startScan.scanhistory')),
            ],
        ),
    ]

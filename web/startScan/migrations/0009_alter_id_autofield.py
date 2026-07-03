from django.db import migrations, models


class Migration(migrations.Migration):
    """Alinha o campo `id` de ScanBridgeJob e SensorImport ao AutoField declarado
    explicitamente nos models (o DEFAULT_AUTO_FIELD do projeto é BigAutoField, então
    o Django detectava um drift cosmético a cada checagem). Só metadata do campo id;
    as tabelas são AutoField no DB. Fecha o aviso 'have changes not reflected'."""

    dependencies = [
        ('startScan', '0008_sensorimport'),
    ]

    operations = [
        migrations.AlterField(
            model_name='scanbridgejob',
            name='id',
            field=models.AutoField(primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='sensorimport',
            name='id',
            field=models.AutoField(primary_key=True, serialize=False),
        ),
    ]

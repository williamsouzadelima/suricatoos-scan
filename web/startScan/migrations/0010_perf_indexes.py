# Onda 3 (#20) — índices em campos quentes de filtro/ordenação (perf de DataTables/dashboard).
# Transparente ao contrato de saída (só acelera). AddIndex padrão é atômico: o CREATE INDEX
# trava a tabela contra escritas durante a criação — aceitável na janela de deploy. Para
# tabelas MUITO grandes, converter p/ django.contrib.postgres.operations.AddIndexConcurrently
# com `atomic = False` (evita o lock).
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('startScan', '0009_alter_id_autofield'),
    ]

    operations = [
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(fields=['severity'], name='vuln_severity_idx'),
        ),
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(fields=['validation_status'], name='vuln_valstatus_idx'),
        ),
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(fields=['target_domain', 'severity'], name='vuln_domain_sev_idx'),
        ),
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(fields=['scan_history', 'severity'], name='vuln_scan_sev_idx'),
        ),
        migrations.AddIndex(
            model_name='subdomain',
            index=models.Index(fields=['name'], name='subdomain_name_idx'),
        ),
    ]

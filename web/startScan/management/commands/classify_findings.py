"""Reclassifica achados existentes em vulnerability / hygiene / inventory.

Por que existe: o scanner grava RECONHECIMENTO na mesma tabela que vulnerabilidade.
Medido em producao (26/07/2026, 12.096 achados): 97,3% eram `info` e o achado de maior
volume era "RDAP WHOIS" (3.923) — uma consulta WHOIS; o 3o era "WAF Detection" (1.532),
que e uma coisa boa. Enquanto isso conta como vulnerabilidade, todo numero que o cliente
ve mente, e os achados criticos de verdade ficam soterrados.

A classificacao nova vale para achados NOVOS automaticamente (save_vulnerability). Este
comando e o passo explicito para os que ja estao no banco.

  manage.py classify_findings                 # DRY-RUN: so mostra o que mudaria
  manage.py classify_findings --apply         # grava
  manage.py classify_findings --apply --scan-id 69

Dry-run e o default de proposito: reclassificar 12k linhas muda o que o cliente ve.
"""
from collections import Counter

from django.core.management.base import BaseCommand
from django.db import transaction

from startScan.models import Vulnerability
from Suricatoos.common_func import classify_finding


class Command(BaseCommand):
    help = "Reclassifica achados existentes em vulnerability/hygiene/inventory (dry-run por padrao)."

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true',
                            help='grava as mudancas (sem isto, apenas mostra)')
        parser.add_argument('--scan-id', type=int, default=None,
                            help='limita a um ScanHistory')
        parser.add_argument('--show', type=int, default=15,
                            help='quantos exemplos por classe mostrar (default 15)')

    def handle(self, *args, **opts):
        apply_changes = opts['apply']
        qs = Vulnerability.objects.all().prefetch_related('tags')
        if opts['scan_id']:
            qs = qs.filter(scan_history__id=opts['scan_id'])

        total = qs.count()
        if not total:
            self.stdout.write('Nenhum achado a classificar.')
            return

        antes = Counter()
        depois = Counter()
        mudancas = []
        severos_rebaixados = []
        # Amostra por (classe nova, nome) para o operador CONFERIR a regra antes de aplicar
        # — reclassificar em massa sem olhar e como nao ter medido.
        exemplos = {}

        for vuln in qs.iterator(chunk_size=500):
            tags = [t.name for t in vuln.tags.all()]
            novo = classify_finding(vuln.severity, tags, vuln.template_id)
            antes[vuln.finding_class] += 1
            depois[novo] += 1
            exemplos.setdefault(novo, Counter())[vuln.name[:60]] += 1
            if novo != vuln.finding_class:
                mudancas.append((vuln.id, novo))
                # Trava: nada de severidade media+ pode sair de `vulnerability`. O piso
                # em classify_finding existe para impedir isso; se chegou aqui, a regra
                # regrediu e reclassificar em massa esconderia risco real.
                if vuln.severity >= 2 and novo != Vulnerability.CLASS_VULNERABILITY:
                    severos_rebaixados.append((vuln.id, vuln.severity, vuln.name[:60], novo))

        self.stdout.write(f'\nTotal de achados: {total}')
        self.stdout.write('\nANTES:')
        for k, v in antes.most_common():
            self.stdout.write(f'  {k:<16} {v:>6}')
        self.stdout.write('\nDEPOIS:')
        for k, v in depois.most_common():
            pct = 100.0 * v / total
            self.stdout.write(f'  {k:<16} {v:>6}  ({pct:.1f}%)')

        for classe in sorted(exemplos):
            self.stdout.write(f'\nTop achados em "{classe}":')
            for nome, n in exemplos[classe].most_common(opts['show']):
                self.stdout.write(f'  {n:>5}  {nome}')

        if severos_rebaixados:
            self.stderr.write(self.style.ERROR(
                f'\nABORTADO: {len(severos_rebaixados)} achado(s) de severidade media+ '
                f'seriam rebaixados. O piso de classify_finding deveria impedir isso — '
                f'a regra regrediu.'))
            for vid, sev, nome, novo in severos_rebaixados[:10]:
                self.stderr.write(f'  id={vid} sev={sev} -> {novo}  {nome}')
            return

        self.stdout.write(f'\nMudariam de classe: {len(mudancas)} de {total}')
        if not apply_changes:
            self.stdout.write(self.style.WARNING(
                '\nDRY-RUN. Nada foi gravado. Rode com --apply para valer.'))
            return

        with transaction.atomic():
            for classe in (Vulnerability.CLASS_INVENTORY, Vulnerability.CLASS_HYGIENE,
                           Vulnerability.CLASS_VULNERABILITY):
                ids = [i for i, c in mudancas if c == classe]
                for i in range(0, len(ids), 1000):
                    Vulnerability.objects.filter(id__in=ids[i:i + 1000]).update(
                        finding_class=classe)
        self.stdout.write(self.style.SUCCESS(
            f'\nAplicado: {len(mudancas)} achado(s) reclassificado(s).'))

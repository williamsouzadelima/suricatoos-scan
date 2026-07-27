"""Run the local-Ollama FP-judge over existing findings and print verdicts.

This is a TEST/triage helper — it does NOT write to the DB. Use it to see how the
LLM flags likely false positives before wiring the judge into the scan pipeline.

  manage.py triage_vulns --scan-id 24 --limit 20
  manage.py triage_vulns --min-severity 4 --model qwen2.5:3b
  manage.py triage_vulns --source dalfox --min-severity 2 --limit 30

O filtro era fixo em source='nuclei'. Medido em 27/07/2026, isso deixava o juiz
alcancando 31 dos 265 achados que o cliente ve: os outros 234 sao XSS do dalfox,
e desses NENHUM jamais foi validado — 154 nunca processados e 80 recusados pelo
validador v1, que so trata template do nuclei. Era justamente o bloco sem
curadoria nenhuma que ficava fora do alcance da unica ferramenta de curadoria.

A classe LLMFPJudge ja e agnostica de fonte (julga por name/template_id/severity/
http_url/extracted_results/response); so o filtro daqui restringia.

Note: loads an Ollama model (~2-3 GB) — run it when no scan is competing for RAM.
Este host tem 3,8 GB e o celery sozinho chega a 1,4 GB durante um scan: rodar com
scan em voo e a receita do OOM que abortou os scans 66/67/68.
"""
import logging

from django.core.management.base import BaseCommand

from startScan.models import Vulnerability
from Suricatoos.llm import LLMFPJudge


class Command(BaseCommand):
    help = "Run the local-Ollama FP-judge over existing findings (prints verdicts; no DB write)."

    def add_arguments(self, parser):
        parser.add_argument('--scan-id', type=int, default=None, help='limit to a ScanHistory id')
        parser.add_argument('--limit', type=int, default=20, help='max findings to judge (default 20)')
        parser.add_argument('--min-severity', type=int, default=3,
                            help='nuclei severity floor: 3=high, 4=critical (default 3)')
        parser.add_argument('--model', default=None, help='ollama model (default qwen2.5:3b)')
        parser.add_argument('--source', default='nuclei',
                            help="fonte do achado: nuclei (padrao), dalfox, ou 'all'")
        parser.add_argument('--all-classes', action='store_true',
                            help='julga tambem higiene/inventario (padrao: so vulnerability)')

    def handle(self, *args, **opts):
        logger = logging.getLogger('triage_vulns')
        # So `vulnerability` por padrao: julgar inventario e higiene gasta minutos de
        # inferencia num achado que ja foi tirado da contagem de risco pela taxonomia.
        qs = (Vulnerability.objects if opts['all_classes']
              else Vulnerability.objects.user_facing())
        qs = qs.filter(severity__gte=opts['min_severity']).order_by('-id')
        if opts['source'] != 'all':
            qs = qs.filter(source=opts['source'])
        if opts['scan_id']:
            qs = qs.filter(scan_history_id=opts['scan_id'])
        total = qs.count()
        rows = list(qs[:opts['limit']])
        judge = LLMFPJudge(logger=logger, model_name=opts['model'])

        escopo = 'todas as classes' if opts['all_classes'] else 'so vulnerability'
        self.stdout.write(self.style.MIGRATE_HEADING(
            f'Judging {len(rows)} of {total} findings '
            f'(source={opts["source"]}, severity>={opts["min_severity"]}, {escopo}) '
            f'with model "{judge.model_name}"\n'))

        counts = {}
        for v in rows:
            verdict = judge.judge(LLMFPJudge.evidence_from_vuln(v))
            counts[verdict['verdict']] = counts.get(verdict['verdict'], 0) + 1
            line = (f"[{verdict['verdict']:12}] conf={verdict['confidence']:.2f} "
                    f"val={(v.validation_status or '-'):14} "
                    f"sev={v.severity} {str(v.name)[:46]:46} "
                    f"({v.template_id}) — {verdict['reason']}")
            style = (self.style.ERROR if verdict['verdict'] == 'likely_fp'
                     else self.style.SUCCESS if verdict['verdict'] == 'real'
                     else self.style.WARNING)
            self.stdout.write(style(line))

        self.stdout.write('\n' + self.style.MIGRATE_HEADING(f'Summary: {counts}'))

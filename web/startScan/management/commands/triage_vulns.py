"""Run the local-Ollama FP-judge over existing nuclei findings and print verdicts.

This is a TEST/triage helper — it does NOT write to the DB. Use it to see how the
LLM flags likely false positives before wiring the judge into the scan pipeline.

  manage.py triage_vulns --scan-id 24 --limit 20
  manage.py triage_vulns --min-severity 4 --model qwen2.5:3b

Note: loads an Ollama model (~2-3 GB) — run it when no scan is competing for RAM.
"""
import logging

from django.core.management.base import BaseCommand

from startScan.models import Vulnerability
from Suricatoos.llm import LLMFPJudge


class Command(BaseCommand):
    help = "Run the local-Ollama FP-judge over existing nuclei findings (prints verdicts; no DB write)."

    def add_arguments(self, parser):
        parser.add_argument('--scan-id', type=int, default=None, help='limit to a ScanHistory id')
        parser.add_argument('--limit', type=int, default=20, help='max findings to judge (default 20)')
        parser.add_argument('--min-severity', type=int, default=3,
                            help='nuclei severity floor: 3=high, 4=critical (default 3)')
        parser.add_argument('--model', default=None, help='ollama model (default qwen2.5:3b)')

    def handle(self, *args, **opts):
        logger = logging.getLogger('triage_vulns')
        qs = (Vulnerability.objects
              .filter(source='nuclei', severity__gte=opts['min_severity'])
              .order_by('-id'))
        if opts['scan_id']:
            qs = qs.filter(scan_history_id=opts['scan_id'])
        total = qs.count()
        rows = list(qs[:opts['limit']])
        judge = LLMFPJudge(logger=logger, model_name=opts['model'])

        self.stdout.write(self.style.MIGRATE_HEADING(
            f'Judging {len(rows)} of {total} nuclei findings '
            f'(severity>={opts["min_severity"]}) with model "{judge.model_name}"\n'))

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

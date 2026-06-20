"""OWASP A09 — Security Logging Failures.

A09-1: the h8mail OSINT task must NOT write raw leaked-credential records to the
logs (cred['data'] holds plaintext passwords/hashes/PII), and must delete the raw
h8mail.json report from disk after parsing (mirroring the gitleaks/ggshield paths
which redact + _safe_remove).
"""
import json
import os
import shutil
import tempfile
from unittest.mock import patch, MagicMock

from django.test import TestCase

from Suricatoos import tasks


class H8mailLogRedactionTests(TestCase):
    SECRET_PASSWORD = 'SuperSecretLeakedPassw0rd!'

    def setUp(self):
        self.results_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.results_dir, ignore_errors=True)

    def _fake_h8mail_run(self, *args, **kwargs):
        """Stand in for run_command: emulate h8mail writing its JSON report with a
        breached credential record."""
        with open(os.path.join(self.results_dir, 'h8mail.json'), 'w') as f:
            json.dump({'targets': [{
                'target': 'victim@example.com',
                'pwn_num': 3,
                'data': [f'BreachDB:{self.SECRET_PASSWORD}'],
            }]}, f)

    def test_breach_credentials_not_logged_and_report_deleted(self):
        scan = MagicMock()
        scan.emails.all.return_value = [MagicMock(address='victim@example.com')]
        with patch.object(tasks.ScanHistory.objects, 'get', return_value=scan), \
                patch.object(tasks, 'run_command', side_effect=self._fake_h8mail_run), \
                patch.object(tasks, 'save_email', return_value=(MagicMock(), True)), \
                self.assertLogs('Suricatoos.tasks', level='INFO') as cm:
            tasks.h8mail('cfg', 'example.com', 1, 1, self.results_dir)

        logs = '\n'.join(cm.output)
        # the raw leaked password must never reach the logs
        self.assertNotIn(self.SECRET_PASSWORD, logs)
        # a non-sensitive triage line (email + breach count) is acceptable
        self.assertIn('victim@example.com', logs)
        # the raw report must be removed so creds are not left on disk
        self.assertFalse(
            os.path.exists(os.path.join(self.results_dir, 'h8mail.json')),
            'raw h8mail.json must be deleted after parsing',
        )

"""Tests for the secret-scanning feature (gitleaks / ggshield -> LeakedSecret).

Run with the project test runner, e.g.:
    python3 manage.py test tests.test_secret_scan
"""
import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault('SURICATOOS_SECRET_KEY', 'secret')
os.environ.setdefault('CELERY_ALWAYS_EAGER', 'True')

from django.test import TestCase
from django.utils import timezone

from Suricatoos.tasks import (redact_secret, save_leaked_secret,
                              run_gitleaks_scan)
from startScan.models import LeakedSecret, ScanHistory
from targetApp.models import Domain
from scanEngine.models import EngineType


class TestRedactSecret(unittest.TestCase):
    """Pure-logic tests — the raw secret must NEVER survive redaction."""

    def test_short_secret_is_fully_masked(self):
        self.assertEqual(redact_secret('abc'), '***')
        self.assertEqual(redact_secret('12345678'), '*' * 8)

    def test_long_secret_keeps_only_prefix_and_suffix(self):
        self.assertEqual(redact_secret('AKIA1234567890SECRET'), 'AKI********ET')

    def test_raw_secret_never_present_in_output(self):
        raw = 'ghp_supersecrettoken1234567890'
        out = redact_secret(raw)
        self.assertNotIn(raw, out)
        self.assertNotIn('supersecrettoken', out)

    def test_falsy_values_pass_through(self):
        self.assertIsNone(redact_secret(None))
        self.assertEqual(redact_secret(''), '')


class TestLeakedSecretModel(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='example.com')
        self.engine = EngineType.objects.create(
            engine_name='t', yaml_configuration='secret_scan: {}')
        self.scan = ScanHistory.objects.create(
            domain=self.domain, scan_type=self.engine,
            start_scan_date=timezone.now())

    def test_get_leaked_secret_count(self):
        self.assertEqual(self.scan.get_leaked_secret_count(), 0)
        LeakedSecret.objects.create(
            scan_history=self.scan, source='gitleaks', rule_id='aws-key',
            secret_redacted='AKI********ET', severity=4)
        self.assertEqual(self.scan.get_leaked_secret_count(), 1)

    def test_save_leaked_secret_is_idempotent(self):
        data = {
            'source': 'gitleaks', 'rule_id': 'aws-key', 'file_path': 'a.env',
            'commit': None, 'line': 3, 'secret_redacted': 'AKI********ET',
            'description': 'AWS key', 'severity': 4,
            'discovered_date': timezone.now(),
        }
        first = save_leaked_secret(dict(data), scan_history=self.scan,
                                   domain=self.domain)
        self.assertIsNotNone(first)
        dup = save_leaked_secret(dict(data), scan_history=self.scan,
                                 domain=self.domain)
        self.assertIsNone(dup)
        self.assertEqual(
            LeakedSecret.objects.filter(scan_history=self.scan).count(), 1)


class TestGitleaksParsing(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='example.com')
        self.engine = EngineType.objects.create(
            engine_name='t', yaml_configuration='secret_scan: {}')
        self.scan = ScanHistory.objects.create(
            domain=self.domain, scan_type=self.engine,
            start_scan_date=timezone.now())
        self.tmp = tempfile.mkdtemp()
        self.fake_self = SimpleNamespace(
            yaml_configuration={'secret_scan': {'gitleaks_mode': 'dir'}},
            results_dir=self.tmp,
            history_file=f'{self.tmp}/commands.txt',
            scan_id=self.scan.id,
            activity_id=None,
            scan=self.scan,
            domain=self.domain,
        )

    @patch('Suricatoos.tasks.run_command')
    def test_findings_are_parsed_and_stored_masked(self, mock_run):
        # gitleaks writes its JSON report; mock run_command and pre-write it.
        report = [
            {
                'RuleID': 'aws-access-token',
                'Description': 'AWS Access Token',
                'StartLine': 12,
                'Match': 'aws_key = AKIAIOSFODNN7EXAMPLE',
                'Secret': 'AKIAIOSFODNN7EXAMPLE',
                'File': 'config/prod.env',
                'Commit': 'abc123',
            }
        ]
        with open(f'{self.tmp}/gitleaks.json', 'w') as f:
            json.dump(report, f)

        count = run_gitleaks_scan(self.fake_self, self.tmp)

        self.assertEqual(count, 1)
        ls = LeakedSecret.objects.get(scan_history=self.scan)
        self.assertEqual(ls.source, 'gitleaks')
        self.assertEqual(ls.rule_id, 'aws-access-token')
        self.assertEqual(ls.file_path, 'config/prod.env')
        self.assertEqual(ls.line, 12)
        self.assertEqual(ls.severity, 4)
        # The raw secret must never be persisted.
        self.assertNotIn('AKIAIOSFODNN7EXAMPLE', ls.secret_redacted or '')

    @patch('Suricatoos.tasks.run_command')
    def test_missing_report_is_handled_gracefully(self, mock_run):
        # No report file -> no crash, no findings.
        count = run_gitleaks_scan(self.fake_self, self.tmp)
        self.assertEqual(count, 0)
        self.assertEqual(
            LeakedSecret.objects.filter(scan_history=self.scan).count(), 0)


if __name__ == '__main__':
    unittest.main()

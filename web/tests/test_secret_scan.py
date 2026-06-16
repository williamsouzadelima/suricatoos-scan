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
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from Suricatoos.tasks import (redact_secret, save_leaked_secret,
                              run_gitleaks_scan, run_ggshield_scan,
                              spiderfoot_scan)
from api.serializers import LeakedSecretSerializer
from api.views import LeakedSecretViewSet
from dashboard.models import GitGuardianAPIKey
from startScan.models import (LeakedSecret, ScanHistory, Email, Employee,
                              IpAddress)
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


class TestGgshieldParsing(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='example.com')
        self.engine = EngineType.objects.create(
            engine_name='t', yaml_configuration='secret_scan: {}')
        self.scan = ScanHistory.objects.create(
            domain=self.domain, scan_type=self.engine,
            start_scan_date=timezone.now())
        self.tmp = tempfile.mkdtemp()
        # ggshield needs a GitGuardian key; provide one via the API vault.
        GitGuardianAPIKey.objects.create(key='test-key')
        self.fake_self = SimpleNamespace(
            results_dir=self.tmp,
            history_file=f'{self.tmp}/commands.txt',
            scan_id=self.scan.id,
            activity_id=None,
            scan=self.scan,
            domain=self.domain,
        )

    @patch('Suricatoos.tasks.run_command')
    def test_nested_report_is_parsed_and_masked(self, mock_run):
        report = {
            'scans': [{
                'entities_with_incidents': [{
                    'filename': 'settings.py',
                    'incidents': [{
                        'type': 'Generic Password',
                        'policy': 'Secrets detection',
                        'occurrences': [{
                            'match': 'hunter2supersecret',
                            'type': 'password',
                            'line_start': 7,
                        }],
                    }],
                }],
            }],
        }
        with open(f'{self.tmp}/ggshield.json', 'w') as f:
            json.dump(report, f)

        count = run_ggshield_scan(self.fake_self, self.tmp)

        self.assertEqual(count, 1)
        ls = LeakedSecret.objects.get(scan_history=self.scan, source='ggshield')
        self.assertEqual(ls.rule_id, 'Generic Password')
        self.assertEqual(ls.file_path, 'settings.py')
        self.assertEqual(ls.line, 7)
        self.assertNotIn('hunter2supersecret', ls.secret_redacted or '')

    @patch('Suricatoos.tasks.run_command')
    def test_skips_when_no_key_configured(self, mock_run):
        GitGuardianAPIKey.objects.all().delete()
        os.environ.pop('GITGUARDIAN_API_KEY', None)
        count = run_ggshield_scan(self.fake_self, self.tmp)
        self.assertEqual(count, 0)


class TestSpiderFootMapping(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='example.com')
        self.engine = EngineType.objects.create(
            engine_name='t', yaml_configuration='osint: {}')
        self.scan = ScanHistory.objects.create(
            domain=self.domain, scan_type=self.engine,
            start_scan_date=timezone.now())
        self.tmp = tempfile.mkdtemp()
        self.ctx = {
            'track': False,
            'yaml_configuration': {'osint': {}},
            'results_dir': self.tmp,
            'scan_history_id': self.scan.id,
            'domain_id': self.domain.id,
        }

    @patch('Suricatoos.tasks.run_command')
    def test_events_are_mapped_to_existing_models(self, mock_run):
        events = [
            {'type': 'EMAILADDR', 'data': 'admin@example.com'},
            {'type': 'IP_ADDRESS', 'data': '203.0.113.5'},
            {'type': 'HUMAN_NAME', 'data': 'John Doe'},
        ]
        with open(f'{self.tmp}/spiderfoot.json', 'w') as f:
            json.dump(events, f)

        spiderfoot_scan(
            config={}, host=self.domain.name, scan_history_id=self.scan.id,
            activity_id=None, results_dir=self.tmp, ctx=self.ctx)

        self.assertTrue(Email.objects.filter(address='admin@example.com').exists())
        self.assertTrue(IpAddress.objects.filter(address='203.0.113.5').exists())
        self.assertTrue(Employee.objects.filter(name='John Doe').exists())


class TestLeakedSecretAPI(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='example.com')
        self.engine = EngineType.objects.create(
            engine_name='t', yaml_configuration='secret_scan: {}')
        self.scan = ScanHistory.objects.create(
            domain=self.domain, scan_type=self.engine,
            start_scan_date=timezone.now())
        self.ls = LeakedSecret.objects.create(
            scan_history=self.scan, target_domain=self.domain, source='gitleaks',
            rule_id='aws-key', file_path='a.env', line=3,
            secret_redacted='AKI********ET', severity=4)

    def test_serializer_exposes_masked_secret_only(self):
        data = LeakedSecretSerializer(self.ls).data
        self.assertEqual(data['source'], 'gitleaks')
        self.assertEqual(data['secret_redacted'], 'AKI********ET')
        # There is no raw `secret` field — only the masked one is exposed.
        self.assertNotIn('secret', data)

    def test_viewset_filters_by_scan_history(self):
        other = ScanHistory.objects.create(
            domain=self.domain, scan_type=self.engine,
            start_scan_date=timezone.now())
        LeakedSecret.objects.create(
            scan_history=other, source='gitleaks', rule_id='other', severity=4)

        req = Request(APIRequestFactory().get(
            '/api/listLeakedSecrets/', {'scan_history': str(self.scan.id)}))
        viewset = LeakedSecretViewSet()
        viewset.request = req
        qs = viewset.get_queryset()

        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first().rule_id, 'aws-key')


if __name__ == '__main__':
    unittest.main()

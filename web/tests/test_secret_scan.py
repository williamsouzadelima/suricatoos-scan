"""Tests for the secret-scanning feature (gitleaks / ggshield -> LeakedSecret).

Run with the project test runner, e.g.:
    python3 manage.py test tests.test_secret_scan
"""
import json
import os
import shlex
import shutil
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
                              spiderfoot_scan, secret_scan)
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

    def test_medium_length_secret_is_fully_masked(self):
        # 9-15 char secrets reveal nothing — a 3+2 char window would expose too
        # large a fraction of them.
        self.assertEqual(redact_secret('hunter2pass'), '*' * 11)
        self.assertEqual(redact_secret('a' * 15), '*' * 15)
        # The reveal only kicks in at 16+ chars.
        self.assertEqual(redact_secret('A' * 16), 'AAA' + '*' * 8 + 'AA')

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
            'source': 'gitleaks', 'rule_id': 'aws-key', 'repo_url': '/srv/app',
            'file_path': 'a.env', 'commit': None, 'line': 3,
            'secret_redacted': 'AKI********ET', 'description': 'AWS key',
            'severity': 4, 'discovered_date': timezone.now(),
        }
        first = save_leaked_secret(dict(data), scan_history=self.scan,
                                   domain=self.domain)
        self.assertIsNotNone(first)
        dup = save_leaked_secret(dict(data), scan_history=self.scan,
                                 domain=self.domain)
        self.assertIsNone(dup)
        self.assertEqual(
            LeakedSecret.objects.filter(scan_history=self.scan).count(), 1)

    def test_distinct_secrets_at_same_location_are_kept(self):
        # Two different secrets at the same rule/file/line must NOT be deduped
        # away — secret_redacted is part of the record identity.
        base = {
            'source': 'gitleaks', 'rule_id': 'aws-key', 'repo_url': '/srv/app',
            'file_path': 'a.env', 'commit': None, 'line': 3,
            'description': 'AWS key', 'severity': 4,
            'discovered_date': timezone.now(),
        }
        a = dict(base, secret_redacted='AAA********11')
        b = dict(base, secret_redacted='BBB********22')
        self.assertIsNotNone(save_leaked_secret(
            dict(a), scan_history=self.scan, domain=self.domain))
        self.assertIsNotNone(save_leaked_secret(
            dict(b), scan_history=self.scan, domain=self.domain))
        self.assertEqual(
            LeakedSecret.objects.filter(scan_history=self.scan).count(), 2)

    def test_gitguardian_str_does_not_leak_key(self):
        # __str__ surfaces in admin/logs/templates — it must never be the token.
        k = GitGuardianAPIKey.objects.create(key='ggp_supersecret_value_123')
        self.assertNotIn('ggp_supersecret_value_123', str(k))


class TestGitleaksParsing(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='example.com')
        self.engine = EngineType.objects.create(
            engine_name='t', yaml_configuration='secret_scan: {}')
        self.scan = ScanHistory.objects.create(
            domain=self.domain, scan_type=self.engine,
            start_scan_date=timezone.now())
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
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

    @patch('Suricatoos.tasks.run_command')
    def test_malicious_scan_path_is_shell_quoted(self, mock_run):
        # A crafted path from the engine YAML must be quoted, not interpolated raw
        # into the shell=True command (command-injection guard).
        evil = '/tmp/x; touch /tmp/pwned #'
        run_gitleaks_scan(self.fake_self, evil)
        cmd = mock_run.call_args.args[0]
        self.assertIn(shlex.quote(evil), cmd)
        # With the path quoted, the injected command is inert text.
        self.assertNotIn('; touch /tmp/pwned', cmd.replace(shlex.quote(evil), ''))

    @patch('Suricatoos.tasks.run_command')
    def test_invalid_mode_falls_back_to_dir(self, mock_run):
        # An out-of-allowlist gitleaks_mode must not reach the command verb.
        self.fake_self.yaml_configuration = {
            'secret_scan': {'gitleaks_mode': 'git; rm -rf /'}}
        run_gitleaks_scan(self.fake_self, self.tmp)
        cmd = mock_run.call_args.args[0]
        self.assertTrue(cmd.startswith('gitleaks dir '))
        self.assertNotIn('rm -rf', cmd)

    @patch('Suricatoos.tasks.run_command')
    def test_report_file_is_deleted_after_parse(self, mock_run):
        # The raw report on disk must be removed once parsed (no secret-at-rest).
        report = f'{self.tmp}/gitleaks.json'
        with open(report, 'w') as f:
            json.dump([], f)
        run_gitleaks_scan(self.fake_self, self.tmp)
        self.assertFalse(os.path.exists(report))

    @patch('Suricatoos.tasks.run_command', side_effect=RuntimeError('db write boom'))
    def test_report_deleted_even_if_run_command_raises(self, mock_run):
        # gitleaks writes the raw report BEFORE run_command returns; if run_command
        # then raises (e.g. a DB/history-file write error), the report must STILL
        # be deleted — run_command lives inside the try guarded by the finally.
        report = f'{self.tmp}/gitleaks.json'
        with open(report, 'w') as f:
            json.dump([{'RuleID': 'x', 'Secret': 'AKIAIOSFODNN7EXAMPLE'}], f)
        count = run_gitleaks_scan(self.fake_self, self.tmp)
        self.assertEqual(count, 0)
        self.assertFalse(os.path.exists(report))

    @patch('Suricatoos.tasks.run_command')
    def test_non_string_mode_falls_back_to_dir(self, mock_run):
        # A list/dict YAML value must fail the allowlist safely, not raise.
        self.fake_self.yaml_configuration = {
            'secret_scan': {'gitleaks_mode': ['git']}}
        run_gitleaks_scan(self.fake_self, self.tmp)
        cmd = mock_run.call_args.args[0]
        self.assertTrue(cmd.startswith('gitleaks dir '))


class TestGgshieldParsing(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='example.com')
        self.engine = EngineType.objects.create(
            engine_name='t', yaml_configuration='secret_scan: {}')
        self.scan = ScanHistory.objects.create(
            domain=self.domain, scan_type=self.engine,
            start_scan_date=timezone.now())
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(os.environ.pop, 'GITGUARDIAN_API_KEY', None)
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

    @patch('Suricatoos.tasks.run_command')
    def test_key_absent_from_command_and_env_restored(self, mock_run):
        # The GitGuardian key must never appear on the command line, and must not
        # linger in the worker env after the scan.
        os.environ.pop('GITGUARDIAN_API_KEY', None)
        with open(f'{self.tmp}/ggshield.json', 'w') as f:
            json.dump({'scans': []}, f)
        run_ggshield_scan(self.fake_self, self.tmp)
        cmd = mock_run.call_args.args[0]
        self.assertNotIn('test-key', cmd)
        self.assertNotIn('GITGUARDIAN_API_KEY', os.environ)

    @patch('Suricatoos.tasks.run_command')
    def test_malicious_scan_path_is_shell_quoted(self, mock_run):
        evil = '/tmp/x; touch /tmp/pwned #'
        with open(f'{self.tmp}/ggshield.json', 'w') as f:
            json.dump({'scans': []}, f)
        run_ggshield_scan(self.fake_self, evil)
        cmd = mock_run.call_args.args[0]
        self.assertIn(shlex.quote(evil), cmd)

    @patch('Suricatoos.tasks.run_command')
    def test_report_file_is_deleted_after_parse(self, mock_run):
        report = f'{self.tmp}/ggshield.json'
        with open(report, 'w') as f:
            json.dump({'scans': []}, f)
        run_ggshield_scan(self.fake_self, self.tmp)
        self.assertFalse(os.path.exists(report))


class TestSpiderFootMapping(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='example.com')
        self.engine = EngineType.objects.create(
            engine_name='t', yaml_configuration='osint: {}')
        self.scan = ScanHistory.objects.create(
            domain=self.domain, scan_type=self.engine,
            start_scan_date=timezone.now())
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.ctx = {
            'track': False,
            'yaml_configuration': {'osint': {}},
            'results_dir': self.tmp,
            'scan_history_id': self.scan.id,
            'domain_id': self.domain.id,
        }

    # geo_localize is patched so save_ip_address() doesn't enqueue a real Celery
    # task (which would try to reach Redis and stall the test with retries).
    @patch('Suricatoos.tasks.geo_localize')
    @patch('Suricatoos.tasks.run_command')
    def test_events_are_mapped_to_existing_models(self, mock_run, mock_geo):
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

    @patch('Suricatoos.tasks.run_command')
    def test_malicious_preset_falls_back_to_passive(self, mock_run):
        # An out-of-allowlist spiderfoot preset must not reach the shell command.
        with open(f'{self.tmp}/spiderfoot.json', 'w') as f:
            json.dump([], f)
        spiderfoot_scan(
            config={'spiderfoot_preset': 'passive; rm -rf /'},
            host=self.domain.name, scan_history_id=self.scan.id,
            activity_id=None, results_dir=self.tmp, ctx=self.ctx)
        cmd = mock_run.call_args.args[0]
        self.assertIn('-u passive ', cmd)
        self.assertNotIn('rm -rf', cmd)


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
        # Fail closed: the exposed field set must be EXACTLY this allowlist. If a
        # raw-secret column is ever added to the model and leaks through the
        # serializer, this assertion breaks (unlike `assertNotIn('secret', data)`,
        # which could never fail).
        self.assertEqual(set(data.keys()), {
            'id', 'scan_history', 'target_domain', 'source', 'rule_id',
            'repo_url', 'file_path', 'commit', 'line', 'secret_redacted',
            'description', 'severity', 'discovered_date',
        })
        self.assertEqual(data['source'], 'gitleaks')
        self.assertEqual(data['secret_redacted'], 'AKI********ET')

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


class TestSecretScanEntryPoint(TestCase):
    """The secret_scan Celery task (bind=True, SuricatoosTask base): config gating,
    SCAN_PATH override and the nonexistent-path skip. Driven through the task's
    __call__ via ctx (track=False bypasses scan-activity/DB side effects); the
    gitleaks/ggshield workers are mocked."""

    def setUp(self):
        self.domain = Domain.objects.create(name='example.com')
        self.engine = EngineType.objects.create(
            engine_name='t', yaml_configuration='secret_scan: {}')
        self.scan = ScanHistory.objects.create(
            domain=self.domain, scan_type=self.engine,
            start_scan_date=timezone.now())
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _ctx(self, secret_cfg, results_dir=None):
        return {
            'track': False,  # skip scan-activity / notification side effects
            'yaml_configuration': {'secret_scan': secret_cfg},
            'results_dir': results_dir or self.tmp,
            'scan_history_id': self.scan.id,
        }

    @patch('Suricatoos.tasks.run_ggshield_scan')
    @patch('Suricatoos.tasks.run_gitleaks_scan')
    def test_runs_gitleaks_by_default_not_ggshield(self, mock_gl, mock_gg):
        secret_scan(ctx=self._ctx({}))
        mock_gl.assert_called_once()
        mock_gg.assert_not_called()

    @patch('Suricatoos.tasks.run_ggshield_scan')
    @patch('Suricatoos.tasks.run_gitleaks_scan')
    def test_skips_when_path_missing(self, mock_gl, mock_gg):
        secret_scan(ctx=self._ctx(
            {'scan_path': '/no/such/path/xyz'}, results_dir='/no/such/path/xyz'))
        mock_gl.assert_not_called()
        mock_gg.assert_not_called()

    @patch('Suricatoos.tasks.run_ggshield_scan')
    @patch('Suricatoos.tasks.run_gitleaks_scan')
    def test_scan_path_override_and_ggshield_opt_in(self, mock_gl, mock_gg):
        override = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, override, ignore_errors=True)
        secret_scan(ctx=self._ctx(
            {'scan_path': override, 'run_ggshield': True}))
        mock_gl.assert_called_once()
        mock_gg.assert_called_once()
        # both scanners get the overridden path, not the results_dir
        self.assertEqual(mock_gl.call_args.args[1], override)
        self.assertEqual(mock_gg.call_args.args[1], override)

    @patch('Suricatoos.tasks.run_ggshield_scan')
    @patch('Suricatoos.tasks.run_gitleaks_scan')
    def test_run_gitleaks_false_disables_gitleaks(self, mock_gl, mock_gg):
        secret_scan(ctx=self._ctx({'run_gitleaks': False}))
        mock_gl.assert_not_called()
        mock_gg.assert_not_called()


if __name__ == '__main__':
    unittest.main()

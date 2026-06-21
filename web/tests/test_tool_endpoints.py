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

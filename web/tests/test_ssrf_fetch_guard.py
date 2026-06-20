"""OWASP A10 (SSRF) + A04-2 — guard the operator-facing fetch tools.

  * is_blocked_fetch_target — the SSRF classifier reused by the WAF/CMS detectors.
  * WafDetector / CMSDetector — must reject internal/metadata URLs before running
    wafw00f/CMSeeK (which would fetch the attacker-chosen host).
  * CVEDetails — must reject a malformed CVE id before building the circl.lu URL.
"""
from unittest.mock import patch

from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from Suricatoos import tasks


def _addrinfo(ip, port=0):
    return [(2, 1, 6, '', (ip, port))]


class IsBlockedFetchTargetTests(TestCase):
    def test_cloud_metadata_blocked(self):
        # 169.254.169.254 is link-local -> always blocked (IP literal, no DNS needed)
        blocked, _ = tasks.is_blocked_fetch_target('http://169.254.169.254/latest/meta-data/')
        self.assertTrue(blocked)

    def test_loopback_blocked(self):
        blocked, _ = tasks.is_blocked_fetch_target('http://127.0.0.1:8000/admin')
        self.assertTrue(blocked)

    def test_private_blocked_by_default(self):
        blocked, _ = tasks.is_blocked_fetch_target('http://10.0.0.5/')
        self.assertTrue(blocked)

    def test_private_allowed_when_opted_in(self):
        blocked, _ = tasks.is_blocked_fetch_target('http://10.0.0.5/', allow_private=True)
        self.assertFalse(blocked)

    def test_public_host_allowed(self):
        with patch('Suricatoos.tasks.socket.getaddrinfo', return_value=_addrinfo('93.184.216.34')):
            blocked, _ = tasks.is_blocked_fetch_target('http://example.com/')
        self.assertFalse(blocked)

    def test_bare_domain_resolving_internal_is_blocked(self):
        # DNS-rebinding-style: a bare domain that resolves to loopback must be blocked
        with patch('Suricatoos.tasks.socket.getaddrinfo', return_value=_addrinfo('127.0.0.1')):
            blocked, _ = tasks.is_blocked_fetch_target('internal.example')
        self.assertTrue(blocked)

    def test_empty_target_blocked(self):
        blocked, _ = tasks.is_blocked_fetch_target('')
        self.assertTrue(blocked)


class DetectorSsrfTests(TestCase):
    """The tool command must NEVER run for an internal/metadata target."""

    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username='ssrf_tester', password='x-irrelevant')
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    @patch('api.views.run_command')
    def test_waf_detector_blocks_metadata(self, mock_run):
        resp = self.client.get('/api/tools/waf_detector/', {'url': 'http://169.254.169.254/latest/meta-data/'})
        self.assertFalse(resp.data.get('status'))
        mock_run.assert_not_called()

    @patch('api.views.run_command')
    def test_cms_detector_blocks_loopback(self, mock_run):
        resp = self.client.get('/api/tools/cms_detector/', {'url': 'http://127.0.0.1:8000/'})
        self.assertFalse(resp.data.get('status'))
        mock_run.assert_not_called()

    @patch('api.views.run_command', return_value=(0, ''))
    def test_waf_detector_allows_public(self, mock_run):
        # a public host must still reach the tool (read path preserved)
        with patch('Suricatoos.tasks.socket.getaddrinfo', return_value=_addrinfo('93.184.216.34')):
            self.client.get('/api/tools/waf_detector/', {'url': 'http://example.com/'})
        mock_run.assert_called()


class CveDetailsValidationTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username='cve_tester', password='x-irrelevant')
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    @patch('api.views.requests.get')
    def test_malformed_cve_id_rejected_without_fetch(self, mock_get):
        resp = self.client.get('/api/tools/cve_details/', {'cve_id': '../../etc/passwd'})
        self.assertFalse(resp.data.get('status'))
        mock_get.assert_not_called()

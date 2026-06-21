"""OWASP A04-3 / A07-3 — login brute-force throttle.

Verifies: block after N failures (even with correct creds), success resets the counter,
no single-admin DoS (per ip+username, not username-only), disabled flag is a no-op, and
real-IP resolution behind the proxy.
"""
from django.test import TestCase, override_settings, RequestFactory
from django.contrib.auth import get_user_model
from django.core.cache import caches

from Suricatoos import login_throttle


PASSWORD = 'CorrectHorse9-Battery'


@override_settings(
    SURICATOOS_LOGIN_THROTTLE_ENABLED=True,
    SURICATOOS_LOGIN_FAIL_LIMIT=3,
    SURICATOOS_LOGIN_IP_FAIL_LIMIT=20,
    SURICATOOS_LOGIN_COOLDOWN=900,
)
class LoginThrottleTests(TestCase):
    def setUp(self):
        caches['login_throttle'].clear()
        self.addCleanup(caches['login_throttle'].clear)
        User = get_user_model()
        self.user = User.objects.create_user('admin', password=PASSWORD)

    def _login(self, username, password, ip=None):
        extra = {'HTTP_X_REAL_IP': ip} if ip else {}
        return self.client.post('/login/', {'username': username, 'password': password}, **extra)

    def test_blocks_after_fail_limit_even_with_correct_password(self):
        for _ in range(3):  # FAIL_LIMIT
            self.assertEqual(self._login('admin', 'wrong').status_code, 200)  # re-render, not blocked yet
        # next attempt is blocked even with the CORRECT password
        resp = self._login('admin', PASSWORD)
        self.assertEqual(resp.status_code, 429)
        self.assertFalse('_auth_user_id' in self.client.session)

    def test_success_before_limit_clears_counter(self):
        self._login('admin', 'wrong')
        self._login('admin', 'wrong')
        resp = self._login('admin', PASSWORD)   # succeeds -> clears
        self.assertEqual(resp.status_code, 302)
        self.assertIn('_auth_user_id', self.client.session)
        # counter cleared: a fresh round of failures is allowed again (not immediately blocked)
        self.client.logout()
        self.assertEqual(self._login('admin', 'wrong').status_code, 200)

    @override_settings(SURICATOOS_LOGIN_TRUST_PROXY_IP=True)
    def test_no_single_admin_dos_across_ips(self):
        # attacker hammers the admin username from IP A
        for _ in range(3):
            self._login('admin', 'wrong', ip='10.0.0.1')
        self.assertEqual(self._login('admin', PASSWORD, ip='10.0.0.1').status_code, 429)  # A blocked
        # legit admin logs in from a DIFFERENT IP — must NOT be blocked
        resp = self._login('admin', PASSWORD, ip='203.0.113.9')
        self.assertEqual(resp.status_code, 302)
        self.assertIn('_auth_user_id', self.client.session)

    @override_settings(SURICATOOS_LOGIN_THROTTLE_ENABLED=False)
    def test_disabled_flag_is_noop(self):
        for _ in range(8):
            self.assertEqual(self._login('admin', 'wrong').status_code, 200)  # never 429

    def test_admin_login_is_gated_by_login_required_redirect(self):
        # The admin login is NOT a separate brute-force surface: LoginRequiredMiddleware
        # redirects an unauthenticated /admin/login/ POST to the throttled /login/ (the POST
        # body is discarded), so it can't be hammered AND including it in the throttle would
        # be a counter-reset bypass. Document that behaviour here.
        resp = self.client.post('/admin/login/', {'username': 'admin', 'password': 'wrong'})
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/login/', resp['Location'])

    def test_username_whitespace_variants_share_one_budget(self):
        # ' admin'/'admin ' authenticate as 'admin' (Django strips) -> must NOT each get a
        # fresh budget. With normalization they share the (ip, admin) counter.
        self._login(' admin', 'wrong')
        self._login('admin ', 'wrong')
        self._login('admin', 'wrong')   # 3rd failed attempt for the same normalized account
        resp = self._login('admin', PASSWORD)  # blocked despite correct password
        self.assertEqual(resp.status_code, 429)


class ResolveClientIpTests(TestCase):
    def setUp(self):
        self.rf = RequestFactory()

    @override_settings(SURICATOOS_LOGIN_TRUST_PROXY_IP=True)
    def test_uses_x_real_ip_behind_proxy(self):
        req = self.rf.post('/login/', HTTP_X_REAL_IP='198.51.100.7', REMOTE_ADDR='172.18.0.5')
        self.assertEqual(login_throttle.resolve_client_ip(req), '198.51.100.7')

    @override_settings(SURICATOOS_LOGIN_TRUST_PROXY_IP=False)
    def test_uses_remote_addr_when_not_behind_proxy(self):
        # X-Real-IP must be IGNORED when not behind the proxy (it'd be client-forgeable)
        req = self.rf.post('/login/', HTTP_X_REAL_IP='1.1.1.1', REMOTE_ADDR='172.18.0.5')
        self.assertEqual(login_throttle.resolve_client_ip(req), '172.18.0.5')

    @override_settings(SURICATOOS_LOGIN_TRUST_PROXY_IP=True)
    def test_garbage_ip_falls_back(self):
        req = self.rf.post('/login/', HTTP_X_REAL_IP='not-an-ip', REMOTE_ADDR='also-bad')
        self.assertEqual(login_throttle.resolve_client_ip(req), 'unknown')

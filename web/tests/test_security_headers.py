"""OWASP A05/A02/A07 — security headers & cookie flags are configured.

These assert the deployment-hardening settings exist and take effect, and act
as the regression guard for the env-flagged security block in settings.py.
"""
from django.test import TestCase
from django.conf import settings


class SecuritySettingsTests(TestCase):
    def test_cookie_flags_present(self):
        self.assertTrue(settings.SESSION_COOKIE_HTTPONLY)
        self.assertEqual(settings.SESSION_COOKIE_SAMESITE, 'Lax')
        self.assertEqual(settings.CSRF_COOKIE_SAMESITE, 'Lax')

    def test_secure_cookies_enabled(self):
        # The actual deploy gap (check --deploy W012/W016): cookies must be
        # Secure in the non-debug deployment. Env-flagged via SURICATOOS_SECURE_COOKIES
        # (defaults to `not DEBUG`); the CI test step sets it explicitly.
        self.assertTrue(settings.SESSION_COOKIE_SECURE)
        self.assertTrue(settings.CSRF_COOKIE_SECURE)

    def test_secure_header_settings(self):
        self.assertTrue(settings.SECURE_CONTENT_TYPE_NOSNIFF)
        self.assertEqual(settings.SECURE_REFERRER_POLICY, 'same-origin')

    def test_nosniff_header_on_response(self):
        # SecurityMiddleware adds X-Content-Type-Options when the setting is on.
        resp = self.client.get('/login/')
        self.assertEqual(resp.headers.get('X-Content-Type-Options'), 'nosniff')

    def test_referrer_policy_header_on_response(self):
        resp = self.client.get('/login/')
        self.assertEqual(resp.headers.get('Referrer-Policy'), 'same-origin')

    def test_protected_page_requires_auth(self):
        # an unauthenticated request to a protected legacy page must not 200
        resp = self.client.get('/scanEngine/default/', follow=False)
        self.assertIn(resp.status_code, (301, 302))  # redirected to /login

    def test_session_age_is_bounded(self):
        # OWASP A07-4: the 14-day default session is too long for an admin tool
        # that stores 3rd-party API keys. Cap it (default 8h).
        self.assertLessEqual(settings.SESSION_COOKIE_AGE, 28800)

    def test_csp_header_present_with_safe_directives(self):
        # OWASP A05-1: a baseline CSP must ship on responses. The safe subset does
        # not require touching inline scripts but adds real defense-in-depth.
        resp = self.client.get('/login/')
        csp = resp.headers.get('Content-Security-Policy', '')
        self.assertIn("object-src 'none'", csp)
        self.assertIn("base-uri 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)

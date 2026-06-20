"""OWASP A01 — Broken Access Control regression tests.

Covers the audit findings:
  * A01-1 / A01-2 — result-listing DRF viewsets must be read-only. The DRF
    router must NOT expose POST/PUT/PATCH/DELETE on them (the legacy UI only
    issues read-only DataTables GETs). An authenticated request with an unsafe
    verb must get 405 Method Not Allowed, not perform a write.
  * A01-3 — change_vuln_status (a state-changing view) must enforce RBAC
    (PERM_MODIFY_SCAN_RESULTS), not authentication alone.
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient


READ_ONLY_LIST_ROUTES = [
    '/api/listTargets/',
    '/api/listSubdomains/',
    '/api/listEndpoints/',
    '/api/listDirectories/',
    '/api/listVulnerability/',
    '/api/listIps/',
    '/api/listDatatableSubdomain/',
]


class ReadOnlyResultViewSetsTests(TestCase):
    """A01-1 / A01-2: write verbs are not routed on result viewsets."""

    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username='ro_tester', password='x-irrelevant')
        # force_authenticate bypasses SessionAuthentication's CSRF enforcement so
        # the unsafe verb actually reaches DRF's method dispatch (and 405s) rather
        # than being short-circuited by a missing CSRF token (which would 403 and
        # mask whether the verb is routed at all).
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_post_to_list_is_method_not_allowed(self):
        for route in READ_ONLY_LIST_ROUTES:
            resp = self.client.post(route, {}, format='json')
            self.assertEqual(resp.status_code, 405, f'POST {route} should be 405 (read-only), got {resp.status_code}')

    def test_delete_on_detail_is_method_not_allowed(self):
        for route in READ_ONLY_LIST_ROUTES:
            resp = self.client.delete(route + '1/')
            self.assertEqual(resp.status_code, 405, f'DELETE {route}1/ should be 405 (read-only), got {resp.status_code}')

    def test_get_still_allowed(self):
        # the read path the UI depends on must keep working (200, not 405)
        resp = self.client.get('/api/listTargets/')
        self.assertEqual(resp.status_code, 200)


class ChangeVulnStatusRbacTests(TestCase):
    """A01-3: change_vuln_status must require PERM_MODIFY_SCAN_RESULTS."""

    def test_user_without_permission_is_redirected(self):
        User = get_user_model()
        user = User.objects.create_user(username='norole', password='x-irrelevant')
        self.client.force_login(user)
        # A user with no assigned role lacks PERM_MODIFY_SCAN_RESULTS; the
        # has_permission_decorator must redirect (302) to the 404 page BEFORE the
        # view body runs. Without the decorator the body runs and 500s on a missing
        # vuln id (so a 302 here specifically proves the control is in place).
        resp = self.client.post('/scan/toggle/vuln_status/999999', follow=False)
        self.assertEqual(resp.status_code, 302, 'expected RBAC redirect, got %s' % resp.status_code)

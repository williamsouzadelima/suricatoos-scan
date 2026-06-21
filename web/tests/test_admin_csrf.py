"""OWASP A07-1 — the admin "enable/disable account" action (change_status) must be a
CSRF-protected POST, not a state-changing GET. Django's CsrfViewMiddleware only guards
unsafe methods, so a GET mutation is exploitable via a cross-site <img>/link. After the
fix the mutation happens only on POST (CSRF-checked); a GET must not change is_active.
"""
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from rolepermissions.roles import assign_role


class ChangeStatusCsrfTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.admin = User.objects.create_user('admin_cs', password='Str0ng-Pass-77')
        assign_role(self.admin, 'sys_admin')  # holds PERM_MODIFY_SYSTEM_CONFIGURATIONS
        self.target = User.objects.create_user('target_cs', password='Str0ng-Pass-88')
        self.client.force_login(self.admin)

    def _url(self):
        return '/p/admin_interface/update?mode=change_status&user=%d' % self.target.id

    def test_get_does_not_change_status(self):
        # A GET (not CSRF-protected) must NOT flip the account's active state.
        before = self.target.is_active
        self.client.get(self._url())
        self.target.refresh_from_db()
        self.assertEqual(self.target.is_active, before, 'GET must not mutate is_active (CSRF)')

    def test_post_changes_status(self):
        # The legitimate path (POST, CSRF-protected) must still toggle the state.
        before = self.target.is_active
        self.client.post(self._url())
        self.target.refresh_from_db()
        self.assertEqual(self.target.is_active, not before, 'POST must toggle is_active')

    def test_post_without_csrf_token_is_rejected(self):
        # The security property A07-1 locks in: with CSRF enforcement on, a token-less
        # POST (i.e. a cross-site request) is rejected (403) and must not mutate state.
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.admin)
        before = self.target.is_active
        resp = csrf_client.post(self._url())
        self.assertEqual(resp.status_code, 403)
        self.target.refresh_from_db()
        self.assertEqual(self.target.is_active, before, 'token-less POST must not mutate is_active')

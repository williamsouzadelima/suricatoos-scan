"""OWASP A07-2 — AUTH_PASSWORD_VALIDATORS must be enforced on the admin/onboarding
user-creation paths (create_user/set_password do NOT run the validator chain on their
own; only Django's auth *forms* do). A weak password on these paths must be rejected.
"""
import json

from django.test import TestCase
from django.contrib.auth import get_user_model
from rolepermissions.roles import assign_role


class AdminPasswordPolicyTests(TestCase):
    def setUp(self):
        User = get_user_model()
        # an admin who holds PERM_MODIFY_SYSTEM_CONFIGURATIONS (SysAdmin role)
        self.admin = User.objects.create_user('admin_t', password='Str0ng-Passphrase-42')
        assign_role(self.admin, 'sys_admin')
        self.client.force_login(self.admin)
        self.url = '/p/admin_interface/update?mode=create'  # slug='p'; create ignores the slug

    def _create(self, username, password):
        return self.client.post(
            self.url,
            data=json.dumps({'username': username, 'password': password, 'role': 'sys_admin'}),
            content_type='application/json',
        )

    def test_weak_password_rejected_and_user_not_created(self):
        User = get_user_model()
        before = User.objects.count()
        resp = self._create('weakling', '123')
        self.assertFalse(resp.json()['status'])
        self.assertEqual(User.objects.count(), before)
        self.assertFalse(User.objects.filter(username='weakling').exists())

    def test_strong_password_still_creates_user(self):
        resp = self._create('stronguser', 'Str0ng-Passphrase-99')
        self.assertTrue(resp.json()['status'])
        self.assertTrue(get_user_model().objects.filter(username='stronguser').exists())

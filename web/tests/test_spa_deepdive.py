from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient
from django.contrib.auth.models import User
from targetApp.models import Domain
from dashboard.models import Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory, EndPoint


class DeepDiveBaseTest(TestCase):
	def setUp(self):
		self.user = User.objects.create_user('t', password='p')
		self.client = APIClient()
		self.client.force_authenticate(self.user)
		self.project = Project.objects.create(name='P', slug='p', insert_date=timezone.now())
		self.domain = Domain.objects.create(name='ex.com', project=self.project)
		self.engine = EngineType.objects.create(engine_name='test-engine')
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_status=2, start_scan_date=timezone.now(), scan_type=self.engine)
		self.other = ScanHistory.objects.create(domain=self.domain, scan_status=2, start_scan_date=timezone.now(), scan_type=self.engine)


class EndpointApiTest(DeepDiveBaseTest):
	def setUp(self):
		super().setUp()
		EndPoint.objects.create(scan_history=self.scan, http_url='http://ex.com/a', http_status=200)
		EndPoint.objects.create(scan_history=self.other, http_url='http://ex.com/b', http_status=200)

	def test_lists_only_scan_endpoints(self):
		r = self.client.get('/api/endpoints/', {'scan_history': self.scan.id})
		self.assertEqual(r.status_code, 200)
		urls = [e['http_url'] for e in r.json()]
		self.assertEqual(urls, ['http://ex.com/a'])

	def test_unscoped_list_is_empty(self):
		r = self.client.get('/api/endpoints/')
		self.assertEqual(r.json(), [])

	def test_requires_auth(self):
		anon = APIClient()
		self.assertEqual(anon.get('/api/endpoints/', {'scan_history': self.scan.id}).status_code, 401)

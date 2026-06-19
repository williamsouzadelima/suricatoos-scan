from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient
from django.contrib.auth.models import User
from targetApp.models import Domain
from dashboard.models import Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory, EndPoint, IpAddress, Port, Subdomain


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


class IpApiTest(DeepDiveBaseTest):
	def setUp(self):
		super().setUp()
		sub = Subdomain.objects.create(scan_history=self.scan, name='a.ex.com')
		ip = IpAddress.objects.create(address='1.2.3.4', is_cdn=False)
		port = Port.objects.create(number=443, service_name='https')
		ip.ports.add(port)
		sub.ip_addresses.add(ip)

	def test_lists_scan_ips_with_ports(self):
		r = self.client.get('/api/ips/', {'scan_history': self.scan.id})
		self.assertEqual(r.status_code, 200)
		data = r.json()
		self.assertEqual(len(data), 1)
		self.assertEqual(data[0]['address'], '1.2.3.4')
		self.assertEqual(data[0]['ports'][0]['number'], 443)

	def test_unscoped_empty(self):
		self.assertEqual(self.client.get('/api/ips/').json(), [])


from startScan.models import Technology


class TechApiTest(DeepDiveBaseTest):
	def setUp(self):
		super().setUp()
		sub = Subdomain.objects.create(scan_history=self.scan, name='a.ex.com')
		tech = Technology.objects.create(name='nginx')
		sub.technologies.add(tech)

	def test_lists_scan_tech(self):
		r = self.client.get('/api/technologies/', {'scan_history': self.scan.id})
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.json()[0]['name'], 'nginx')
		self.assertEqual(r.json()[0]['subdomain_count'], 1)

	def test_unscoped_empty(self):
		self.assertEqual(self.client.get('/api/technologies/').json(), [])


from startScan.models import DirectoryScan, DirectoryFile


class DirectoryApiTest(DeepDiveBaseTest):
	def setUp(self):
		super().setUp()
		sub = Subdomain.objects.create(scan_history=self.scan, name='a.ex.com')
		ds = DirectoryScan.objects.create()
		df = DirectoryFile.objects.create(name='admin', http_status=200, length=12, words=2, lines=1)
		ds.directory_files.add(df)
		sub.directories.add(ds)

	def test_lists_scan_directories(self):
		r = self.client.get('/api/scan-directories/', {'scan_history': self.scan.id})
		self.assertEqual(r.status_code, 200)
		row = r.json()[0]
		self.assertEqual(row['name'], 'admin')
		self.assertEqual(row['subdomain_name'], 'a.ex.com')
		self.assertEqual(row['http_status'], 200)

	def test_unscoped_empty(self):
		self.assertEqual(self.client.get('/api/scan-directories/').json(), [])

	def test_requires_auth(self):
		self.assertEqual(APIClient().get('/api/scan-directories/', {'scan_history': self.scan.id}).status_code, 401)


import os, tempfile
from django.conf import settings


class ScreenshotApiTest(DeepDiveBaseTest):
	def setUp(self):
		super().setUp()
		self.shot_dir = os.path.join(settings.MEDIA_ROOT, 'sx_test_shots')
		os.makedirs(self.shot_dir, exist_ok=True)
		self.shot = os.path.join(self.shot_dir, 's.png')
		with open(self.shot, 'wb') as f:
			f.write(b'\x89PNG\r\n')
		self.sub = Subdomain.objects.create(
			scan_history=self.scan, name='a.ex.com', screenshot_path=self.shot)

	def tearDown(self):
		try:
			os.remove(self.shot); os.rmdir(self.shot_dir)
		except OSError:
			pass

	def test_list_returns_image_url(self):
		r = self.client.get('/api/screenshots/', {'scan_history': self.scan.id})
		self.assertEqual(r.status_code, 200)
		row = r.json()[0]
		self.assertEqual(row['subdomain_id'], self.sub.id)
		self.assertEqual(row['image_url'], f'/api/scan-screenshot/{self.sub.id}/')

	def test_image_served_with_auth(self):
		r = self.client.get(f'/api/scan-screenshot/{self.sub.id}/')
		self.assertEqual(r.status_code, 200)
		self.assertTrue(r['Content-Type'].startswith('image'))

	def test_image_requires_auth(self):
		self.assertEqual(APIClient().get(f'/api/scan-screenshot/{self.sub.id}/').status_code, 401)

	def test_image_traversal_blocked(self):
		# screenshot_path pointing outside MEDIA_ROOT is refused even if it exists
		self.sub.screenshot_path = '/etc/hostname'
		self.sub.save()
		self.assertEqual(self.client.get(f'/api/scan-screenshot/{self.sub.id}/').status_code, 404)

	def test_missing_screenshot_404(self):
		bare = Subdomain.objects.create(scan_history=self.scan, name='b.ex.com')
		self.assertEqual(self.client.get(f'/api/scan-screenshot/{bare.id}/').status_code, 404)

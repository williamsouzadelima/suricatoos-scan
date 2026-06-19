# ScanDetail deep-dive Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add tabs to the SPA ScanDetail page that surface a scan's endpoints, IPs/ports, screenshots, directories, and technologies.

**Architecture:** Five new scan-scoped REST endpoints under `/api/` follow the existing Spa* pattern (plain-array JSON, `?scan_history=`, `pagination_class=None`, list-scope guard) plus one JWT-authenticated screenshot image endpoint. The frontend refactors `ScanDetail.tsx` into a URL-synced tab layout, lazily loading each tab; a shared `<DataTable>` powers the four tabular tabs and an `<AuthImage>` renders bearer-authenticated screenshots.

**Tech Stack:** Django REST Framework (Python 3.10), React 18 + Vite 5 + TypeScript, TanStack Query + TanStack Table, Tailwind.

## Global Constraints

- Backend files use **TAB** indentation (existing `web/api/` convention) — match exactly.
- New `/api/` routes are plain nouns (`endpoints`, `ips`, `screenshots`, `technologies`) registered in `web/api/urls.py`; they must not collide with legacy `listEndpoints`/`listIps`/`listDirectories`.
- Every list viewset: `pagination_class = None`, `serializer_class`, and a guard `if self.action == 'list' and not <scope>: return qs.none()` (single-tenant — guard bounds payload, not authz). `retrieve` stays usable.
- The screenshot image endpoint resolves the file path **only from the DB** (`Subdomain.screenshot_path`) and enforces `os.path.commonpath` containment under `MEDIA_ROOT` — no request value reaches the filesystem call (same barrier as `serve_branding_asset`).
- Frontend: SPA source lives in `web/frontend/src`. The build artifact is produced by the Docker image (do **not** commit `web/static/spa`). Frontend "test" gate = `cd web/frontend && npm run build` (tsc + vite) clean, then live check.
- Backend tests run against a throwaway postgres using the project harness pattern (see Task 1, Step "run tests").
- Commit after each task. Branch: `feat/scandetail-deepdive`.

---

## File Structure

**Backend**
- Modify `web/api/serializers.py` — add `EndpointSpaSerializer`, `PortSpaSerializer`, `IpSpaSerializer`, `ScreenshotSpaSerializer`, `TechSpaSerializer`.
- Modify `web/api/views.py` — add `SpaEndpointViewSet`, `SpaIpViewSet`, `SpaScreenshotViewSet`, `SpaTechViewSet`, `ScanDirectories` (APIView), `ScanScreenshotImage` (APIView).
- Modify `web/api/urls.py` — register 4 router routes + 2 `path()` entries.
- Create `web/tests/test_spa_deepdive.py` — backend tests.

**Frontend**
- Create `web/frontend/src/components/DataTable.tsx` — shared TanStack table.
- Create `web/frontend/src/components/AuthImage.tsx` — bearer-authenticated image.
- Modify `web/frontend/src/pages/Subdomains.tsx` and `web/frontend/src/pages/Vulnerabilities.tsx` — use `<DataTable>`.
- Create `web/frontend/src/pages/scandetail/` — `OverviewTab.tsx`, `EndpointsTab.tsx`, `IpsTab.tsx`, `ScreenshotsTab.tsx`, `DirectoriesTab.tsx`, `TechTab.tsx`.
- Modify `web/frontend/src/pages/ScanDetail.tsx` — tab shell.

---

## Task 1: Endpoints API (serializer + viewset + route + tests)

**Files:**
- Modify: `web/api/serializers.py`
- Modify: `web/api/views.py`
- Modify: `web/api/urls.py`
- Test: `web/tests/test_spa_deepdive.py`

**Interfaces:**
- Produces: `GET /api/endpoints/?scan_history=<id>` → `[{id, http_url, http_status, page_title, content_length, content_type, webserver, response_time, is_important}]`

- [ ] **Step 1: Write the failing test** (create `web/tests/test_spa_deepdive.py`)

```python
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from django.contrib.auth.models import User
from targetApp.models import Domain
from dashboard.models import Project
from startScan.models import ScanHistory, EndPoint


class DeepDiveBaseTest(TestCase):
	def setUp(self):
		self.user = User.objects.create_user('t', password='p')
		self.client = APIClient()
		self.client.force_authenticate(self.user)
		self.project = Project.objects.create(name='P', slug='p')
		self.domain = Domain.objects.create(name='ex.com', project=self.project)
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_status=2)
		self.other = ScanHistory.objects.create(domain=self.domain, scan_status=2)


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
```

- [ ] **Step 2: Run the test, verify it fails**

Run:
```bash
cd /root && bash -c '
NET=suri_t; DB=suri_tdb; PW=p
docker rm -f $DB >/dev/null 2>&1; docker network create $NET >/dev/null 2>&1 || true
docker run -d --name $DB --network $NET -e POSTGRES_DB=suricatoos -e POSTGRES_USER=suricatoos -e POSTGRES_PASSWORD=$PW postgres:12.3-alpine >/dev/null
for i in $(seq 1 40); do docker exec $DB pg_isready -U suricatoos >/dev/null 2>&1 && break; sleep 1; done
docker run --rm --network $NET -e POSTGRES_DB=suricatoos -e POSTGRES_USER=suricatoos -e POSTGRES_PASSWORD=$PW -e POSTGRES_HOST=$DB -e POSTGRES_PORT=5432 -e DEBUG=1 -e CELERY_BROKER=redis://x -e CELERY_BACKEND=redis://x -e DOMAIN_NAME=localhost -v /root/suricatoos/web:/usr/src/app -w /usr/src/app --entrypoint python3 suricatoos/web:latest manage.py test tests.test_spa_deepdive.EndpointApiTest -v2
docker rm -f $DB >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1'
```
Expected: FAIL — 404 (route not registered).

- [ ] **Step 3: Add the serializer** (`web/api/serializers.py`, end of file, TABS)

```python
class EndpointSpaSerializer(serializers.ModelSerializer):
	"""Lean endpoint shape for the SPA scan deep-dive."""
	class Meta:
		model = EndPoint
		fields = [
			'id', 'http_url', 'http_status', 'page_title', 'content_length',
			'content_type', 'webserver', 'response_time', 'is_important',
		]
```

- [ ] **Step 4: Add the viewset** (`web/api/views.py`, near the other Spa viewsets, TABS)

```python
class SpaEndpointViewSet(viewsets.ReadOnlyModelViewSet):
	"""Scan-scoped endpoint list for the SPA deep-dive (?scan_history=)."""
	queryset = EndPoint.objects.none()
	serializer_class = EndpointSpaSerializer
	pagination_class = None

	def get_queryset(self):
		scan_id = self.request.query_params.get('scan_history')
		if self.action == 'list' and not scan_id:
			return EndPoint.objects.none()
		qs = EndPoint.objects.all()
		if scan_id:
			qs = qs.filter(scan_history_id=scan_id)
		return qs.order_by('-http_status', 'http_url').distinct()
```

Confirm `EndpointSpaSerializer` is importable: `web/api/views.py` already does `from .serializers import *` (verify; if it imports names explicitly, add `EndpointSpaSerializer`).

- [ ] **Step 5: Register the route** (`web/api/urls.py`, in the router block with the other Spa routes)

```python
router.register(r'endpoints', SpaEndpointViewSet, basename='spa_endpoints')
```

- [ ] **Step 6: Run the test, verify it passes**

Run the same command as Step 2. Expected: PASS (3 tests).

- [ ] **Step 7: Commit**

```bash
cd /root/suricatoos
git add web/api/serializers.py web/api/views.py web/api/urls.py web/tests/test_spa_deepdive.py
git commit -m "feat(api): scan-scoped endpoints endpoint for SPA deep-dive"
```

---

## Task 2: IPs & Ports API (nested serializer + viewset + route + tests)

**Files:**
- Modify: `web/api/serializers.py`, `web/api/views.py`, `web/api/urls.py`
- Test: `web/tests/test_spa_deepdive.py`

**Interfaces:**
- Produces: `GET /api/ips/?scan_history=<id>` → `[{address, is_cdn, ports:[{number, service_name, is_uncommon}]}]`

- [ ] **Step 1: Write the failing test** (append to `web/tests/test_spa_deepdive.py`)

```python
from startScan.models import Subdomain, IpAddress, Port


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
```

- [ ] **Step 2: Run it, verify FAIL** (Step 2 command from Task 1, replace test path with `tests.test_spa_deepdive.IpApiTest`). Expected: 404.

- [ ] **Step 3: Add serializers** (`web/api/serializers.py`, TABS)

```python
class PortSpaSerializer(serializers.ModelSerializer):
	class Meta:
		model = Port
		fields = ['number', 'service_name', 'is_uncommon']


class IpSpaSerializer(serializers.ModelSerializer):
	ports = PortSpaSerializer(many=True, read_only=True)
	class Meta:
		model = IpAddress
		fields = ['address', 'is_cdn', 'ports']
```

- [ ] **Step 4: Add the viewset** (`web/api/views.py`, TABS) — `Subdomain.ip_addresses` has `related_name='ip_addresses'`, so the reverse filter from `IpAddress` to its subdomains is `ip_addresses`.

```python
class SpaIpViewSet(viewsets.ReadOnlyModelViewSet):
	"""Scan-scoped IP+ports list for the SPA deep-dive (?scan_history=)."""
	queryset = IpAddress.objects.none()
	serializer_class = IpSpaSerializer
	pagination_class = None

	def get_queryset(self):
		scan_id = self.request.query_params.get('scan_history')
		if self.action == 'list' and not scan_id:
			return IpAddress.objects.none()
		qs = IpAddress.objects.prefetch_related('ports')
		if scan_id:
			qs = qs.filter(ip_addresses__scan_history_id=scan_id)
		return qs.order_by('address').distinct()
```

- [ ] **Step 5: Register route** (`web/api/urls.py`): `router.register(r'ips', SpaIpViewSet, basename='spa_ips')`

- [ ] **Step 6: Run it, verify PASS** (`tests.test_spa_deepdive.IpApiTest`).

- [ ] **Step 7: Commit**

```bash
git add web/api/serializers.py web/api/views.py web/api/urls.py web/tests/test_spa_deepdive.py
git commit -m "feat(api): scan-scoped ips+ports endpoint for SPA deep-dive"
```

---

## Task 3: Technologies API (serializer + viewset + route + tests)

**Files:** Modify `web/api/serializers.py`, `web/api/views.py`, `web/api/urls.py`; Test `web/tests/test_spa_deepdive.py`

**Interfaces:** Produces `GET /api/technologies/?scan_history=<id>` → `[{name, subdomain_count}]`

- [ ] **Step 1: Failing test** (append)

```python
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
```

- [ ] **Step 2: Run, verify FAIL** (`tests.test_spa_deepdive.TechApiTest`). Expected 404.

- [ ] **Step 3: Serializer** (`web/api/serializers.py`, TABS)

```python
class TechSpaSerializer(serializers.ModelSerializer):
	subdomain_count = serializers.IntegerField(read_only=True)
	class Meta:
		model = Technology
		fields = ['name', 'subdomain_count']
```

- [ ] **Step 4: Viewset** (`web/api/views.py`, TABS) — `Subdomain.technologies` has `related_name='technologies'`.

```python
class SpaTechViewSet(viewsets.ReadOnlyModelViewSet):
	"""Scan-scoped technologies for the SPA deep-dive (?scan_history=)."""
	queryset = Technology.objects.none()
	serializer_class = TechSpaSerializer
	pagination_class = None

	def get_queryset(self):
		scan_id = self.request.query_params.get('scan_history')
		if self.action == 'list' and not scan_id:
			return Technology.objects.none()
		qs = Technology.objects.all()
		if scan_id:
			qs = qs.filter(technologies__scan_history_id=scan_id)
		return qs.annotate(
			subdomain_count=Count('technologies', distinct=True)
		).order_by('-subdomain_count', 'name').distinct()
```

`Count` is already imported in `web/api/views.py` (used by `SpaScanViewSet`); verify.

- [ ] **Step 5: Route**: `router.register(r'technologies', SpaTechViewSet, basename='spa_technologies')`

- [ ] **Step 6: Run, verify PASS.**

- [ ] **Step 7: Commit**

```bash
git add web/api/serializers.py web/api/views.py web/api/urls.py web/tests/test_spa_deepdive.py
git commit -m "feat(api): scan-scoped technologies endpoint for SPA deep-dive"
```

---

## Task 4: Directories API (APIView + route + tests)

**Files:** Modify `web/api/views.py`, `web/api/urls.py`; Test `web/tests/test_spa_deepdive.py`

**Interfaces:** Produces `GET /api/scan-directories/?scan_history=<id>` → `[{subdomain_name, name, http_status, length, words, lines}]`

Rationale: the join `Subdomain.directories (DirectoryScan) → directory_files (DirectoryFile)` is awkward for a ModelViewSet, so an `APIView` builds the flat list.

- [ ] **Step 1: Failing test** (append)

```python
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
```

- [ ] **Step 2: Run, verify FAIL** (`tests.test_spa_deepdive.DirectoryApiTest`). Expected 404.

- [ ] **Step 3: APIView** (`web/api/views.py`, TABS)

```python
class ScanDirectories(APIView):
	"""Flat directory-fuzzing results for a scan (?scan_history=)."""

	def get(self, request):
		scan_id = request.query_params.get('scan_history')
		if not scan_id:
			return Response([])
		subs = Subdomain.objects.filter(scan_history_id=scan_id).prefetch_related(
			'directories__directory_files')
		rows = []
		for sub in subs:
			for ds in sub.directories.all():
				for f in ds.directory_files.all():
					rows.append({
						'subdomain_name': sub.name,
						'name': f.name,
						'http_status': f.http_status,
						'length': f.length,
						'words': f.words,
						'lines': f.lines,
					})
		return Response(rows)
```

- [ ] **Step 4: Route** (`web/api/urls.py`, in `urlpatterns`, import `ScanDirectories` via the existing `from .views import *`)

```python
path('scan-directories/', ScanDirectories.as_view(), name='scan_directories'),
```

- [ ] **Step 5: Run, verify PASS.**

- [ ] **Step 6: Commit**

```bash
git add web/api/views.py web/api/urls.py web/tests/test_spa_deepdive.py
git commit -m "feat(api): scan-scoped directories endpoint for SPA deep-dive"
```

---

## Task 5: Screenshots list + image endpoint (serializer + viewset + APIView + route + tests)

**Files:** Modify `web/api/serializers.py`, `web/api/views.py`, `web/api/urls.py`; Test `web/tests/test_spa_deepdive.py`

**Interfaces:**
- Produces `GET /api/screenshots/?scan_history=<id>` → `[{subdomain_id, subdomain_name, image_url}]` where `image_url == '/api/scan-screenshot/<subdomain_id>/'`
- Produces `GET /api/scan-screenshot/<subdomain_id>/` → image bytes (JWT-auth), 404 if no/invalid screenshot.

- [ ] **Step 1: Failing test** (append) — uses a real temp file under `MEDIA_ROOT` and a traversal attempt.

```python
import os, tempfile
from django.conf import settings
from unittest import mock


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
```

- [ ] **Step 2: Run, verify FAIL** (`tests.test_spa_deepdive.ScreenshotApiTest`). Expected 404 routes.

- [ ] **Step 3: Serializer** (`web/api/serializers.py`, TABS)

```python
class ScreenshotSpaSerializer(serializers.ModelSerializer):
	subdomain_id = serializers.IntegerField(source='id', read_only=True)
	subdomain_name = serializers.CharField(source='name', read_only=True)
	image_url = serializers.SerializerMethodField()
	class Meta:
		model = Subdomain
		fields = ['subdomain_id', 'subdomain_name', 'image_url']

	def get_image_url(self, obj):
		return f'/api/scan-screenshot/{obj.id}/'
```

- [ ] **Step 4: Viewset + image APIView** (`web/api/views.py`, TABS — needs `import os`, `mimetypes`, `from django.conf import settings`, `from django.http import FileResponse, Http404`; add any missing imports at the top of the file)

```python
class SpaScreenshotViewSet(viewsets.ReadOnlyModelViewSet):
	"""Scan-scoped subdomains that have a screenshot (?scan_history=)."""
	queryset = Subdomain.objects.none()
	serializer_class = ScreenshotSpaSerializer
	pagination_class = None

	def get_queryset(self):
		scan_id = self.request.query_params.get('scan_history')
		if self.action == 'list' and not scan_id:
			return Subdomain.objects.none()
		qs = Subdomain.objects.exclude(
			screenshot_path__isnull=True).exclude(screenshot_path='')
		if scan_id:
			qs = qs.filter(scan_history_id=scan_id)
		return qs.order_by('name').distinct()


class ScanScreenshotImage(APIView):
	"""Stream a subdomain's screenshot to JWT clients. Path comes from the DB
	(Subdomain.screenshot_path) and is containment-checked under MEDIA_ROOT, so no
	request value reaches the filesystem call (no traversal)."""

	def get(self, request, subdomain_id):
		import os, mimetypes
		from django.conf import settings
		from django.http import FileResponse, Http404
		try:
			sub = Subdomain.objects.get(id=subdomain_id)
		except Subdomain.DoesNotExist:
			raise Http404
		stored = sub.screenshot_path or ''
		if not stored:
			raise Http404
		media_root = os.path.realpath(settings.MEDIA_ROOT)
		# screenshot_path may be absolute or relative to MEDIA_ROOT.
		candidate = stored if os.path.isabs(stored) else os.path.join(media_root, stored)
		file_path = os.path.realpath(candidate)
		if os.path.commonpath([media_root, file_path]) != media_root:
			raise Http404
		if not os.path.isfile(file_path):
			raise Http404
		content_type, _ = mimetypes.guess_type(file_path)
		return FileResponse(open(file_path, 'rb'),
			content_type=content_type or 'application/octet-stream')
```

- [ ] **Step 5: Routes** (`web/api/urls.py`)

```python
router.register(r'screenshots', SpaScreenshotViewSet, basename='spa_screenshots')
# ...and in urlpatterns:
path('scan-screenshot/<int:subdomain_id>/', ScanScreenshotImage.as_view(), name='scan_screenshot_image'),
```

- [ ] **Step 6: Run, verify PASS** (5 tests).

- [ ] **Step 7: Commit**

```bash
git add web/api/serializers.py web/api/views.py web/api/urls.py web/tests/test_spa_deepdive.py
git commit -m "feat(api): scan screenshots list + JWT image endpoint (containment-checked)"
```

- [ ] **Step 8: Run the full deep-dive suite**

Run the Step 2 command with `tests.test_spa_deepdive` (no class). Expected: all classes PASS.

---

## Task 6: Shared `<DataTable>` + migrate Subdomains & Vulnerabilities

**Files:**
- Create: `web/frontend/src/components/DataTable.tsx`
- Modify: `web/frontend/src/pages/Subdomains.tsx`, `web/frontend/src/pages/Vulnerabilities.tsx`

**Interfaces:**
- Produces: `DataTable<T>(props: { data: T[]; columns: ColumnDef<T>[]; countLabel: string; initialSort?: SortingState; pageSize?: number })` — renders a searchable, sortable, paginated table (the markup currently in `Subdomains.tsx`).

- [ ] **Step 1: Create `web/frontend/src/components/DataTable.tsx`**

```tsx
import { useMemo, useState } from 'react'
import {
  useReactTable, getCoreRowModel, getSortedRowModel, getFilteredRowModel,
  getPaginationRowModel, flexRender, type ColumnDef, type SortingState,
} from '@tanstack/react-table'

export function DataTable<T>({ data, columns, countLabel, initialSort = [], pageSize = 25 }: {
  data: T[]; columns: ColumnDef<T>[]; countLabel: string
  initialSort?: SortingState; pageSize?: number
}) {
  const [sorting, setSorting] = useState<SortingState>(initialSort)
  const [globalFilter, setGlobalFilter] = useState('')
  const cols = useMemo(() => columns, [columns])
  const table = useReactTable({
    data, columns: cols, state: { sorting, globalFilter },
    onSortingChange: setSorting, onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(), getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(), getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize } },
  })
  return (
    <div>
      <div className="mb-3 flex justify-end">
        <input value={globalFilter} onChange={(e) => setGlobalFilter(e.target.value)} placeholder="Search…"
          className="w-64 rounded-lg border border-sx-border bg-sx-surface-2 px-3 py-1.5 text-sm outline-none focus:border-sx-primary" />
      </div>
      <div className="overflow-x-auto rounded-xl border border-sx-border">
        <table className="w-full text-sm">
          <thead className="bg-sx-surface-2 text-left text-sx-muted">
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id}>
                {hg.headers.map((h) => (
                  <th key={h.id} className="cursor-pointer select-none px-4 py-2" onClick={h.column.getToggleSortingHandler()}>
                    {flexRender(h.column.columnDef.header, h.getContext())}
                    {{ asc: ' ↑', desc: ' ↓' }[h.column.getIsSorted() as string] ?? ''}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map((row) => (
              <tr key={row.id} className="border-t border-sx-border">
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id} className="px-4 py-2 align-top break-all">{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-3 flex items-center justify-between text-sm text-sx-muted">
        <span>{table.getFilteredRowModel().rows.length} {countLabel}</span>
        <div className="flex items-center gap-2">
          <button className="rounded border border-sx-border px-2 py-1 disabled:opacity-50" onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()}>Prev</button>
          <span>Page {table.getState().pagination.pageIndex + 1} / {table.getPageCount() || 1}</span>
          <button className="rounded border border-sx-border px-2 py-1 disabled:opacity-50" onClick={() => table.nextPage()} disabled={!table.getCanNextPage()}>Next</button>
        </div>
      </div>
    </div>
  )
}
```

- [ ] **Step 2: Refactor `Subdomains.tsx`** — remove the table machinery (lines importing `useReactTable`/state and the markup), keep the `columns` def and query, render `<DataTable data={data ?? []} columns={columns} countLabel="subdomains" initialSort={[{ id: 'name', desc: false }]} />`. Keep the loading/error guards and the page `<h1>`.

- [ ] **Step 3: Refactor `Vulnerabilities.tsx`** the same way (`countLabel="vulnerabilities"`, its existing initial sort).

- [ ] **Step 4: Verify the build**

Run: `cd /root/suricatoos/web/frontend && npm run build`
Expected: clean (tsc + vite), no type errors.

- [ ] **Step 5: Commit**

```bash
cd /root/suricatoos
git add web/frontend/src/components/DataTable.tsx web/frontend/src/pages/Subdomains.tsx web/frontend/src/pages/Vulnerabilities.tsx
git commit -m "refactor(spa): extract shared DataTable; migrate Subdomains + Vulnerabilities"
```

---

## Task 7: `<AuthImage>` component

**Files:** Create `web/frontend/src/components/AuthImage.tsx`

**Interfaces:** Produces `AuthImage(props: { src: string; alt: string; className?: string })` — fetches `src` with the JWT bearer (via the shared `api` axios client) as a blob, renders it through an object URL, revoking on unmount; shows a placeholder while loading and on error.

- [ ] **Step 1: Create the component**

```tsx
import { useEffect, useState } from 'react'
import { api } from '../api/client'

export function AuthImage({ src, alt, className }: { src: string; alt: string; className?: string }) {
  const [url, setUrl] = useState<string | null>(null)
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    let objectUrl: string | null = null
    let active = true
    setFailed(false); setUrl(null)
    api.get(src, { responseType: 'blob' })
      .then((r) => {
        if (!active) return
        objectUrl = URL.createObjectURL(r.data as Blob)
        setUrl(objectUrl)
      })
      .catch(() => active && setFailed(true))
    return () => { active = false; if (objectUrl) URL.revokeObjectURL(objectUrl) }
  }, [src])
  if (failed) return <div className={'flex items-center justify-center bg-sx-surface-2 text-xs text-sx-muted ' + (className ?? '')}>no image</div>
  if (!url) return <div className={'animate-pulse bg-sx-surface-2 ' + (className ?? '')} />
  return <img src={url} alt={alt} className={className} loading="lazy" />
}
```

- [ ] **Step 2: Verify build** — `cd /root/suricatoos/web/frontend && npm run build`. Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add web/frontend/src/components/AuthImage.tsx
git commit -m "feat(spa): AuthImage — bearer-authenticated image via blob object URL"
```

---

## Task 8: ScanDetail tab shell + Overview extraction

**Files:**
- Create: `web/frontend/src/pages/scandetail/OverviewTab.tsx`
- Modify: `web/frontend/src/pages/ScanDetail.tsx`

**Interfaces:**
- Produces: `OverviewTab(props: { data: ScanDetail })` — the current progress/stats/timeline markup.
- Produces: `ScanDetail` page renders a tab bar; active tab in `?tab=` (default `overview`); exports the shared `ScanDetail` type via `web/frontend/src/pages/scandetail/types.ts`.

- [ ] **Step 1: Create `web/frontend/src/pages/scandetail/types.ts`**

```ts
export type Activity = { id: number; title: string; name: string; status: number; time: string | null; error_message: string | null }
export type ScanDetail = {
  id: number; domain_name: string; engine_name: string; scan_status: number
  start_scan_date: string | null; stop_scan_date: string | null
  subdomain_count: number; endpoint_count: number; vulnerability_count: number
  osint_count: number; progress: number; activities: Activity[]
}
export const STATUS: Record<number, { label: string; cls: string }> = {
  [-1]: { label: 'Initiated', cls: 'bg-sx-info/20 text-sx-info' },
  0: { label: 'Failed', cls: 'bg-sx-critical/20 text-sx-critical' },
  1: { label: 'Running', cls: 'bg-sx-medium/20 text-sx-medium' },
  2: { label: 'Success', cls: 'bg-sx-success/20 text-sx-success' },
  3: { label: 'Aborted', cls: 'bg-sx-surface-2 text-sx-muted' },
}
export function fmt(d: string | null) { return d ? new Date(d).toLocaleString() : '—' }
export function statusCls(s: number) {
  if (s >= 200 && s < 300) return 'bg-sx-success/20 text-sx-success'
  if (s >= 300 && s < 400) return 'bg-sx-info/20 text-sx-info'
  if (s >= 400 && s < 500) return 'bg-sx-medium/20 text-sx-medium'
  if (s >= 500) return 'bg-sx-critical/20 text-sx-critical'
  return 'bg-sx-surface-2 text-sx-muted'
}
```

- [ ] **Step 2: Create `web/frontend/src/pages/scandetail/OverviewTab.tsx`** — move the progress bar + Stat grid + dates + activity timeline (current `ScanDetail.tsx` lines 54–89) here.

```tsx
import { type ScanDetail, STATUS, fmt } from './types'

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-xl border border-sx-border bg-sx-surface p-4">
      <div className="text-sm text-sx-muted">{label}</div>
      <div className="mt-1 text-2xl font-semibold">{value}</div>
    </div>
  )
}

export function OverviewTab({ data }: { data: ScanDetail }) {
  return (
    <div>
      {data.scan_status === 1 && (
        <div className="mb-6">
          <div className="mb-1 flex justify-between text-xs text-sx-muted"><span>Progress</span><span>{data.progress ?? 0}%</span></div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-sx-surface-2">
            <div className="h-full bg-sx-primary" style={{ width: `${data.progress ?? 0}%` }} />
          </div>
        </div>
      )}
      <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-4">
        <Stat label="Subdomains" value={data.subdomain_count} />
        <Stat label="Endpoints" value={data.endpoint_count} />
        <Stat label="Vulnerabilities" value={data.vulnerability_count} />
        <Stat label="OSINT" value={data.osint_count} />
      </div>
      <div className="mb-2 grid grid-cols-2 gap-4 text-sm text-sx-muted md:grid-cols-2">
        <div>Started: <span className="text-sx-text">{fmt(data.start_scan_date)}</span></div>
        <div>Stopped: <span className="text-sx-text">{fmt(data.stop_scan_date)}</span></div>
      </div>
      <h2 className="mb-3 mt-6 text-base font-medium">Activity timeline</h2>
      <div className="rounded-xl border border-sx-border bg-sx-surface">
        {data.activities.length === 0 && <p className="px-4 py-3 text-sx-muted">No activities yet.</p>}
        {data.activities.map((a) => {
          const ast = STATUS[a.status] ?? STATUS[-1]
          return (
            <div key={a.id} className="flex items-center gap-3 border-b border-sx-border px-4 py-2 last:border-0">
              <span className={'rounded px-2 py-0.5 text-xs ' + ast.cls}>{ast.label}</span>
              <span className="flex-1">{a.title || a.name}</span>
              <span className="text-xs text-sx-muted">{fmt(a.time)}</span>
              {a.error_message && <span className="text-xs text-sx-critical" title={a.error_message}>⚠</span>}
            </div>
          )
        })}
      </div>
    </div>
  )
}
```

- [ ] **Step 3: Rewrite `web/frontend/src/pages/ScanDetail.tsx`** as the tab shell. (Tab content components from Tasks 9–10 are imported here; until those exist, the build will fail — that's expected; this task's build gate is deferred to Task 10's Step where all tabs exist. To keep this task independently green, stub the not-yet-built tabs with a placeholder `() => null` import-free inline and replace them in Tasks 9–10.)

```tsx
import { useQuery } from '@tanstack/react-query'
import { useParams, useSearchParams, Link } from 'react-router-dom'
import { api } from '../api/client'
import { type ScanDetail as ScanDetailT, STATUS } from './scandetail/types'
import { OverviewTab } from './scandetail/OverviewTab'

const TABS = ['overview', 'endpoints', 'ips', 'screenshots', 'directories', 'tech'] as const
type Tab = typeof TABS[number]
const TAB_LABEL: Record<Tab, string> = {
  overview: 'Overview', endpoints: 'Endpoints', ips: 'Ports & IPs',
  screenshots: 'Screenshots', directories: 'Directories', tech: 'Tech',
}

export function ScanDetail() {
  const { id } = useParams()
  const [params, setParams] = useSearchParams()
  const active = (TABS.includes(params.get('tab') as Tab) ? params.get('tab') : 'overview') as Tab
  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan', id],
    queryFn: async () => (await api.get<ScanDetailT>(`/scans/${id}/`)).data,
    refetchInterval: (q) => (q.state.data?.scan_status === 1 ? 5000 : false),
  })
  if (isLoading) return <p className="text-sx-muted">Loading…</p>
  if (isError || !data) return <p className="text-sx-critical">Failed to load scan.</p>
  const st = STATUS[data.scan_status] ?? STATUS[-1]
  const scanId = Number(id)
  return (
    <div>
      <div className="mb-4 flex items-center gap-3">
        <Link to="/scans" className="text-sm text-sx-muted hover:text-sx-text">← Scans</Link>
      </div>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold">{data.domain_name}</h1>
        <span className="text-sx-muted">{data.engine_name}</span>
        <span className={'rounded px-2 py-0.5 text-xs ' + st.cls}>{st.label}</span>
      </div>
      <div className="mb-6 flex gap-1 border-b border-sx-border">
        {TABS.map((t) => (
          <button key={t} onClick={() => setParams(t === 'overview' ? {} : { tab: t }, { replace: true })}
            className={'px-3 py-2 text-sm ' + (active === t ? 'border-b-2 border-sx-primary text-sx-text' : 'text-sx-muted hover:text-sx-text')}>
            {TAB_LABEL[t]}
          </button>
        ))}
      </div>
      {active === 'overview' && <OverviewTab data={data} />}
      {active === 'endpoints' && <EndpointsTab scanId={scanId} />}
      {active === 'ips' && <IpsTab scanId={scanId} />}
      {active === 'screenshots' && <ScreenshotsTab scanId={scanId} />}
      {active === 'directories' && <DirectoriesTab scanId={scanId} />}
      {active === 'tech' && <TechTab scanId={scanId} />}
    </div>
  )
}
```

Add the imports at the top (created in Tasks 9–10):
```tsx
import { EndpointsTab } from './scandetail/EndpointsTab'
import { IpsTab } from './scandetail/IpsTab'
import { ScreenshotsTab } from './scandetail/ScreenshotsTab'
import { DirectoriesTab } from './scandetail/DirectoriesTab'
import { TechTab } from './scandetail/TechTab'
```

- [ ] **Step 4: Commit** (build verified at end of Task 10)

```bash
git add web/frontend/src/pages/ScanDetail.tsx web/frontend/src/pages/scandetail/
git commit -m "feat(spa): ScanDetail tab shell + Overview tab (URL-synced tabs)"
```

---

## Task 9: Tabular tabs — Endpoints, Ports & IPs, Directories, Tech

**Files:** Create `web/frontend/src/pages/scandetail/{EndpointsTab,IpsTab,DirectoriesTab,TechTab}.tsx`

**Interfaces:** each `Tab(props: { scanId: number })` — lazy `useQuery` (enabled by mount, since the shell only mounts the active tab) → `<DataTable>`.

- [ ] **Step 1: `EndpointsTab.tsx`**

```tsx
import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { api } from '../../api/client'
import { DataTable } from '../../components/DataTable'
import { statusCls } from './types'

type Endpoint = {
  id: number; http_url: string; http_status: number; page_title: string | null
  content_length: number | null; content_type: string | null; webserver: string | null
  response_time: number | null; is_important: boolean | null
}

export function EndpointsTab({ scanId }: { scanId: number }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan-endpoints', scanId],
    queryFn: async () => (await api.get<Endpoint[]>('/endpoints/', { params: { scan_history: scanId } })).data,
  })
  const columns = useMemo<ColumnDef<Endpoint>[]>(() => [
    { accessorKey: 'http_url', header: 'URL' },
    { accessorKey: 'http_status', header: 'Status', cell: (c) => {
        const s = c.getValue<number>(); return s ? <span className={'rounded px-2 py-0.5 text-xs ' + statusCls(s)}>{s}</span> : <span className="text-sx-muted">—</span> } },
    { accessorKey: 'page_title', header: 'Title', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
    { accessorKey: 'content_type', header: 'Type', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
    { accessorKey: 'webserver', header: 'Server', cell: (c) => <span className="text-sx-muted">{c.getValue<string>() || '—'}</span> },
    { accessorKey: 'content_length', header: 'Length', cell: (c) => c.getValue<number>() || '—' },
  ], [])
  if (isLoading) return <p className="text-sx-muted">Loading…</p>
  if (isError) return <p className="text-sx-critical">Failed to load endpoints.</p>
  if (!data || data.length === 0) return <p className="text-sx-muted">No endpoints for this scan.</p>
  return <DataTable data={data} columns={columns} countLabel="endpoints" initialSort={[{ id: 'http_status', desc: true }]} />
}
```

- [ ] **Step 2: `IpsTab.tsx`**

```tsx
import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { api } from '../../api/client'
import { DataTable } from '../../components/DataTable'

type Port = { number: number; service_name: string | null; is_uncommon: boolean }
type Ip = { address: string; is_cdn: boolean; ports: Port[] }

export function IpsTab({ scanId }: { scanId: number }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan-ips', scanId],
    queryFn: async () => (await api.get<Ip[]>('/ips/', { params: { scan_history: scanId } })).data,
  })
  const columns = useMemo<ColumnDef<Ip>[]>(() => [
    { accessorKey: 'address', header: 'IP' },
    { accessorKey: 'is_cdn', header: 'CDN', cell: (c) => c.getValue<boolean>() ? 'yes' : '—' },
    { id: 'ports', header: 'Open ports', cell: (c) => {
        const ports = c.row.original.ports
        if (!ports.length) return <span className="text-sx-muted">—</span>
        return <div className="flex flex-wrap gap-1">{ports.map((p) => (
          <span key={p.number} className={'rounded px-1.5 py-0.5 text-xs ' + (p.is_uncommon ? 'bg-sx-medium/20 text-sx-medium' : 'bg-sx-surface-2 text-sx-muted')}>
            {p.number}{p.service_name ? `/${p.service_name}` : ''}</span>)}</div> } },
  ], [])
  if (isLoading) return <p className="text-sx-muted">Loading…</p>
  if (isError) return <p className="text-sx-critical">Failed to load IPs.</p>
  if (!data || data.length === 0) return <p className="text-sx-muted">No IPs for this scan.</p>
  return <DataTable data={data} columns={columns} countLabel="IPs" initialSort={[{ id: 'address', desc: false }]} />
}
```

- [ ] **Step 3: `DirectoriesTab.tsx`**

```tsx
import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { api } from '../../api/client'
import { DataTable } from '../../components/DataTable'
import { statusCls } from './types'

type Dir = { subdomain_name: string; name: string; http_status: number; length: number; words: number; lines: number }

export function DirectoriesTab({ scanId }: { scanId: number }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan-directories', scanId],
    queryFn: async () => (await api.get<Dir[]>('/scan-directories/', { params: { scan_history: scanId } })).data,
  })
  const columns = useMemo<ColumnDef<Dir>[]>(() => [
    { accessorKey: 'subdomain_name', header: 'Subdomain' },
    { accessorKey: 'name', header: 'Path' },
    { accessorKey: 'http_status', header: 'Status', cell: (c) => {
        const s = c.getValue<number>(); return s ? <span className={'rounded px-2 py-0.5 text-xs ' + statusCls(s)}>{s}</span> : '—' } },
    { accessorKey: 'length', header: 'Length' },
    { accessorKey: 'words', header: 'Words' },
    { accessorKey: 'lines', header: 'Lines' },
  ], [])
  if (isLoading) return <p className="text-sx-muted">Loading…</p>
  if (isError) return <p className="text-sx-critical">Failed to load directories.</p>
  if (!data || data.length === 0) return <p className="text-sx-muted">No directory results for this scan.</p>
  return <DataTable data={data} columns={columns} countLabel="paths" initialSort={[{ id: 'subdomain_name', desc: false }]} />
}
```

- [ ] **Step 4: `TechTab.tsx`**

```tsx
import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { api } from '../../api/client'
import { DataTable } from '../../components/DataTable'

type Tech = { name: string; subdomain_count: number }

export function TechTab({ scanId }: { scanId: number }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan-tech', scanId],
    queryFn: async () => (await api.get<Tech[]>('/technologies/', { params: { scan_history: scanId } })).data,
  })
  const columns = useMemo<ColumnDef<Tech>[]>(() => [
    { accessorKey: 'name', header: 'Technology' },
    { accessorKey: 'subdomain_count', header: 'Subdomains' },
  ], [])
  if (isLoading) return <p className="text-sx-muted">Loading…</p>
  if (isError) return <p className="text-sx-critical">Failed to load technologies.</p>
  if (!data || data.length === 0) return <p className="text-sx-muted">No technologies for this scan.</p>
  return <DataTable data={data} columns={columns} countLabel="technologies" initialSort={[{ id: 'subdomain_count', desc: true }]} />
}
```

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/pages/scandetail/
git commit -m "feat(spa): Endpoints / Ports&IPs / Directories / Tech deep-dive tabs"
```

---

## Task 10: Screenshots tab + full frontend build

**Files:** Create `web/frontend/src/pages/scandetail/ScreenshotsTab.tsx`

**Interfaces:** `ScreenshotsTab(props: { scanId: number })` — grid of cards; each uses `<AuthImage>` for the bearer-authenticated screenshot.

- [ ] **Step 1: `ScreenshotsTab.tsx`**

```tsx
import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import { AuthImage } from '../../components/AuthImage'

type Shot = { subdomain_id: number; subdomain_name: string; image_url: string }

export function ScreenshotsTab({ scanId }: { scanId: number }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan-screenshots', scanId],
    queryFn: async () => (await api.get<Shot[]>('/screenshots/', { params: { scan_history: scanId } })).data,
  })
  if (isLoading) return <p className="text-sx-muted">Loading…</p>
  if (isError) return <p className="text-sx-critical">Failed to load screenshots.</p>
  if (!data || data.length === 0) return <p className="text-sx-muted">No screenshots for this scan.</p>
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {data.map((s) => (
        <div key={s.subdomain_id} className="overflow-hidden rounded-xl border border-sx-border bg-sx-surface">
          <AuthImage src={s.image_url} alt={s.subdomain_name} className="h-48 w-full object-cover object-top" />
          <div className="truncate px-3 py-2 text-sm" title={s.subdomain_name}>{s.subdomain_name}</div>
        </div>
      ))}
    </div>
  )
}
```

- [ ] **Step 2: Build the whole SPA** (now all tab imports in `ScanDetail.tsx` resolve)

Run: `cd /root/suricatoos/web/frontend && npm run build`
Expected: clean — `tsc -b` passes (no type errors) and `vite build` writes `dist/`.

- [ ] **Step 3: Commit**

```bash
cd /root/suricatoos
git add web/frontend/src/pages/scandetail/ScreenshotsTab.tsx
git commit -m "feat(spa): Screenshots deep-dive tab (AuthImage grid)"
```

---

## Task 11: Live verification + PR

**Files:** none (verification + integration)

- [ ] **Step 1: Rebuild the image + recreate web (deploys the new SPA + API)**

```bash
cd /root/suricatoos
docker compose -f docker-compose.yml build web celery
# 0 active scans assumed; recreate to pick up the new image and republish /opt/spa
docker compose -f docker-compose.yml up -d web
```

- [ ] **Step 2: Smoke the new endpoints** (replace `<SID>` with a real scan id that has data, e.g. from `ScanHistory.objects.order_by('-id')`)

```bash
docker exec suricatoos-web-1 sh -c '
  for ep in endpoints ips screenshots technologies scan-directories; do
    curl -s -o /dev/null -w "  /api/$ep -> %{http_code}\n" "http://localhost:8000/api/$ep/?scan_history=<SID>"
  done'
```
Expected: 401 without auth is fine for a sanity check; for a true check, hit through the SPA logged in. Confirm none return 500.

- [ ] **Step 3: Live UI check** — log into the SPA at `https://<host>/app/`, open a scan with data, click each tab (Endpoints, Ports & IPs, Screenshots, Directories, Tech). Confirm data renders, screenshots load (AuthImage), tabs deep-link (`?tab=`), and empty tabs show their empty state.

- [ ] **Step 4: Push + open PR**

```bash
TOK=$(cat /root/.suricatoos_token)
git push "https://x-access-token:${TOK}@github.com/williamsouzadelima/suricatoos-scan.git" feat/scandetail-deepdive
```
Then open a PR against `main` (title: `feat(spa): ScanDetail deep-dive — endpoints/ips/screenshots/directories/tech tabs`) with a body summarizing the spec. **Do not merge** — merge is gated on explicit approval.

---

## Self-Review

- **Spec coverage:** endpoints ✓ (T1), ips/ports ✓ (T2), tech ✓ (T3), directories ✓ (T4), screenshots list + JWT image ✓ (T5), shared DataTable + migration ✓ (T6), AuthImage ✓ (T7), tab shell + Overview ✓ (T8), 4 tabular tabs ✓ (T9), screenshots tab ✓ (T10), backend tests ✓ (T1–T5), live frontend verification + PR ✓ (T11). Security containment for screenshots ✓ (T5 Step 4 + traversal test).
- **Placeholders:** none — every step has real code/commands. (The one intentional cross-task dependency — ScanDetail importing tabs created in T9/T10 — is called out, with the build gate at T10 Step 2.)
- **Type consistency:** `ScanDetail` type centralized in `scandetail/types.ts` and consumed by the shell + OverviewTab; tab props are uniformly `{ scanId: number }`; `DataTable<T>` prop names match across all tab usages; serializer field names match the TS row types (e.g. `http_url`, `subdomain_count`, `image_url`).

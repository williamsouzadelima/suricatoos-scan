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

    def test_eager_loaded_lists_return_200(self):
        # Onda 3 (#16/#17/#19): as querysets ganharam select_related/prefetch_related. Um nome
        # de relação errado dispararia FieldError (HTTP 500). O select_related constrói os JOINs
        # na montagem do queryset — exercitado mesmo em base vazia — então este smoke pega erros
        # de nome de relação nos endpoints otimizados.
        for route in ('/api/listVulnerability/', '/api/listDatatableSubdomain/',
                      '/api/listSubdomains/', '/api/listTargets/'):
            resp = self.client.get(route)
            self.assertEqual(resp.status_code, 200, f'GET {route} deveria ser 200, veio {resp.status_code}')


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


class SubdomainCountAnnotationTests(TestCase):
    """Onda 3b (#16): as Subquery annotations de contagem do SubdomainDatatableViewSet devem
    reproduzir EXATAMENTE as properties do model que elas substituem (incl. excluir
    FALSE_POSITIVE). Testa o endpoint real (viewset annotation + serializer) contra a property
    (fonte da verdade) e valores concretos."""

    def setUp(self):
        self.user = get_user_model().objects.create_user(username='cnt_tester', password='x-irrelevant')
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def test_severity_counts_match_property_and_exclude_false_positive(self):
        from django.utils import timezone
        from targetApp.models import Domain
        from scanEngine.models import EngineType
        from startScan.models import ScanHistory, Subdomain, Vulnerability

        domain = Domain.objects.create(name='fixture.example')
        engine = EngineType.objects.create(engine_name='e', yaml_configuration='')
        sh = ScanHistory.objects.create(start_scan_date=timezone.now(), domain=domain, scan_type=engine)
        sub = Subdomain.objects.create(name='a.fixture.example', scan_history=sh, target_domain=domain)
        for sev in (0, 1, 2, 2, 3, 4, 4):
            Vulnerability.objects.create(name=f'v{sev}', severity=sev, subdomain=sub,
                                         scan_history=sh, target_domain=domain)
        # uma false-positive (sev crítico) que AMBAS property e annotation devem excluir
        Vulnerability.objects.create(name='fp', severity=4, subdomain=sub, scan_history=sh,
                                     target_domain=domain,
                                     validation_status=Vulnerability.VALIDATION_FALSE_POSITIVE)

        resp = self.client.get(f'/api/listDatatableSubdomain/?scan_id={sh.id}')
        self.assertEqual(resp.status_code, 200)
        # O envelope varia: sem os params de DataTables (draw/start/length) o paginador
        # devolve a lista pura; com paginação vem {'data': [...]} (ou {'results': [...]}).
        payload = resp.data
        if isinstance(payload, dict):
            rows_src = payload.get('data') or payload.get('results') or []
        else:
            rows_src = payload
        rows = [r for r in rows_src if r['name'] == sub.name]
        self.assertEqual(len(rows), 1, 'o subdomínio do fixture deve aparecer na página')
        row = rows[0]
        # a annotation (via endpoint) deve bater com a property (fonte da verdade)...
        self.assertEqual(row['info_count'], sub.get_info_count)
        self.assertEqual(row['low_count'], sub.get_low_count)
        self.assertEqual(row['medium_count'], sub.get_medium_count)
        self.assertEqual(row['high_count'], sub.get_high_count)
        self.assertEqual(row['critical_count'], sub.get_critical_count)
        # ...e com os valores concretos (FALSE_POSITIVE excluído): info/low/medium/high/critical
        self.assertEqual(
            [row['info_count'], row['low_count'], row['medium_count'], row['high_count'], row['critical_count']],
            [1, 1, 2, 1, 2],
        )

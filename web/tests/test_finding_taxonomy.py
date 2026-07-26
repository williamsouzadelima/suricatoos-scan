"""Taxonomia do achado: separar reconhecimento de vulnerabilidade.

Medido em producao em 26/07/2026, sobre 12.096 achados reais:
  - 97,3% eram severidade `info`;
  - o achado de MAIOR volume era "RDAP WHOIS" (3.923) — uma consulta WHOIS;
  - o 3o era "WAF Detection" (1.532) — que e uma coisa BOA;
  - so 2 criticos e 8 altos existiam, soterrados sob 11.766 linhas de fato de ambiente;
  - 12.096 ocorrencias para 137 nomes unicos: 88 repeticoes em media.

Enquanto reconhecimento e vulnerabilidade forem o mesmo objeto, toda contagem,
dashboard, relatorio e rating mente. Estes testes usam os casos REAIS medidos, com as
tags exatas que o nuclei atribuiu em producao.

Run with:  python3 manage.py test tests.test_finding_taxonomy
"""
import unittest

from django.test import TestCase

from Suricatoos.common_func import classify_finding
from Suricatoos.definitions import (FINDING_CLASS_VULNERABILITY, FINDING_CLASS_HYGIENE,
                                    FINDING_CLASS_INVENTORY)


# Casos reais: (nome, severidade, tags exatas do nuclei em producao, classe esperada)
CASOS_REAIS = [
    # --- inventario: fato de ambiente, nao ha o que remediar ---
    ('RDAP WHOIS', 0, ['misc', 'miscellaneous', 'osint', 'rdap', 'vuln', 'whois'],
     FINDING_CLASS_INVENTORY),
    ('WAF Detection', 0, ['discovery', 'misc', 'tech', 'waf'], FINDING_CLASS_INVENTORY),
    ('Wappalyzer Technology Detection', 0, ['discovery', 'tech'], FINDING_CLASS_INVENTORY),
    ('DNS WAF Detection', 0, ['discovery', 'dns', 'tech', 'waf'], FINDING_CLASS_INVENTORY),
    ('CAA Record', 0, ['caa', 'discovery', 'dns'], FINDING_CLASS_INVENTORY),
    ('WordPress Passive Detection', 0,
     ['cms', 'discovery', 'enum', 'passive', 'plugin', 'tech', 'theme', 'wordpress', 'wp'],
     FINDING_CLASS_INVENTORY),
    ('TLS Version - Detect', 0, ['discovery', 'ssl', 'tls'], FINDING_CLASS_INVENTORY),
    # --- higiene: boa pratica ausente, real mas nao exploravel por si ---
    ('HTTP Missing Security Headers', 0, ['generic', 'headers', 'misconfig', 'vuln'],
     FINDING_CLASS_HYGIENE),
    ('Missing Subresource Integrity', 0, ['compliance', 'css', 'js', 'misconfig', 'sri', 'vuln'],
     FINDING_CLASS_HYGIENE),
    # --- vulnerabilidade: o que o cliente precisa ver ---
    ('XSS (Cross Site Scripting)', 2, [], FINDING_CLASS_VULNERABILITY),
    ('WordPress LiteSpeed Cache - Unauthenticated Privilege Escalation', 4,
     ['wordpress', 'wp-plugin', 'cve'], FINDING_CLASS_VULNERABILITY),
    ('React Server Components - Denial of Service', 3, ['cve', 'react'],
     FINDING_CLASS_VULNERABILITY),
]


class CasosReaisTests(unittest.TestCase):
    def test_classifica_os_casos_medidos_em_producao(self):
        for nome, sev, tags, esperado in CASOS_REAIS:
            with self.subTest(achado=nome):
                self.assertEqual(classify_finding(sev, tags), esperado,
                                 f'{nome} (sev={sev}, tags={tags})')

    def test_rdap_whois_nao_e_vulnerabilidade(self):
        # O achado nº1 do sistema em volume. Se este teste falhar, a regra regrediu para
        # o estado em que uma consulta WHOIS era a "vulnerabilidade" mais comum da base.
        self.assertEqual(
            classify_finding(0, ['misc', 'osint', 'rdap', 'vuln', 'whois']),
            FINDING_CLASS_INVENTORY)

    def test_detectar_um_waf_nao_e_achado_de_risco(self):
        # Ter WAF e uma coisa BOA. Contar isso como vulnerabilidade inverte o sinal.
        self.assertEqual(classify_finding(0, ['discovery', 'misc', 'tech', 'waf']),
                         FINDING_CLASS_INVENTORY)


class PisoDeSeveridadeTests(unittest.TestCase):
    """A tag NUNCA pode esconder um achado severo — as tags do nuclei sao inconsistentes."""

    def test_severidade_media_ou_maior_nunca_e_rebaixada(self):
        # Mesmo carregando tags de inventario, um achado medium+ continua vulnerabilidade.
        for sev in (2, 3, 4):
            with self.subTest(severidade=sev):
                self.assertEqual(
                    classify_finding(sev, ['discovery', 'tech', 'osint', 'passive']),
                    FINDING_CLASS_VULNERABILITY)
                self.assertEqual(
                    classify_finding(sev, ['misconfig', 'compliance']),
                    FINDING_CLASS_VULNERABILITY)

    def test_a_tag_vuln_do_nuclei_nao_e_confiavel(self):
        # "RDAP WHOIS" carrega a tag `vuln` em producao. Confiar nela para PROMOVER
        # traria 3.923 consultas WHOIS de volta para a contagem de risco.
        self.assertEqual(classify_finding(0, ['vuln', 'osint', 'whois']),
                         FINDING_CLASS_INVENTORY)


class BordasTests(unittest.TestCase):
    def test_sem_tag_permanece_vulnerabilidade(self):
        # dalfox e o scanner bridge nao tageiam: sem base para rebaixar, nao se rebaixa.
        for tags in ([], None, ['', '  ']):
            with self.subTest(tags=tags):
                self.assertEqual(classify_finding(0, tags), FINDING_CLASS_VULNERABILITY)

    def test_severidade_invalida_nao_quebra(self):
        for sev in (None, '', 'alta', object()):
            with self.subTest(sev=sev):
                self.assertIn(classify_finding(sev, ['discovery']),
                              (FINDING_CLASS_INVENTORY, FINDING_CLASS_VULNERABILITY))

    def test_tags_sao_normalizadas(self):
        self.assertEqual(classify_finding(0, ['DISCOVERY', ' Tech ']),
                         FINDING_CLASS_INVENTORY)

    def test_inventario_vence_higiene(self):
        # "WordPress Passive Detection" carrega as duas familias; o que entrega e fato
        # de ambiente, nao boa pratica ausente.
        self.assertEqual(classify_finding(0, ['discovery', 'misconfig']),
                         FINDING_CLASS_INVENTORY)


class ModeloTests(unittest.TestCase):
    def test_default_do_campo_nao_muda_contagem_nenhuma(self):
        # A coluna nasce com todo mundo em `vulnerability`: a taxonomia so passa a valer
        # depois do passo EXPLICITO (manage.py classify_findings --apply). Sem isso, o
        # deploy do campo mudaria silenciosamente o que o cliente ve.
        from startScan.models import Vulnerability
        campo = Vulnerability._meta.get_field('finding_class')
        self.assertEqual(campo.default, Vulnerability.CLASS_VULNERABILITY)
        self.assertTrue(campo.db_index, 'sera filtrado em toda listagem')


class UserFacingQuerysetTests(TestCase):
    """A definicao UNICA de "o que conta como vulnerabilidade".

    Antes, ~10 lugares (dashboard, api/views, api/serializers, tasks, models, o gate do
    PDF) repetiam `.exclude(validation_status=FALSE_POSITIVE)` a mao. Com a taxonomia,
    cada um teria de aprender TAMBEM a filtrar por classe — e bastaria esquecer um para o
    painel dizer 600 e o relatorio entregue ao cliente dizer 12.018, que e pior que nao
    ter feito nada.
    """

    def setUp(self):
        from targetApp.models import Domain
        from scanEngine.models import EngineType
        from startScan.models import ScanHistory, Vulnerability
        from django.utils import timezone
        self.V = Vulnerability
        dom = Domain.objects.create(name='example.com')
        eng = EngineType.objects.create(engine_name='t', yaml_configuration='{}')
        self.scan = ScanHistory.objects.create(
            domain=dom, scan_type=eng, start_scan_date=timezone.now(), scan_status=2)

        def mk(nome, classe, sev=0, status='confirmed'):
            return Vulnerability.objects.create(
                scan_history=self.scan, target_domain=dom, name=nome, severity=sev,
                finding_class=classe, validation_status=status, http_url='http://x/')

        self.vuln = mk('XSS', Vulnerability.CLASS_VULNERABILITY, sev=2)
        self.hyg = mk('Missing Security Headers', Vulnerability.CLASS_HYGIENE)
        self.inv = mk('RDAP WHOIS', Vulnerability.CLASS_INVENTORY)
        self.fp = mk('Falso positivo', Vulnerability.CLASS_VULNERABILITY,
                     sev=2, status='false_positive')

    def test_user_facing_conta_so_vulnerabilidade_real(self):
        nomes = set(self.V.objects.user_facing().values_list('name', flat=True))
        self.assertEqual(nomes, {'XSS'})

    def test_user_facing_exclui_inventario_e_higiene(self):
        ids = set(self.V.objects.user_facing().values_list('id', flat=True))
        self.assertNotIn(self.hyg.id, ids)
        self.assertNotIn(self.inv.id, ids)

    def test_user_facing_continua_excluindo_falso_positivo(self):
        # A taxonomia nao pode ter feito a exclusao de FP regredir.
        self.assertNotIn(self.fp.id, set(self.V.objects.user_facing().values_list('id', flat=True)))

    def test_hygiene_isola_o_balde_proprio(self):
        nomes = set(self.V.objects.hygiene().values_list('name', flat=True))
        self.assertEqual(nomes, {'Missing Security Headers'})

    def test_contagens_do_scan_usam_a_mesma_definicao(self):
        self.assertEqual(self.scan.get_vulnerability_count(), 1)
        self.assertEqual(self.scan.get_hygiene_count(), 1)
        self.assertEqual(self.scan.get_medium_vulnerability_count(), 1)
        self.assertEqual(self.scan.get_info_vulnerability_count(), 0)


class NenhumSiteReimplementaOFiltroTests(unittest.TestCase):
    def test_ninguem_repete_o_exclude_a_mao(self):
        # Trava de regressao: um site novo que copie o `.exclude(validation_status=...)`
        # em vez de usar `.user_facing()` volta a divergir do resto silenciosamente.
        import os
        raiz = os.path.join(os.path.dirname(__file__), '..')
        alvo = 'exclude(validation_status=Vulnerability.VALIDATION_FALSE_POSITIVE)'
        infratores = []
        for base, _dirs, arqs in os.walk(raiz):
            if any(p in base for p in ('/tests', '/migrations', '__pycache__', '/node_modules')):
                continue
            for a in arqs:
                if not a.endswith('.py'):
                    continue
                caminho = os.path.join(base, a)
                with open(caminho, errors='ignore') as f:
                    for n, linha in enumerate(f, 1):
                        if alvo in linha and 'def real' not in linha:
                            # a unica ocorrencia legitima e dentro do proprio helper
                            if 'return self.exclude' in linha:
                                continue
                            infratores.append(f'{os.path.relpath(caminho, raiz)}:{n}')
        self.assertEqual(infratores, [], f'usar .user_facing() nestes: {infratores}')


class SuperficiesDeUsuarioTests(TestCase):
    """A higiene tem superfície PRÓPRIA — não some, nem conta como risco."""

    def test_api_aceita_filtro_por_classe(self):
        import inspect
        from api import views
        src = inspect.getsource(views.VulnerabilityViewSet.get_queryset)
        self.assertIn("finding_class", src)
        self.assertIn("base.hygiene()", src)
        self.assertIn("base.user_facing()", src)

    def test_api_nao_expoe_inventario_por_parametro(self):
        # Só `hygiene` tem superfície; qualquer outro valor cai em user_facing().
        # Sem isso, `?finding_class=inventory` reabriria por query os 8.048 que a
        # taxonomia tirou da contagem.
        import inspect
        from api import views
        src = inspect.getsource(views.VulnerabilityViewSet.get_queryset)
        self.assertNotIn("CLASS_INVENTORY", src)

    def test_relatorio_tem_secao_propria_de_higiene(self):
        import os
        base = os.path.join(os.path.dirname(__file__), '..')
        with open(os.path.join(base, 'templates/report/default.html')) as f:
            html = f.read()
        self.assertIn('hygiene_findings', html)
        self.assertIn('hygiene-summary', html)

    def test_pagina_do_scan_tem_aba_de_higiene(self):
        import os
        base = os.path.join(os.path.dirname(__file__), '..')
        with open(os.path.join(base, 'startScan/templates/startScan/detail_scan.html')) as f:
            html = f.read()
        self.assertIn('total_hygiene_count', html)
        self.assertIn('finding_class=hygiene', html)

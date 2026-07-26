"""deep_port_queue: idempotencia, relevancia e fan-out finito.

Contexto (incidente de 2026-07): a `deep_port_queue` acumulou 344 tarefas `udp_port_scan`
de scans ja encerrados, e os 4 slots do deep_port_worker ficaram ocupados pela MESMA task
id (`753a8559…`, do scan 49, concluido em 01/07), reentregue apos perdas de conexao com o
redis. Cada copia rodava `nmap -sU -p 1-65535` contra host de cliente por DIAS — a do scan
49 seguia viva 24 dias depois. Essas tasks rodam com ctx['track']=False, entao seu celery_id
nunca entra em ScanHistory.celery_ids e o hang_monitor (que revoga exatamente celery_ids)
e incapaz de mata-las: o guard de relevancia e a UNICA autoridade que existe sobre elas.

Run with:  python3 manage.py test tests.test_deep_udp_hardening
"""
import os
import tempfile
import unittest
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from Suricatoos.tasks import (build_udp_nmap_cmd, parse_nmap_xml_open_ports,
                              _deep_udp_chunks, _deep_udp_select_hosts,
                              _deep_udp_still_relevant)
from Suricatoos.definitions import (DEEP_UDP_CHUNK_PORTS, DEEP_UDP_MAX_HOSTS,
                                    DEEP_UDP_STALE_AFTER, DEEP_UDP_MESSAGE_EXPIRES,
                                    RUNNING_TASK, ABORTED_TASK)


# nmap 7.98, capturado de verdade: host que estoura --host-timeout produz
# `timedout="true"` e NENHUM elemento <ports>.
XML_TIMEDOUT = ('<?xml version="1.0"?><nmaprun><host starttime="1785020833" '
                'endtime="1785020843" timedout="true"><status state="up"/>'
                '<address addr="10.0.0.5" addrtype="ipv4"/><hostnames></hostnames>'
                '<times srtt="27"/></host></nmaprun>')


class NmapTimeoutSemanticsTests(unittest.TestCase):
    """A premissa que justifica FATIAR em vez de cronometrar o host."""

    def test_timed_out_host_yields_nothing(self):
        # E tentador "limitar o host" com --host-timeout e supor que o parcial e gravado.
        # Nao e: o resultado do host inteiro se perde. Sobre a faixa cheia, um alvo que
        # faz rate-limit de ICMP (a razao de durar dias) estouraria SEMPRE — o tier deep
        # viraria "rapido e sempre vazio", indistinguivel de "nenhuma porta UDP" na UI.
        with tempfile.NamedTemporaryFile('w', suffix='.xml', delete=False) as f:
            f.write(XML_TIMEDOUT)
            path = f.name
        try:
            self.assertEqual(parse_nmap_xml_open_ports(path), [])
        finally:
            os.unlink(path)


class ChunkingTests(unittest.TestCase):
    def test_chunks_cover_the_full_range_without_gap_or_overlap(self):
        chunks = _deep_udp_chunks()
        self.assertEqual(chunks[0][0], 1)
        self.assertEqual(chunks[-1][1], 65535)
        for (a_lo, a_hi), (b_lo, b_hi) in zip(chunks, chunks[1:]):
            self.assertEqual(b_lo, a_hi + 1, 'blocos precisam ser contiguos')
        total = sum(hi - lo + 1 for lo, hi in chunks)
        self.assertEqual(total, 65535, 'a promessa do tier deep e a faixa TODA')

    def test_chunk_size_respects_the_knob(self):
        self.assertLessEqual(_deep_udp_chunks()[0][1], DEEP_UDP_CHUNK_PORTS)

    def test_command_carries_the_partial_range_not_the_full_one(self):
        cmd = build_udp_nmap_cmd('example.com', 'deep', port_range='1-8192')
        self.assertIn('-p 1-8192', cmd)
        self.assertNotIn('1-65535', cmd)

    def test_range_is_validated_against_injection(self):
        self.assertIsNone(build_udp_nmap_cmd('example.com', 'deep', port_range='1-80 -oN /tmp/x'))
        self.assertIsNone(build_udp_nmap_cmd('example.com', 'deep', port_range='$(id)'))

    def test_default_range_is_still_the_full_sweep(self):
        self.assertIn('-p 1-65535', build_udp_nmap_cmd('example.com', 'deep'))

    def test_non_deep_tier_never_emits_udp(self):
        for tier in ('fast', 'medium'):
            self.assertIsNone(build_udp_nmap_cmd('example.com', tier, port_range='1-100'))


class AdaptiveSweepTests(unittest.TestCase):
    """O caminho de ESTOURO — o que a primeira versao errava e nenhum teste cobria.

    Com bloco de tamanho FIXO, um alvo que faz rate-limit de ICMP dest-unreachable
    (~1 porta/s — a classe de alvo que motiva o tier deep, e a razao de um `-sU -p-` durar
    ~18h) nunca cabia nos 2700s do orcamento. Todo bloco morria por SIGKILL, o nmap nao
    grava parcial, e apos 3 strikes o host voltava VAZIO: "rapido e sempre vazio",
    indistinguivel de "nenhuma porta UDP" na UI. Era REGRESSAO — antes dos blocos, um unico
    nmap com watchdog de dias concluia com as portas reais.
    """

    def test_slow_target_is_subdivided_instead_of_abandoned(self):
        from Suricatoos.tasks import _deep_udp_sweep
        from Suricatoos.definitions import DEEP_UDP_MIN_CHUNK_PORTS
        # Alvo que so consegue varrer faixas pequenas: qualquer coisa acima do piso estoura.
        scanned = []

        def scan_range(lo, hi):
            if (hi - lo + 1) > DEEP_UDP_MIN_CHUNK_PORTS:
                return True, []          # morto pelo watchdog, sem resultado parcial
            scanned.append((lo, hi))
            return False, [{'port': lo, 'ip': '10.0.0.1'}]

        found, reason = _deep_udp_sweep([(1, 8192)], scan_range)
        self.assertEqual(reason, '', 'nao pode desistir do host: as faixas cabem quando divididas')
        self.assertEqual(len(found), 8192 // DEEP_UDP_MIN_CHUNK_PORTS)
        # E a faixa toda tem que acabar coberta, sem buraco nem sobreposicao.
        cobertura = sorted(scanned)
        self.assertEqual(cobertura[0][0], 1)
        self.assertEqual(cobertura[-1][1], 8192)
        for (a_lo, a_hi), (b_lo, b_hi) in zip(cobertura, cobertura[1:]):
            self.assertEqual(b_lo, a_hi + 1)

    def test_fast_target_is_not_subdivided(self):
        from Suricatoos.tasks import _deep_udp_sweep
        calls = []

        def scan_range(lo, hi):
            calls.append((lo, hi))
            return False, []

        _deep_udp_sweep([(1, 8192), (8193, 16384)], scan_range)
        self.assertEqual(calls, [(1, 8192), (8193, 16384)], 'sem estouro, nada de subdividir')

    def test_gives_up_only_after_the_floor_itself_times_out(self):
        from Suricatoos.tasks import _deep_udp_sweep
        from Suricatoos.definitions import DEEP_UDP_MAX_TIMED_OUT_CHUNKS
        # Alvo que nao responde nem no piso: aí sim desistir é o certo.
        found, reason = _deep_udp_sweep([(1, 8192)], lambda lo, hi: (True, []))
        self.assertEqual(found, [])
        self.assertIn('piso', reason)
        self.assertIn(str(DEEP_UDP_MAX_TIMED_OUT_CHUNKS), reason)

    def test_results_confirmed_before_giving_up_are_kept(self):
        # O ponto do fatiamento: o que ja foi confirmado nao se perde quando o resto morre.
        # Faixas ja no piso, entao cada estouro conta strike direto (sem subdividir); sao
        # precisos DEEP_UDP_MAX_TIMED_OUT_CHUNKS estouros para desistir do host.
        from Suricatoos.tasks import _deep_udp_sweep
        from Suricatoos.definitions import DEEP_UDP_MAX_TIMED_OUT_CHUNKS
        ranges = [(1, 100)] + [(100 * i + 1, 100 * (i + 1))
                               for i in range(1, DEEP_UDP_MAX_TIMED_OUT_CHUNKS + 1)]

        def scan_range(lo, hi):
            return (False, [{'port': 53}]) if lo == 1 else (True, [])

        found, reason = _deep_udp_sweep(ranges, scan_range)
        self.assertEqual(found, [{'port': 53}], 'o que foi confirmado tem que sobreviver')
        self.assertIn('piso', reason, 'desistiu apos os strikes no piso')

    def test_host_budget_stops_the_sweep(self):
        from Suricatoos.tasks import _deep_udp_sweep
        from Suricatoos.definitions import DEEP_UDP_HOST_BUDGET
        # Relogio falso que salta o orcamento inteiro apos a primeira faixa.
        ticks = iter([0, 0, DEEP_UDP_HOST_BUDGET + 1, DEEP_UDP_HOST_BUDGET + 2])
        found, reason = _deep_udp_sweep(
            [(1, 100), (101, 200)], lambda lo, hi: (False, [{'port': lo}]),
            clock=lambda: next(ticks))
        self.assertEqual(found, [{'port': 1}], 'a primeira faixa foi varrida e salva')
        self.assertIn('teto', reason)

    def test_irrelevant_scan_stops_the_sweep_midway(self):
        from Suricatoos.tasks import _deep_udp_sweep
        calls = []

        def scan_range(lo, hi):
            calls.append((lo, hi))
            return False, []

        # Relevante na 1a checagem, irrelevante na 2a (scan abortado no meio da varredura).
        states = iter([(True, ''), (False, 'scan 49 foi abortado')])
        found, reason = _deep_udp_sweep(
            [(1, 100), (101, 200)], scan_range, still_relevant=lambda: next(states))
        self.assertEqual(len(calls), 1, 'nao pode seguir varrendo host de scan abortado')
        self.assertIn('abortado', reason)


class RelevanceGuardTests(TestCase):
    def setUp(self):
        from targetApp.models import Domain
        from scanEngine.models import EngineType
        from startScan.models import ScanHistory
        self.ScanHistory = ScanHistory
        self.domain = Domain.objects.create(name='example.com')
        self.engine = EngineType.objects.create(engine_name='t', yaml_configuration='{}')

    def _scan(self, status, age_s):
        return self.ScanHistory.objects.create(
            domain=self.domain, scan_type=self.engine, scan_status=status,
            start_scan_date=timezone.now() - timedelta(seconds=age_s))

    def test_finished_scan_is_STILL_relevant(self):
        # Deliberado: o fan-out e fire-and-forget e report() fecha o scan enquanto as
        # varreduras seguem na fila. Exigir RUNNING descartaria em silencio tudo a partir
        # do 5o host — o guard estaria "funcionando" e destruindo o recurso.
        from Suricatoos.definitions import SUCCESS_TASK
        scan = self._scan(SUCCESS_TASK, age_s=3600)
        ok, _ = _deep_udp_still_relevant(scan.id)
        self.assertTrue(ok)

    def test_aborted_scan_is_not_relevant(self):
        scan = self._scan(ABORTED_TASK, age_s=3600)
        ok, why = _deep_udp_still_relevant(scan.id)
        self.assertFalse(ok)
        self.assertIn('abortado', why)

    def test_scan_older_than_the_drain_budget_is_not_relevant(self):
        # O caso literal do scan 49: concluido em 01/07 e ainda varrendo em 25/07.
        scan = self._scan(RUNNING_TASK, age_s=DEEP_UDP_STALE_AFTER + 3600)
        ok, why = _deep_udp_still_relevant(scan.id)
        self.assertFalse(ok)
        self.assertIn('teto', why)

    def test_deleted_scan_is_not_relevant(self):
        ok, why = _deep_udp_still_relevant(999999)
        self.assertFalse(ok)
        self.assertIn('nao existe', why)

    def test_fresh_scan_is_relevant(self):
        scan = self._scan(RUNNING_TASK, age_s=60)
        ok, _ = _deep_udp_still_relevant(scan.id)
        self.assertTrue(ok)


class SingleFlightLockTests(unittest.TestCase):
    class FakeRedis:
        def __init__(self):
            self.store = {}

        def set(self, key, value, nx=False, ex=None):
            if nx and key in self.store:
                return None
            self.store[key] = value
            return True

        def eval(self, script, nkeys, key, token):
            if self.store.get(key) == token:
                del self.store[key]
                return 1
            return 0

    def test_second_copy_is_refused_while_the_first_holds(self):
        from Suricatoos.tasks import _deep_udp_lock_acquire, _deep_udp_lock_release
        fake = self.FakeRedis()
        with patch('Suricatoos.tasks._deep_udp_broker', return_value=fake):
            self.assertTrue(_deep_udp_lock_acquire(49, 'erp.example.com', 'task-a', 60))
            self.assertFalse(_deep_udp_lock_acquire(49, 'erp.example.com', 'task-b', 60))
            _deep_udp_lock_release(49, 'erp.example.com', 'task-a')
            self.assertTrue(_deep_udp_lock_acquire(49, 'erp.example.com', 'task-b', 60))

    def test_release_only_removes_our_own_token(self):
        # Sem o compare-and-delete, uma copia que termina depois do TTL expirar apagaria
        # o lock de outra copia legitima.
        from Suricatoos.tasks import _deep_udp_lock_acquire, _deep_udp_lock_release
        fake = self.FakeRedis()
        with patch('Suricatoos.tasks._deep_udp_broker', return_value=fake):
            _deep_udp_lock_acquire(1, 'h', 'mine', 60)
            _deep_udp_lock_release(1, 'h', 'someone-else')
            self.assertFalse(_deep_udp_lock_acquire(1, 'h', 'other', 60))

    def test_broker_down_fails_open(self):
        # O lock protege um recurso, nao e um gate de seguranca: broker fora do ar nao
        # pode impedir o scan de rodar.
        from Suricatoos.tasks import _deep_udp_lock_acquire
        with patch('Suricatoos.tasks._deep_udp_broker', return_value=None):
            self.assertTrue(_deep_udp_lock_acquire(1, 'h', 'tok', 60))

    def test_different_hosts_do_not_block_each_other(self):
        from Suricatoos.tasks import _deep_udp_lock_acquire
        fake = self.FakeRedis()
        with patch('Suricatoos.tasks._deep_udp_broker', return_value=fake):
            self.assertTrue(_deep_udp_lock_acquire(1, 'a.example.com', 't1', 60))
            self.assertTrue(_deep_udp_lock_acquire(1, 'b.example.com', 't2', 60))


class HostSelectionTests(unittest.TestCase):
    def test_no_cap_when_under_the_limit(self):
        hosts = [f'h{i}.example.com' for i in range(3)]
        sel, skipped = _deep_udp_select_hosts(hosts, None, 1)
        self.assertEqual(sel, hosts)
        self.assertEqual(skipped, 0)

    def test_cap_is_applied_and_the_remainder_is_reported(self):
        hosts = [f'h{i:03d}.example.com' for i in range(DEEP_UDP_MAX_HOSTS + 10)]
        with patch('Suricatoos.tasks.Subdomain'):
            sel, skipped = _deep_udp_select_hosts(hosts, None, 1)
        self.assertEqual(len(sel), DEEP_UDP_MAX_HOSTS)
        self.assertEqual(skipped, 10)

    def test_window_rotates_between_scans_so_the_tail_is_eventually_covered(self):
        # get_subdomains ordena por nome, entao um corte simples varreria SEMPRE os
        # mesmos primeiros nomes e NUNCA a cauda (vpn.*, www.*) — em nenhum scan, jamais.
        # Nao e "pode-se perder um host": e ponto cego reproduzivel que a UI apresenta
        # como "nenhuma porta UDP".
        hosts = [f'h{i:03d}.example.com' for i in range(DEEP_UDP_MAX_HOSTS * 3)]
        with patch('Suricatoos.tasks.Subdomain'):
            seen = set()
            for scan_id in range(3):
                sel, _ = _deep_udp_select_hosts(hosts, None, scan_id)
                seen.update(sel)
        self.assertEqual(len(seen), len(hosts), 'a cauda tem que ser coberta em algum scan')

    def test_selection_is_deterministic_for_the_same_scan(self):
        hosts = [f'h{i:03d}.example.com' for i in range(DEEP_UDP_MAX_HOSTS + 5)]
        with patch('Suricatoos.tasks.Subdomain'):
            a, _ = _deep_udp_select_hosts(hosts, None, 7)
            b, _ = _deep_udp_select_hosts(hosts, None, 7)
        self.assertEqual(a, b)


class MessageExpiryTests(unittest.TestCase):
    def test_expiry_outlives_the_drain_budget(self):
        # Se a mensagem expirasse antes de a fila drenar, o teto viraria descarte
        # silencioso de trabalho legitimo.
        self.assertGreater(DEEP_UDP_MESSAGE_EXPIRES, DEEP_UDP_STALE_AFTER)

    def test_dispatch_sets_an_expiry(self):
        import inspect
        from Suricatoos import tasks
        src = inspect.getsource(tasks.port_scan)
        self.assertIn('expires=DEEP_UDP_MESSAGE_EXPIRES', src)

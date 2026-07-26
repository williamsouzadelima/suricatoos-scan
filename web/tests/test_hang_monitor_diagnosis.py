"""hang_monitor: distinguir INFRA de scan travado antes de abortar.

Contexto (incidente de 2026-07-22): um OOM matou o processo do coordinator_worker e o
container seguiu `Up`. A `coordinator_queue` ficou sem consumidor, todo scan parava logo
apos o `Http crawl` e o hang_monitor abortou os scans 66, 67 e 68 gravando
`Auto-aborted by hang monitor` — mensagem que nao aponta para causa nenhuma. O monitor
acertava "parou" e errava por completo "por que".

Estes testes fixam a tabela de decisao:

  A  alguma celery_id do scan viva            -> nao aborta
  B  probe indisponivel ou PARCIAL            -> segura (limitado por INFRA_ABORT_AFTER)
  C  fila orfa com mensagem estacionada       -> segura: retoma sozinho
  D  fila orfa e VAZIA                        -> fase perdida: aborta ja
  E  filas servidas, alguma com backlog       -> segura: e fila cheia, nao cunha
  F  tudo servido, tudo vazio, nada vivo      -> cunha genuina: aborta

Run with:  python3 manage.py test tests.test_hang_monitor_diagnosis
"""
import unittest
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from Suricatoos.tasks import hang_monitor, _pipeline_queues, _inspect_cluster, _fit
from Suricatoos.definitions import (RUNNING_TASK, ABORTED_TASK,
                                    HANG_MONITOR_HOLD_PREFIX,
                                    HANG_MONITOR_INFRA_ABORT_AFTER,
                                    HANG_MONITOR_STALE_AFTER)


class PipelineQueuesTests(unittest.TestCase):
    def test_covers_the_queue_that_caused_the_incident(self):
        q = _pipeline_queues()
        self.assertIn('coordinator_queue', q)
        self.assertIn('main_scan_queue', q)

    def test_excludes_fire_and_forget_and_notification_queues(self):
        q = _pipeline_queues()
        # deep_port_queue e profunda POR DESIGN (fan-out nao aguardado): se contasse,
        # todo scan deep seguraria o mundo inteiro pelo caso E.
        self.assertNotIn('deep_port_queue', q)
        self.assertNotIn('initiate_scan_queue', q)
        for name in q:
            self.assertFalse(name.startswith('send_'), f'{name} nao bloqueia fase')


class InspectClusterTests(unittest.TestCase):
    """Resposta PARCIAL tem que ser 'nao sei', nunca prova de fila orfa."""

    def _inspector(self, queues, active, reserved, ping):
        m = patch('Suricatoos.tasks.app.control.inspect')
        insp = m.start()
        self.addCleanup(m.stop)
        insp.return_value.active_queues.return_value = queues
        insp.return_value.active.return_value = active
        insp.return_value.reserved.return_value = reserved
        insp.return_value.ping.return_value = ping
        return insp

    def test_none_reply_raises(self):
        self._inspector(None, None, None, None)
        with self.assertRaises(RuntimeError):
            _inspect_cluster()

    def test_partial_reply_raises(self):
        # w2 respondeu ao ping (feito por ultimo) mas nao ao active_queues (feito antes):
        # prova de que a foto estava incompleta. Sem esta checagem, as filas de w2
        # pareceriam orfas e um cluster saudavel viraria CRITICAL + hold de 24h.
        self._inspector(
            queues={'w1': [{'name': 'main_scan_queue'}]},
            active={'w1': []}, reserved={'w1': []},
            ping={'w1': {'ok': 'pong'}, 'w2': {'ok': 'pong'}})
        with self.assertRaises(RuntimeError) as ctx:
            _inspect_cluster()
        self.assertIn('parcial', str(ctx.exception))

    def test_complete_reply_returns_consumed_and_live_ids(self):
        self._inspector(
            queues={'w1': [{'name': 'main_scan_queue'}, {'name': 'coordinator_queue'}]},
            active={'w1': [{'id': 'task-a'}]}, reserved={'w1': [{'id': 'task-b'}]},
            ping={'w1': {'ok': 'pong'}})
        out = _inspect_cluster()
        self.assertEqual(out['consumed'], {'main_scan_queue', 'coordinator_queue'})
        self.assertEqual(out['live_ids'], {'task-a', 'task-b'})


class FitTests(unittest.TestCase):
    def test_truncates_to_the_column_width(self):
        # ScanHistory.error_message e CharField(max_length=300): passar disso viraria erro
        # de banco DENTRO do abort — o abort falharia por causa da propria mensagem.
        self.assertEqual(len(_fit('x' * 500)), 300)
        self.assertEqual(_fit('curto'), 'curto')


class DecisionTableTests(TestCase):
    def setUp(self):
        from targetApp.models import Domain
        from scanEngine.models import EngineType
        from startScan.models import ScanHistory
        self.ScanHistory = ScanHistory
        self.domain = Domain.objects.create(name='example.com')
        self.engine = EngineType.objects.create(engine_name='t', yaml_configuration='{}')
        revoke = patch('Suricatoos.tasks.app.control.revoke')
        revoke.start()
        self.addCleanup(revoke.stop)

    def _scan(self, age_s, celery_ids=None):
        return self.ScanHistory.objects.create(
            domain=self.domain, scan_type=self.engine,
            start_scan_date=timezone.now() - timedelta(seconds=age_s),
            scan_status=RUNNING_TASK, celery_ids=celery_ids or [])

    def _probe(self, consumed=None, live_ids=None):
        return {'consumed': consumed if consumed is not None else _pipeline_queues(),
                'live_ids': live_ids or set(), 'workers': ['w1']}

    # ---------------- caso A ----------------
    def test_A_live_task_is_never_aborted(self):
        scan = self._scan(age_s=40000, celery_ids=['live-1'])
        with patch('Suricatoos.tasks._inspect_cluster',
                   return_value=self._probe(live_ids={'live-1'})), \
             patch('Suricatoos.tasks._queue_depth', return_value=0):
            self.assertEqual(hang_monitor(), 0)
        scan.refresh_from_db()
        self.assertEqual(scan.scan_status, RUNNING_TASK)

    # ---------------- caso B ----------------
    def test_B_probe_unavailable_holds_instead_of_aborting(self):
        scan = self._scan(age_s=HANG_MONITOR_STALE_AFTER + 600)
        with patch('Suricatoos.tasks._inspect_cluster', side_effect=RuntimeError('sem broker')):
            self.assertEqual(hang_monitor(), 0)
        scan.refresh_from_db()
        self.assertEqual(scan.scan_status, RUNNING_TASK)
        self.assertTrue(scan.error_message.startswith(HANG_MONITOR_HOLD_PREFIX))

    def test_B_hold_is_bounded_and_eventually_aborts(self):
        # Segurar nao pode virar "nunca abortar" — era um buraco pre-existente: o
        # `except: continue` fazia um inspect quebrado significar monitor inerte.
        scan = self._scan(age_s=HANG_MONITOR_INFRA_ABORT_AFTER + 3600)
        with patch('Suricatoos.tasks._inspect_cluster', side_effect=RuntimeError('sem broker')):
            self.assertEqual(hang_monitor(), 1)
        scan.refresh_from_db()
        self.assertEqual(scan.scan_status, ABORTED_TASK)

    # ---------------- caso C ----------------
    def test_C_orphan_queue_with_pending_message_is_held(self):
        scan = self._scan(age_s=HANG_MONITOR_STALE_AFTER + 600)
        consumed = _pipeline_queues() - {'coordinator_queue'}
        with patch('Suricatoos.tasks._inspect_cluster', return_value=self._probe(consumed)), \
             patch('Suricatoos.tasks._queue_depth',
                   side_effect=lambda q: 2 if q == 'coordinator_queue' else 0):
            self.assertEqual(hang_monitor(), 0)
        scan.refresh_from_db()
        self.assertEqual(scan.scan_status, RUNNING_TASK)
        self.assertIn('coordinator_queue', scan.error_message)

    # ---------------- caso D ----------------
    def test_D_orphan_and_empty_queue_aborts_naming_the_cause(self):
        # acks_late=False: a fase morreu com o worker. Segurar prometeria uma retomada
        # que nao viria — este e o cenario REAL dos scans 66/67/68.
        scan = self._scan(age_s=HANG_MONITOR_STALE_AFTER + 600)
        consumed = _pipeline_queues() - {'coordinator_queue'}
        with patch('Suricatoos.tasks._inspect_cluster', return_value=self._probe(consumed)), \
             patch('Suricatoos.tasks._queue_depth', return_value=0):
            self.assertEqual(hang_monitor(), 1)
        scan.refresh_from_db()
        self.assertEqual(scan.scan_status, ABORTED_TASK)
        self.assertIn('coordinator_queue', scan.error_message)
        self.assertNotIn('no scan activity within budget', scan.error_message)

    def test_D_unknown_depth_is_not_read_as_empty(self):
        # Precedencia: >0 vence, depois desconhecida, e so entao 0. Uma profundidade que
        # nao consegui medir jamais pode ser lida como "fila vazia" e virar abort.
        scan = self._scan(age_s=HANG_MONITOR_STALE_AFTER + 600)
        consumed = _pipeline_queues() - {'coordinator_queue'}
        with patch('Suricatoos.tasks._inspect_cluster', return_value=self._probe(consumed)), \
             patch('Suricatoos.tasks._queue_depth', return_value=None):
            self.assertEqual(hang_monitor(), 0)
        scan.refresh_from_db()
        self.assertEqual(scan.scan_status, RUNNING_TASK)

    # ---------------- caso E ----------------
    def test_E_backlog_with_healthy_consumers_is_not_a_wedge(self):
        # O conserto principal: fila COM consumidor mas saturada era indistinguivel de
        # cunha para o monitor antigo, que abortava — e agora com uma frase mais
        # confiante que a antiga. Trocaria uma mentira vaga por uma categorica.
        scan = self._scan(age_s=HANG_MONITOR_STALE_AFTER + 600)
        with patch('Suricatoos.tasks._inspect_cluster', return_value=self._probe()), \
             patch('Suricatoos.tasks._queue_depth',
                   side_effect=lambda q: 7 if q == 'main_scan_queue' else 0):
            self.assertEqual(hang_monitor(), 0)
        scan.refresh_from_db()
        self.assertEqual(scan.scan_status, RUNNING_TASK)
        self.assertTrue(scan.error_message.startswith(HANG_MONITOR_HOLD_PREFIX))

    # ---------------- caso F ----------------
    def test_F_genuine_wedge_still_aborts_with_the_original_message(self):
        scan = self._scan(age_s=HANG_MONITOR_STALE_AFTER + 600)
        with patch('Suricatoos.tasks._inspect_cluster', return_value=self._probe()), \
             patch('Suricatoos.tasks._queue_depth', return_value=0):
            self.assertEqual(hang_monitor(), 1)
        scan.refresh_from_db()
        self.assertEqual(scan.scan_status, ABORTED_TASK)
        self.assertIn('no scan activity within budget', scan.error_message)

    # ---------------- limpeza do hold ----------------
    def test_hold_message_is_cleared_once_the_scan_progresses(self):
        # Sem isto, um scan segurado que retoma e depois falha por outro motivo exibiria
        # "bloqueado por infra" como causa — a mesma atribuicao errada que esta mudanca
        # existe para eliminar.
        from startScan.models import ScanActivity
        scan = self._scan(age_s=40000)
        scan.error_message = f'{HANG_MONITOR_HOLD_PREFIX}: alguma coisa'
        scan.save()
        ScanActivity.objects.create(
            scan_of=scan, title='x', name='x', status=RUNNING_TASK, time=timezone.now())
        with patch('Suricatoos.tasks._inspect_cluster', return_value=self._probe()), \
             patch('Suricatoos.tasks._queue_depth', return_value=0):
            hang_monitor()
        scan.refresh_from_db()
        self.assertIsNone(scan.error_message)
        self.assertEqual(scan.scan_status, RUNNING_TASK)

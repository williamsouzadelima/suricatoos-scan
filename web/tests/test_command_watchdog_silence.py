"""Watchdog de comando: mata por SILENCIO, nao por duracao.

Medido em producao em 28/07/2026, com o watchdog contando tempo total:
  - `naabu`  cortado em 26 de 26 scans
  - `dalfox` cortado em 13 de 13 scans
  - `nuclei` cortado 65 vezes em 12 scans
e os scans reportando SUCESSO. No scan 74 o dalfox morreu deixando 2 bytes de
saida — um `[`, array JSON aberto — e a fase fechou verde com "zero XSS".

E o mesmo modo de falha que fez 28 das 29 execucoes do SpiderFoot falharem em
silencio. Diretiva de 27/07/2026: scan saudavel se espera terminar, independente
do tempo. Demora nao e sintoma; SILENCIO e.

Os testes usam relogio real com prazos curtos, porque threading.Timer nao aceita
relogio injetado. `os.killpg` e interceptado — sem isso o teste mata a si mesmo.

Run with:  python3 manage.py test tests.test_command_watchdog_silence
"""
import time
import unittest
from unittest.mock import patch

from Suricatoos.tasks import _arm_command_watchdog, _beat_watchdog
from Suricatoos.definitions import WATCHDOG_MARKER, WATCHDOG_MARKER_EXPECTED


class ProcFalso:
    """Processo que nunca termina sozinho (poll() -> None), com pid ficticio."""

    pid = 999999

    def __init__(self, vivo=True):
        self._vivo = vivo
        self.morto = False

    def poll(self):
        return None if self._vivo else 0

    def kill(self):
        self.morto = True


class WatchdogSilencioTests(unittest.TestCase):
    def _arma(self, proc, timeout, ceiling=None, poll=0.1):
        # getpgid/killpg interceptados: o pid e ficticio e um killpg real seria
        # catastrofico dentro da suite.
        self._killpg = patch('Suricatoos.tasks.os.killpg').start()
        patch('Suricatoos.tasks.os.getpgid', return_value=ProcFalso.pid).start()
        self.addCleanup(patch.stopall)
        return _arm_command_watchdog(proc, timeout, ceiling=ceiling, poll=poll)

    def test_ferramenta_que_produz_saida_nao_e_morta(self):
        # O caso do naabu/nuclei/dalfox: roda MUITO alem do orcamento, mas produzindo.
        proc = ProcFalso()
        handle, state = self._arma(proc, timeout=0.5, ceiling=10)
        fim = time.monotonic() + 2.0        # 4x o orcamento de silencio
        while time.monotonic() < fim:
            _beat_watchdog(state)           # cada linha de saida bate aqui
            time.sleep(0.05)
        handle.cancel()
        self.assertFalse(state['timed_out'],
                         'ferramenta saudavel que produzia saida foi morta')
        self._killpg.assert_not_called()

    def test_ferramenta_em_silencio_e_morta(self):
        proc = ProcFalso()
        handle, state = self._arma(proc, timeout=0.4, ceiling=10)
        time.sleep(1.2)
        handle.cancel()
        self.assertTrue(state['timed_out'])
        self.assertIn('sem saida', state['reason'])

    def test_teto_absoluto_pega_ferramenta_tagarela_presa(self):
        # O caso oposto: laco preso cuspindo saida para sempre nunca ficaria em
        # silencio. Sem teto, seguraria um slot do prefork — a cunha do scan #28.
        proc = ProcFalso()
        handle, state = self._arma(proc, timeout=0.4, ceiling=1.0)
        fim = time.monotonic() + 2.5
        while time.monotonic() < fim and not state['timed_out']:
            _beat_watchdog(state)
            time.sleep(0.05)
        handle.cancel()
        self.assertTrue(state['timed_out'], 'teto absoluto nao disparou')
        self.assertIn('teto absoluto', state['reason'])

    def test_sem_teto_explicito_o_teto_e_o_proprio_orcamento(self):
        # Chamador que passa orcamento apertado de proposito (chunk UDP 2700s,
        # theHarvester 600s) NAO pode ganhar teto generoso: _deep_udp_sweep calcula
        # lock_ttl a partir do chunk, e alargar faria o lock expirar no meio do sweep.
        proc = ProcFalso()
        handle, state = self._arma(proc, timeout=0.4, ceiling=None)
        fim = time.monotonic() + 1.5
        while time.monotonic() < fim and not state['timed_out']:
            _beat_watchdog(state)
            time.sleep(0.05)
        handle.cancel()
        self.assertTrue(state['timed_out'])
        self.assertIn('teto absoluto', state['reason'])

    def test_timeout_zero_nao_arma_nada(self):
        proc = ProcFalso()
        for t in (0, None, -1):
            with self.subTest(timeout=t):
                handle, state = _arm_command_watchdog(proc, t)
                self.assertIsNone(handle)
                self.assertFalse(state['timed_out'])

    def test_processo_que_termina_sozinho_nao_e_morto(self):
        proc = ProcFalso(vivo=False)     # poll() != None desde o inicio
        handle, state = self._arma(proc, timeout=0.3, ceiling=10)
        time.sleep(0.9)
        handle.cancel()
        self.assertFalse(state['timed_out'])
        self._killpg.assert_not_called()

    def test_cancel_impede_disparo_posterior(self):
        proc = ProcFalso()
        handle, state = self._arma(proc, timeout=0.3, ceiling=10)
        handle.cancel()
        time.sleep(0.9)
        self.assertFalse(state['timed_out'], 'watchdog disparou apos cancel()')

    def test_beat_em_watchdog_inexistente_nao_explode(self):
        # timeout=0 devolve state sem timer; o leitor bate nele do mesmo jeito.
        _beat_watchdog(None)
        _beat_watchdog({'last_output': 0})


class MarcadoresTests(unittest.TestCase):
    def test_marcadores_sao_disjuntos(self):
        # Se um fosse prefixo do outro, `output__contains=WATCHDOG_MARKER` casaria os
        # dois e a contagem de truncamento misturaria desenho com defeito.
        self.assertNotIn(WATCHDOG_MARKER, WATCHDOG_MARKER_EXPECTED)
        self.assertNotIn(WATCHDOG_MARKER_EXPECTED, WATCHDOG_MARKER)

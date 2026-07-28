"""Barreira de orquestracao: prazo SEM PROGRESSO, nao tempo total.

Diretiva de 27/07/2026: scan saudavel se espera terminar, independente do tempo.
Existem varreduras que demoram muito de verdade, e demora nao e sintoma de
travamento — a AUSENCIA DE PROGRESSO e.

Antes o prazo era wall-clock puro: com o orcamento em 5100s neste host, um fan-out
que precisasse de mais que isso tinha os filhos restantes SIGKILLados e o scan
reportava SUCESSO com resultado parcial, sem nada visivel ao usuario.

A protecao original (cunha do scan #28: filho preso segurando slot do prefork e
travando a fila) continua — so dispara pelo sintoma certo.

Run with:  python3 manage.py test tests.test_orchestration_barrier_progress
"""
import unittest
from unittest.mock import patch

from Suricatoos.tasks import join_group_with_timeout


class GrupoFalso:
    """GroupResult minimo: `pronto_em` passos de poll, `avanca` = concluidos por passo."""

    def __init__(self, pronto_em, avanca=0, completed_raises=False):
        self.pronto_em = pronto_em
        self.avanca = avanca
        self.completed_raises = completed_raises
        self.passos = 0
        self.revogado = False

    def ready(self):
        pronto = self.passos >= self.pronto_em
        self.passos += 1
        return pronto

    def completed_count(self):
        if self.completed_raises:
            raise RuntimeError('backend fora do ar')
        return self.passos * self.avanca

    def revoke(self, **kwargs):
        self.revogado = True


class RelogioFalso:
    """time.monotonic controlado: cada sleep(poll) avanca poll segundos."""

    def __init__(self):
        self.t = 0.0

    def monotonic(self):
        return self.t

    def sleep(self, s):
        self.t += s


class BarreiraProgressoTests(unittest.TestCase):
    def _roda(self, grupo, timeout=100, poll=5):
        relogio = RelogioFalso()
        with patch('Suricatoos.tasks.time.monotonic', relogio.monotonic), \
             patch('Suricatoos.tasks.time.sleep', relogio.sleep):
            ok = join_group_with_timeout(grupo, label='teste', timeout=timeout, poll=poll)
        return ok, relogio.t

    def test_lento_mas_progredindo_nunca_e_morto(self):
        # 400 passos de poll = 2000s de relogio, MUITO alem do timeout de 100s.
        # Como um filho conclui a cada passo, o prazo renova e o grupo termina inteiro.
        grupo = GrupoFalso(pronto_em=400, avanca=1)
        ok, decorrido = self._roda(grupo, timeout=100, poll=5)
        self.assertTrue(ok, 'grupo saudavel porem lento foi interrompido')
        self.assertFalse(grupo.revogado)
        self.assertGreater(decorrido, 100, 'o teste precisa exceder o timeout para valer')

    def test_travado_sem_progresso_ainda_e_morto(self):
        # Protecao da cunha do scan #28: nenhum filho conclui, nunca fica pronto.
        grupo = GrupoFalso(pronto_em=10**9, avanca=0)
        ok, _ = self._roda(grupo, timeout=100, poll=5)
        self.assertFalse(ok)
        self.assertTrue(grupo.revogado, 'grupo travado deveria ter sido revogado')

    def test_progride_e_depois_trava(self):
        # Avanca ate o passo 10 e congela: tem de morrer, mas so apos o prazo
        # contado A PARTIR do ultimo progresso.
        class ProgridePara(GrupoFalso):
            def completed_count(self):
                return min(self.passos, 10)
        grupo = ProgridePara(pronto_em=10**9)
        ok, decorrido = self._roda(grupo, timeout=100, poll=5)
        self.assertFalse(ok)
        self.assertTrue(grupo.revogado)
        self.assertGreater(decorrido, 100, 'prazo deve reiniciar a cada progresso')

    def test_backend_quebrado_nao_renova_prazo_para_sempre(self):
        # Se completed_count() falhar, isso NAO pode contar como progresso — senao um
        # backend fora do ar tornaria a barreira inoperante.
        grupo = GrupoFalso(pronto_em=10**9, completed_raises=True)
        ok, _ = self._roda(grupo, timeout=100, poll=5)
        self.assertFalse(ok)
        self.assertTrue(grupo.revogado)

    def test_timeout_zero_espera_para_sempre(self):
        # Sentinela legado preservado: 0 = sem barreira.
        grupo = GrupoFalso(pronto_em=50, avanca=0)
        ok, _ = self._roda(grupo, timeout=0, poll=5)
        self.assertTrue(ok)
        self.assertFalse(grupo.revogado)

    def test_grupo_ja_pronto_nao_bloqueia(self):
        grupo = GrupoFalso(pronto_em=0)
        ok, decorrido = self._roda(grupo, timeout=100, poll=5)
        self.assertTrue(ok)
        self.assertEqual(decorrido, 0)

    def test_completed_count_nao_numerico_nao_derruba_a_fase(self):
        # Regressao real: a sonda devolvia MagicMock nos testes existentes e o `>`
        # estourava TypeError DENTRO da task da fase — o que derrubaria port_scan /
        # osint / nuclei_scan inteiros. Sonda invalida vira "sem progresso", nunca
        # excecao.
        class SondaEstranha(GrupoFalso):
            def completed_count(self):
                return object()
        grupo = SondaEstranha(pronto_em=10**9)
        ok, _ = self._roda(grupo, timeout=100, poll=5)
        self.assertFalse(ok)
        self.assertTrue(grupo.revogado)

"""Chave do cofre precisa CHEGAR nas configs das ferramentas.

Medido em producao em 28/07/2026: o cofre tinha 5 provedores e NENHUM havia chegado
ao theHarvester. `intelx` e `shodan` estavam no mapa de propagacao e mesmo assim
faltavam — `propagate_vault_key` so roda quando a chave e SALVA na tela, e elas
foram cadastradas antes de esse mecanismo existir. `netlas` e `chaos` sequer
estavam mapeados, apesar de serem fonte do subfinder (`subfinder -ls` lista
`netlas *` e `chaos *`) e o netlas tambem do theHarvester.

Efeito: o theHarvester pulava 19 fontes por falta de chave em TODA execucao, com as
chaves sentadas no banco, e a aba OSINT do scan 74 veio com 2 linhas.

Run with:  python3 manage.py test tests.test_provider_key_reconcile
"""
import os
import tempfile

from django.core.management import call_command
from django.test import TestCase, override_settings

from dashboard.models import ApiCredential
from scanEngine.provider_keys import (VAULT_TOOL_PROPAGATION, get_subfinder_key,
                                      get_theharvester_key)


def _tmp(nome):
    d = tempfile.mkdtemp()
    return os.path.join(d, nome)


class MapaDePropagacaoTests(TestCase):
    def test_netlas_e_chaos_estao_mapeados(self):
        # Regressao: ambos ficaram meses no cofre marcados `consumer:recon`, um
        # rotulo generico sem propagacao nenhuma ligada por tras.
        self.assertEqual(VAULT_TOOL_PROPAGATION.get('netlas'), ('netlas', 'netlas'))
        self.assertEqual(VAULT_TOOL_PROPAGATION.get('chaos'), ('chaos', None))

    def test_todo_destino_de_subfinder_e_nome_valido(self):
        # Nome invalido escreveria uma chave que o subfinder ignora em silencio.
        for slug, (sf, th) in VAULT_TOOL_PROPAGATION.items():
            for destino in (sf, th):
                if destino:
                    with self.subTest(slug=slug, destino=destino):
                        self.assertRegex(destino, r'^[A-Za-z0-9_]+$')


@override_settings(SUBFINDER_PROVIDER_CONFIG_PATH=_tmp('provider-config.yaml'),
                   THEHARVESTER_API_KEYS_PATH=_tmp('api-keys.yaml'))
class ReconciliacaoTests(TestCase):
    def setUp(self):
        ApiCredential.upsert('intelx', 'chave-intelx')
        ApiCredential.upsert('netlas', 'chave-netlas')
        ApiCredential.upsert('chaos', 'chave-chaos')
        ApiCredential.upsert('openai', 'chave-openai')      # sem consumidor de recon

    def test_dry_run_nao_grava(self):
        call_command('reconcile_provider_keys')
        self.assertIsNone(get_theharvester_key('intelx'))
        self.assertIsNone(get_subfinder_key('netlas'))

    def test_apply_propaga_para_os_dois_destinos(self):
        call_command('reconcile_provider_keys', '--apply')
        # intelx e netlas vao para subfinder E theHarvester
        self.assertEqual(get_subfinder_key('intelx'), 'chave-intelx')
        self.assertEqual(get_theharvester_key('intelx'), 'chave-intelx')
        self.assertEqual(get_subfinder_key('netlas'), 'chave-netlas')
        self.assertEqual(get_theharvester_key('netlas'), 'chave-netlas')
        # chaos so tem consumidor no subfinder
        self.assertEqual(get_subfinder_key('chaos'), 'chave-chaos')
        self.assertIsNone(get_theharvester_key('chaos'))

    def test_e_idempotente(self):
        # Precisa poder rodar no boot sem efeito colateral.
        call_command('reconcile_provider_keys', '--apply')
        antes = (get_subfinder_key('netlas'), get_theharvester_key('netlas'))
        call_command('reconcile_provider_keys', '--apply')
        self.assertEqual((get_subfinder_key('netlas'), get_theharvester_key('netlas')),
                         antes)

    def test_provedor_sem_consumidor_nao_vira_chave_orfa(self):
        # `openai` e LLM, nao fonte de recon: nao pode acabar no config do subfinder.
        call_command('reconcile_provider_keys', '--apply')
        self.assertIsNone(get_subfinder_key('openai'))
        self.assertIsNone(get_theharvester_key('openai'))

    def test_valor_vazio_no_cofre_e_pulado(self):
        ApiCredential.upsert('shodan', '   ')
        call_command('reconcile_provider_keys', '--apply')
        self.assertIsNone(get_subfinder_key('shodan'))

    def test_comando_nunca_imprime_o_valor_da_chave(self):
        from io import StringIO
        out = StringIO()
        call_command('reconcile_provider_keys', '--apply', stdout=out)
        saida = out.getvalue()
        for segredo in ('chave-intelx', 'chave-netlas', 'chave-chaos', 'chave-openai'):
            self.assertNotIn(segredo, saida)

"""Porta de evidencia do juiz de falso-positivo.

Medido em producao em 27/07/2026: os 234 XSS do dalfox (88% da contagem que o
cliente ve) tinham ZERO campo discriminante — sem response, sem extracted_results,
sem matcher_name, sem template_id. O prompt era de tres linhas:

    name: XSS (Cross Site Scripting)
    severity: 2
    http_url: https://.../hbss?onpointermove=confirm%281%29...

E o modelo respondeu "The response body contains a specific exploited payload
indicative of XSS vulnerability" com confidence 1.00 — inventando um corpo de
resposta que nao estava no prompt.

Um juiz que alucina e pior que nenhum juiz: um "real" com confianca fabricada e
mais dificil de desconfiar do que um campo vazio.

Run with:  python3 manage.py test tests.test_llm_fp_judge
"""
import unittest
from unittest.mock import patch

from Suricatoos.llm import LLMFPJudge


class PortaDeEvidenciaTests(unittest.TestCase):
    def _judge_sem_chamar_llm(self, evidence):
        # Se a porta funcionar, Ollama nunca e instanciado. O mock existe para que
        # uma regressao apareca como chamada indevida, nao como erro de conexao.
        with patch('Suricatoos.llm.Ollama') as ollama:
            veredito = LLMFPJudge().judge(evidence)
        return veredito, ollama

    def test_dalfox_real_sem_evidencia_nao_chega_no_modelo(self):
        # A forma EXATA dos 234 achados do dalfox em producao.
        veredito, ollama = self._judge_sem_chamar_llm({
            'name': 'XSS (Cross Site Scripting)',
            'severity': 2,
            'http_url': 'https://exemplo.com/x?onpointermove=confirm%281%29',
        })
        self.assertEqual(veredito['verdict'], 'needs_review')
        self.assertEqual(veredito['confidence'], 0.0)
        self.assertIn('insufficient_evidence', veredito['reason'])
        ollama.assert_not_called()

    def test_qualquer_campo_discriminante_libera_o_julgamento(self):
        for chave, valor in (
            ('response', '<html>alert(1)</html>'),
            ('extracted_results', ['token=abc']),
            ('matcher_name', 'status-200'),
            ('template_id', 'generic-tokens'),
        ):
            with self.subTest(campo=chave):
                base = {'name': 'X', 'severity': 2, 'http_url': 'https://e.com/'}
                base[chave] = valor
                with patch('Suricatoos.llm.Ollama') as ollama:
                    ollama.return_value.invoke.return_value = (
                        '{"verdict":"real","confidence":0.9,"reason":"ok"}')
                    veredito = LLMFPJudge().judge(base)
                ollama.assert_called_once()
                self.assertEqual(veredito['verdict'], 'real')

    def test_campo_discriminante_vazio_nao_conta(self):
        # String vazia e lista vazia sao ausencia, nao evidencia.
        veredito, ollama = self._judge_sem_chamar_llm({
            'name': 'X', 'severity': 2, 'http_url': 'https://e.com/',
            'response': '', 'extracted_results': [], 'matcher_name': None,
            'template_id': '',
        })
        self.assertEqual(veredito['verdict'], 'needs_review')
        ollama.assert_not_called()

    def test_nome_severidade_url_nunca_sao_discriminantes(self):
        # Trava de projeto: descrevem o que foi TENTADO, nao o que o alvo respondeu.
        for proibido in ('name', 'severity', 'http_url', 'tags', 'cve_ids'):
            with self.subTest(campo=proibido):
                self.assertNotIn(proibido, LLMFPJudge.DISCRIMINATING_KEYS)

    def test_erro_do_modelo_continua_needs_review(self):
        # Regressao: a porta nao pode ter substituido o tratamento de erro do LLM.
        with patch('Suricatoos.llm.Ollama') as ollama:
            ollama.return_value.invoke.side_effect = RuntimeError('conexao caiu')
            veredito = LLMFPJudge().judge({'name': 'X', 'response': '<html>'})
        self.assertEqual(veredito['verdict'], 'needs_review')
        self.assertIn('llm_error', veredito['reason'])

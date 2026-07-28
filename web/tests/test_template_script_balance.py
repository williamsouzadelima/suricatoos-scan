"""Blocos <script> dos templates precisam estar BALANCEADOS.

Em 28/07/2026, ao mover o init da DataTable de Higiene para fora de
`{% if total_vulnerability_count > 0 %}`, o bloco foi extraido pelo PRIMEIRO `});`
— que fecha a DataTable, nao o `.click()`. Isso quebrou dois blocos de uma vez: o
novo ficou com `$(document).ready(` sem fechar e o original ficou com um `});`
orfao. Ambos sao erro de sintaxe, entao os dois blocos morriam inteiros e a aba
abria vazia SEM erro visivel — nenhuma requisicao chegava a ser feita.

A verificacao que falhou na epoca conferiu se a string do handler estava presente.
Estava — dentro de um bloco invalido. PRESENCA NAO E CORRETUDE; por isso aqui se
mede saldo de delimitadores.

Run with:  python3 manage.py test tests.test_template_script_balance
"""
import os
import re
import unittest

BASE = os.path.join(os.path.dirname(__file__), '..')

# Templates com JS inline nao-trivial. Nao varre tudo de proposito: um template de
# terceiro com JS gerado quebraria o teste por motivo que nao e nosso.
TEMPLATES = [
    'startScan/templates/startScan/detail_scan.html',
    'startScan/templates/startScan/history.html',
]


def _sem_tags_django(txt):
    """Remove {% %}, {{ }} e {# #} — carregam chaves que nao sao do JS."""
    txt = re.sub(r'\{%.*?%\}', ' ', txt, flags=re.S)
    txt = re.sub(r'\{\{.*?\}\}', ' ', txt, flags=re.S)
    return re.sub(r'\{#.*?#\}', ' ', txt, flags=re.S)


def saldo_delimitadores(js):
    """Saldo de (), {} e [] ignorando string, template literal e comentario."""
    saldo = {'(': 0, '{': 0, '[': 0}
    fecha = {')': '(', '}': '{', ']': '['}
    i, n, aspas = 0, len(js), None
    while i < n:
        ch = js[i]
        if aspas:
            if ch == '\\':
                i += 2
                continue
            if ch == aspas:
                aspas = None
            i += 1
            continue
        if ch in '"\'`':
            aspas = ch
            i += 1
            continue
        if js.startswith('//', i):
            j = js.find('\n', i)
            i = n if j < 0 else j
            continue
        if js.startswith('/*', i):
            j = js.find('*/', i)
            i = n if j < 0 else j + 2
            continue
        if ch in saldo:
            saldo[ch] += 1
        elif ch in fecha:
            saldo[fecha[ch]] -= 1
        i += 1
    return {k: v for k, v in saldo.items() if v != 0}


class ScriptBalanceTests(unittest.TestCase):
    def test_blocos_script_inline_estao_balanceados(self):
        for rel in TEMPLATES:
            caminho = os.path.join(BASE, rel)
            with open(caminho, encoding='utf-8') as f:
                html = f.read()
            for m in re.finditer(r'<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>',
                                 html, re.S | re.I):
                js = _sem_tags_django(m.group(1))
                linha = html[:m.start()].count('\n') + 1
                with self.subTest(template=rel, linha=linha):
                    self.assertEqual(
                        saldo_delimitadores(js), {},
                        f'{rel}:{linha} tem bloco <script> desbalanceado — '
                        f'JS invalido mata o bloco INTEIRO em silencio')

    def test_o_detector_realmente_pega_o_defeito_de_28_07(self):
        # Prova negativa: sem isto o teste acima poderia estar sempre passando.
        quebrado = "$(document).ready(function() { $('#x').click(function() { });"
        self.assertEqual(saldo_delimitadores(quebrado), {'(': 1, '{': 1})
        orfao = "chart.render()\n});\nconst x = 1;"
        self.assertEqual(saldo_delimitadores(orfao), {'(': -1, '{': -1})
        bom = "$(document).ready(function() { $('#x').click(function() { }); });"
        self.assertEqual(saldo_delimitadores(bom), {})

    def test_chave_dentro_de_string_nao_conta(self):
        self.assertEqual(saldo_delimitadores('var s = "{{{";'), {})
        self.assertEqual(saldo_delimitadores("var s = '(((';"), {})
        self.assertEqual(saldo_delimitadores('// } } }\nvar a = 1;'), {})

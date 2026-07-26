"""http_crawl: loteamento da entrada do httpx, e o invariante de tempo que ele quase quebrou.

Contexto: o httpx recebia a lista INTEIRA de alvos numa unica invocacao. Com ~950 alvos
chegou a 1.96GB de RSS e estourou o `mem_limit: 2g` do container do celery — foi o gatilho
do OOM de 2026-07-22, em que o killer levou junto o coordinator_worker e produziu 3 dias de
scans auto-abortados, e de novo em 26/07 (matando so o httpx). Quem morre junto e sorteio.

O loteamento resolve a memoria, mas cria um risco de TEMPO: o watchdog do stream_command
vale POR COMANDO, entao N lotes multiplicariam o teto por N e a propria task seria SIGKILLada
pelo celery no meio — trocando um problema por outro, e derrubando a fase chamadora
(http_crawl roda DENTRO de subdomain_discovery). Estes testes travam os dois lados.

Run with:  python3 manage.py test tests.test_http_crawl_batching
"""
import inspect
import unittest

from Suricatoos import tasks
from Suricatoos.definitions import (HTTP_CRAWL_BATCH_SIZE, DEFAULT_COMMAND_EXEC_TIMEOUT)
from Suricatoos.settings import CELERY_TASK_TIME_LIMIT, CELERY_TASK_SOFT_TIME_LIMIT


class BatchSizeTests(unittest.TestCase):
    def test_batch_size_is_bounded_and_sane(self):
        # O ponto e limitar o pico de memoria: um lote grande demais nao limita nada.
        # ~950 alvos -> 1.96GB observados, logo ~2MB/alvo; 150 alvos ~ 300MB de pico.
        self.assertGreater(HTTP_CRAWL_BATCH_SIZE, 0)
        self.assertLessEqual(HTTP_CRAWL_BATCH_SIZE, 500,
                             'lote grande demais nao limita o pico que causou o OOM')

    def test_batching_covers_every_url_exactly_once(self):
        urls = [f'https://h{i}.example.com' for i in range(1000)]
        n = HTTP_CRAWL_BATCH_SIZE
        batches = [urls[i:i + n] for i in range(0, len(urls), n)]
        flat = [u for b in batches for u in b]
        self.assertEqual(flat, urls, 'nem perde nem duplica alvo')
        self.assertTrue(all(len(b) <= n for b in batches))


class TimeBudgetInvariantTests(unittest.TestCase):
    """definitions.py documenta: watchdog < soft < hard. Lotear nao pode violar isso."""

    def test_documented_invariant_still_holds(self):
        self.assertLess(DEFAULT_COMMAND_EXEC_TIMEOUT, CELERY_TASK_SOFT_TIME_LIMIT)
        self.assertLess(CELERY_TASK_SOFT_TIME_LIMIT, CELERY_TASK_TIME_LIMIT)

    def test_dynamic_share_never_exceeds_the_remaining_budget(self):
        # Fatia dinamica: o que os lotes rapidos nao usam flui para os seguintes, mas o
        # total nunca passa do orcamento de UMA invocacao.
        for n in (1, 2, 7, 20, 100):
            remaining = float(DEFAULT_COMMAND_EXEC_TIMEOUT)
            for idx in range(1, n + 1):
                if remaining < 1:
                    break
                share = max(60, int(remaining // (n - idx + 1)))
                t = max(1, int(min(share, remaining)))
                self.assertGreaterEqual(t, 1, 'nunca pode virar o sentinela 0')
                self.assertLessEqual(t, remaining + 1)
                remaining -= t
            self.assertGreaterEqual(remaining, -1,
                                    f'com {n} lotes o total estourou o orcamento')

    def test_stream_command_receives_an_explicit_bounded_timeout(self):
        # Sem timeout explicito cada lote herdaria o watchdog CHEIO e N lotes
        # multiplicariam o teto. E o valor NUNCA pode truncar para 0, que e o sentinela
        # "sem watchdog" — seria a mesma regressao por outra porta.
        src = inspect.getsource(tasks.http_crawl)
        self.assertIn('timeout=batch_timeout', src)
        self.assertIn('max(1, int(min(share, remaining)))', src)
        self.assertIn('if remaining < 1:', src,
                      'guard tem que ser < 1, senao int() trunca para o sentinela 0')

    def test_zero_timeout_sentinel_is_honored(self):
        # 0 significa "sem watchdog" (definitions.py / _arm_command_watchdog). Somar 0 a
        # agora daria um prazo JA VENCIDO e o crawl retornaria sem sondar nada — pior,
        # com endpoint_ids vazio o remove_duplicate_endpoints rodaria SEM filtro, sobre o
        # scan inteiro. Mesmo molde de join_group_with_timeout, neste arquivo.
        src = inspect.getsource(tasks.http_crawl)
        self.assertIn('if DEFAULT_COMMAND_EXEC_TIMEOUT and DEFAULT_COMMAND_EXEC_TIMEOUT > 0 else None', src)
        self.assertIn('if crawl_deadline is None:', src)
        self.assertIn('time.monotonic()', src, 'relogio de parede pode saltar com NTP')

    def test_dedup_is_skipped_when_nothing_was_crawled(self):
        # remove_duplicate_endpoints faz `if filter_ids:` e lista vazia e FALSY: sem este
        # guard a limpeza rodaria sem filtro, apagando endpoints de outras fases.
        src = inspect.getsource(tasks.http_crawl)
        self.assertIn('should_remove_duplicate_endpoints and endpoint_ids', src)

    def test_global_deadline_stops_starting_new_batches(self):
        src = inspect.getsource(tasks.http_crawl)
        self.assertIn('crawl_deadline', src)
        self.assertIn('if remaining < 1:', src,
                      'precisa parar de iniciar lotes quando o orcamento acabar')
        self.assertIn('nao processado', src,
                      'a interrupcao tem que ser VISIVEL no log, nao silenciosa')


class BatchCommandTests(unittest.TestCase):
    def test_inline_u_only_for_a_single_target_crawl(self):
        # O atalho inline vale SO quando o crawl inteiro e de um alvo — o gatilho
        # original. Estende-lo a "qualquer lote de 1" o tornaria alcancavel por lote-resto
        # de URLs vindas do banco/gau, e uma aspa nelas estoura o shlex.split.
        src = inspect.getsource(tasks.http_crawl)
        self.assertIn('if len(batches) == 1 and len(batch) == 1:', src)

    def test_batch_files_are_cleaned_up(self):
        # A limpeza no fim so remove input_path; os `.1..N` ficariam para tras.
        src = inspect.getsource(tasks.http_crawl)
        self.assertIn('os.remove(batch_path)', src)

    def test_threads_are_scaled_to_the_batch_not_the_whole_list(self):
        src = inspect.getsource(tasks.http_crawl)
        self.assertIn('batch_threads = min(threads, len(batch))', src)

    def test_batching_is_behaviour_neutral_wrt_excluded_paths(self):
        # Os lotes saem da lista PRE-filtragem, que e o que o httpx efetivamente recebia
        # (o arquivo era escrito antes de exclude_urls_by_patterns). Fazer sair da lista
        # filtrada PARECE correcao, mas exclude_urls_by_patterns casa contra a string
        # inteira e subdomain_discovery passa HOSTNAMES NUS: `.*\.ico` casaria com
        # `www.icons.example.com`, e digitar `admin` mataria `admin.example.com` do crawl.
        # Um conserto de memoria nao pode carregar essa mudanca de cobertura junto.
        src = inspect.getsource(tasks.http_crawl)
        self.assertIn('crawl_targets = list(urls)', src)
        self.assertIn('crawl_targets[i:i + batch_size]', src)
        i_capture = src.index('crawl_targets = list(urls)')
        i_exclude = src.index('urls = exclude_urls_by_patterns')
        self.assertLess(i_capture, i_exclude,
                        'a captura tem que ser ANTES da filtragem')

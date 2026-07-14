# Onda 3 — Performance (N+1 / índices)

Branch `fix/audit-wave3-performance`. Terceira onda do programa de excelência
(`audit-2026-07-04-roadmap.md`). Recon adversarial confirmou os 6 achados no código atual
antes de otimizar.

## Postura de risco

Django/PG não rodam no mac → correção de ORM é verificada por **`assertNumQueries` + valores
fixados no CI** (que roda agora que os PRs miram `main`). Esta onda entrega o que é
**output-invariante** (eager-loading, índices, consolidação de aggregate) com alta confiança,
e **defere** as reescritas que mudam como um valor é computado/o contrato de saída, porque
exigem verificação contra um banco real (correção de contagem num produto de segurança não se
chuta).

## Entregue nesta onda (output-invariante / seguro)

| # | Achado | O que foi feito |
|---|---|---|
| 20 | Falta de índices | `Meta.indexes` + migração 0010: `severity`, `validation_status`, compostos `(target_domain,severity)`/`(scan_history,severity)`, `subdomain.name` |
| 17 | VulnerabilitySerializer depth=2 N+1 | `select_related` de todas as FKs + `prefetch_related` dos M2M no `VulnerabilityViewSet.get_queryset` (cobre inclusive os M2M lidos por `model_to_dict`) |
| 16 (HIGH) | SubdomainSerializer | `prefetch_related` dos M2M aninhados (ip_addresses+ports/technologies/waf/directories+directory_files) + **Subquery annotations** substituindo os 7 COUNTs por-linha (5 severidades + endpoint + subscan). Falta só o hoist do `is_interesting` (Onda 3b) |
| 19 (completo) | ListTargetsDatatableViewSet | `select_related('project','domain_info')` + `prefetch_related('domains')` (get_organization lê o cache) + `annotate(vuln_count=Count distinct, recent_scan_id=Max)` — corrige o bug do `vuln_count` sempre `None` |
| 18 | ListScanHistory | `select_related('domain','domain__project','initiated_by')` |
| 21 | Dashboard ~13 COUNTs | 6 counts de severidade → 1 `aggregate` (campo local, valores idênticos) |

Todos os nomes de relação foram **conferidos nos models** (um nome errado em
`select_related`/`prefetch_related` = `FieldError`/500). Smoke test em `test_access_control`
(`test_eager_loaded_lists_return_200`) exercita os endpoints otimizados (pega erros de
`select_related`).

## Onda 3b — deferido (muda output/contrato → exige verificação com DB)

Estas otimizações têm o padrão exato já mapeado pelo recon, mas mudam como um valor é
computado (risco de divergência de contagem) ou o contrato da resposta — precisam de
`assertNumQueries` + igualdade de saída contra um dataset real (dup-name, FALSE_POSITIVE) antes
de shipar:

- ~~**#16 (HIGH) — os COUNTs por-linha** (5 severidades + endpoint + subscan)~~ ✅ **CONCLUÍDO**
  (commit posterior): **Subquery annotations** correlacionadas (tradução literal das properties:
  `subdomain__name` + `scan_history` + exclude FALSE_POSITIVE). Method-fields usam a annotation
  SÓ quando o subdomínio tem `scan_history` (via helper `_annotated_or`), com **fallback à
  property** (null-scan raro; subscan incondicional). `directories_count` fica como property
  (subquery nested complexo). **Teste de valor** no endpoint real vs property + valores concretos.
  RESTA só o **hoist do `is_interesting`** (o `scan_id` varia por-linha → precisa de cache
  por-scan no `context`; ~4 queries/linha).
- **#18 — counts por-scan** (subdomain/endpoint/vuln/progress) via annotate `distinct=True` +
  método-fields lendo a annotation; e **paginação** (a resposta é lista pura → mudar p/
  envelope DataTables **muda o contrato**, exige validar o frontend de scan history).
- ~~**#19 — `vuln_count` + `recent_scan_id`**~~ ✅ **CONCLUÍDO** (commit posterior): `annotate(
  vuln_count=Count('vulnerability', filter=~Q(FALSE_POSITIVE), distinct=True),
  recent_scan_id=Max('scanhistory__id'))`. Corrige o bug do `vuln_count` sempre `None` e tira o
  `get_recent_scan_id()` por-linha (get_most_recent_scan lê a annotation via hasattr). Reverse-names
  e tipo de retorno (int) conferidos nos models. #19 agora completo.

## Notas de deploy (gated — não feito aqui)

- Migração 0010 (índices) aplicada no `manage.py migrate` do deploy. `AddIndex` é atômico
  (lock breve); p/ tabela muito grande converter p/ `AddIndexConcurrently` + `atomic=False`.
- Sem mudança de contrato de API nesta onda (só as annotations/paginação da Onda 3b mudam saída).

# Auditoria de excelência — roadmap de correções (2026-07-04)

Auditoria exaustiva e adversarial do score.suricatoos.com (fork reNgine): 12 auditores
por dimensão → cada achado verificado adversarialmente (real? ainda presente? severidade?).
**45 achados brutos → 32 confirmados** (3 HIGH · 17 MEDIUM · 12 LOW). Objetivo: estado da arte.

> **Contexto de tenancy (decisão do William, 2026-07-04):** hoje é **single-org** (só a equipe
> loga; "clientes" são Projects que a equipe gerencia) → os 4 achados "críticos" de isolamento
> cross-cliente foram refutados como **não-vuln hoje**. Mas **multi-tenant é o alvo** → viram
> **Track B (fundacional, pré-lançamento de acesso a cliente)**. O upgrade do Django (EOL) **entra
> no escopo agora** → Track A.

## Ondas de execução

### ✅ Onda 1 — Corretude do núcleo (PR em andamento)
| # | Sev | Achado | Arquivo |
|---|---|---|---|
| 1 | HIGH | `float(cvss)` não-guardado aborta o lote inteiro do import OpenVAS (rows parciais, job trava, achados reais expiram) | tasks.py `import_openvas_findings` |
| 2 | MED | `run_command`: exceção no loop de leitura pula o SIGKILL → grupo de processo órfão (nmap/tool vazado) | tasks.py `run_command` |
| 3 | MED | `report()` sobrescreve `stop_scan_date`/status do ScanHistory pai a cada subscan; e crasha (AttributeError) se scan=None → laço de `link_error` | tasks.py `report` |
| 4 | LOW | `findings_imported` conta pré-dedup → diverge do relatório | tasks.py `import_openvas_findings` |

### ⏳ Onda 2 — Segurança (real hoje)
| # | Sev | Achado | Arquivo |
|---|---|---|---|
| 5 | HIGH | SSRF: guard só valida a origem; WafDetector/CMSDetector seguem 3xx → metadata/interno (bypass) | api/views.py, tasks.py `is_blocked_fetch_target` |
| 6 | MED | Produção servida pelo **dev server** (`runserver`), não gunicorn (já instalado) | entrypoint.sh |
| 7 | MED | Contêineres web/celery rodam como **root** (sem `USER` no Dockerfile) | web/Dockerfile |
| 8 | MED | API DRF sem throttling global (só o login tem rate-limit) | settings.py `REST_FRAMEWORK` |
| 9 | MED | gunicorn 22.0.0 — CVE-2024-6827 (request smuggling); atualizar junto do #6 | requirements.txt |
| 10 | LOW | Bearer do sensor: comparação não-constante (timing); usar `hmac.compare_digest` | api/views.py `SensorFindingsImport` |
| 11 | LOW | Chave privada mTLS gravada world-readable numa janela TOCTOU antes do chmod | openvas_enroll |
| 12 | LOW | DNS-rebinding TOCTOU no `is_blocked_fetch_target` (resolve independente do fetch) | tasks.py |
| 13 | LOW | `UpdateTool`/`UninstallTool` executam comando de tool armazenado via shell sem allowlist (admin) | api/views.py |
| 14 | LOW | Handler genérico devolve `str(exc)` cru em HTTP 500 ao cliente | api/views.py `HackerOneProgramViewSet` |
| 15 | LOW | `ALLOWED_HOSTS` default `['*']` no código | settings.py |

### ⏳ Onda 3 — Performance (N+1 / índices)
| # | Sev | Achado | Arquivo |
|---|---|---|---|
| 16 | HIGH | `SubdomainSerializer`: ~10 COUNTs + 4 M2M por linha, sem prefetch, DataTable de 500 linhas | api |
| 17 | MED | `VulnerabilitySerializer` depth=2 + `get_scan_history` por linha, sem select_related | api |
| 18 | MED | `ListScanHistory` sem paginação + N+1 de contagens por scan | api |
| 19 | MED | `ListTargetsDatatableViewSet`: `Domain.objects.all()` + depth=2 + N+1 | api |
| 20 | LOW | Falta de índice em `Vulnerability.severity`/`validation_status`, `Subdomain.name` | models |
| 21 | LOW | Dashboard index: ~15 COUNTs sequenciais por page-load em campos sem índice | dashboard |

### ⏳ Onda 4 — Testes & CI
| # | Sev | Achado |
|---|---|---|
| 22 | MED | CI (`tests.yml`) roda subconjunto hardcoded — deadlock/orquestração/validação não rodam |
| 23 | MED | Consent gate `send_to_scanner` (push p/ scanner externo) sem teste |
| 24 | MED | Quarentena cross-client em `import_openvas_findings` sem teste |
| 25 | MED | Corpo do import de sensor sem teste; idempotência por `correlation_id` não é tenant-scoped |
| 26 | MED | Orquestração real do loop (submit/poll/import mTLS) sem teste |

### ⏳ Track A (XL, branch próprio) — Upgrade Django 3.2.25 (EOL abr/2024) → 4.2 LTS + DRF ≥3.15 + langchain
Auditoria de breaking changes, migração incremental, suíte verde. Maior gap de "estado da arte".

### ⏳ Track B (XL, design+build, pré-multi-tenant) — Isolamento por tenant
Os 4 "críticos" refutados hoje viram **must-fix antes de abrir login por cliente**: binding
usuário→tenant server-side, authz object-level, scoping de queryset por Project, `IpAddress`
com escopo de tenant, sensor com allowlist de tenant (não payload-controlled).

## Achados refutados (não-issue no contexto atual)
Isolamento cross-cliente / IpAddress global compartilhado / sensor tenant → **não-vuln em single-org**
(Track B cobre quando for multi-tenant). `ctx={}` mutável, `report()` como link_error, alguns mais → refutados.

# Plano — SpiderFoot em host dedicado, integrado por REST

O SpiderFoot antigo (monolito `sf.py`) foi **removido** em `c449a3f`. O motivo está
medido: das 29 execuções que geraram arquivo, **1** produziu `OsintResult` utilizável —
o watchdog matava o processo no meio da escrita, o JSON truncava, `json.load` estourava
e o `except` devolvia `[]`. Falha silenciosa, scan verde.

O fork `poppopjmp/spiderfoot` **não é substituto direto**: `sf.py` não existe desde a
v6.0.0. O que existe é uma plataforma de microserviços com API REST — o que muda a
integração de *subprocess* para *cliente HTTP*.

Este documento é o plano para trazê-lo de volta **em host separado**. Nada aqui está
implantado.

---

## 1. Por que host dedicado

Medição real feita em 28/07/2026, no host do score (172.233.13.124), com **um** scan,
`concurrency=1`, alvo pequeno (`suricatoos.com`):

| Serviço | Repouso | Sob carga |
|---|---:|---:|
| `sf-scan-worker` | — | **1024 MiB** |
| `sf-worker` (core) | 301 MiB | 367 MiB |
| `sf-api` | 204 MiB | 326 MiB |
| postgres | 37 MiB | 39 MiB |
| redis | 12 MiB | 7 MiB |
| **TOTAL** | **554 MiB** | **1760 MiB** |

Durante a medição o host caiu para **633–803 MB disponíveis**. Não houve OOM — mas o
`sf-scan-worker` bateu **exatamente** no `mem_limit` de 1 GB que eu havia posto: ele
queria mais, foi contido. O default do fork para esse serviço é 4 GB.

O host do score tem 3,9 GB e o celery dele sozinho chega a 1,5 GB durante `nuclei_scan`.
Somar ~1,8 GB de SpiderFoot é a mesma aritmética que produziu os OOM dos scans 66/67/68.
Daí o host separado.

**Requisito**: ≥ 4 GB de RAM livres e ≥ 5 GB de disco no host de destino.

---

## 2. Hospedagem

`deploy/spiderfoot/docker-compose.yml` está pronto e dimensionado pela medição acima.

```bash
scp -r deploy/spiderfoot/ root@<HOST>:/opt/spiderfoot/
ssh root@<HOST> 'cd /opt/spiderfoot && cp .env.example .env'
# preencher SF_POSTGRES_PASSWORD e SF_ADMIN_PASSWORD no .env
ssh root@<HOST> 'cd /opt/spiderfoot && docker compose up -d'
```

Imagens são **publicadas** no GHCR (184 MB comprimido cada) — não há build no host.

### Exposição

A API escuta **só em `127.0.0.1:8001`**. Publicar 8001 na interface pública deixaria a
API do SpiderFoot aberta para a internet. O score precisa alcançá-la, então escolha um
dos dois:

- **Túnel SSH** (mais simples, sem certificado): `ssh -N -L 8001:127.0.0.1:8001 <HOST>`
  a partir do host do score, mantido por systemd. Bom para começar.
- **nginx + TLS + mTLS** no host do SpiderFoot, mesmo padrão do `score↔scanner`
  (ADR-0006, que já usa `SURICATOOS_SCANNER_CERT`/`_KEY`/`_CA`). Melhor a prazo, e
  reaproveita ferramental que já existe.

### Armadilha já paga

O worker do *core* escuta `agents/default/export/monitor` — **não** a fila `scan`. Quem
executa varredura é o `sf-scan-worker` (`--queues=scan`), que no fork está atrás do
profile `scan`. Sem ele a tarefa fica parada no redis e o scan **nunca sai de
`CREATED`**. Isso custou uma medição inteira: o primeiro número que obtive (775 MiB
"sob carga") era, na verdade, o sistema ocioso.

---

## 3. Contrato REST — validado ponta a ponta

Sequência testada de verdade na medição, não lida da documentação:

```bash
# 1) autenticar
POST /api/v1/auth/login
     {"username":"...","password":"..."}
  → 200 {"access_token":"eyJ..."}

# 2) criar scan
POST /api/v1/scans            Authorization: Bearer <token>
     {"name":"...","target":"exemplo.com"}
  → 201 {"id":"CEC541F9","status":"STARTING"}

# 3) acompanhar
GET  /api/v1/scans/{id}
  → 200 {"status":"RUNNING","result_count":18,"state_machine":{"is_active":true,...}}

# 4) colher
GET  /api/v1/scans/{id}/events?limit=N
  → 200 [{"type":"IP_ADDRESS","data":"185.158.133.1","module":"sfp_dnsresolve"}, ...]
```

Endpoints úteis: `/api/v1/scans/{id}/modules`, `/api/v1/scans/bulk`.
**Não existe** `/api/v1/scans/{id}/results` — é `/events` (erro que cometi ao testar).

### Estados

`CREATED` → `STARTING` → `RUNNING` → terminal. Um scan em `CREATED` com o worker vivo
significa **fila**, não travamento: com `concurrency=1` o segundo scan espera o
primeiro. Confundi as duas coisas durante a medição e cheguei a acusar a API de
reportar status errado — ela estava certa; eu consultava o scan errado.

---

## 4. Integração no lado do score

### 4.1 Onde entra

Substitui a task `spiderfoot_scan` removida, no `osint_discovery`. Diferença essencial:
**não é subprocess**. A task vira produtor/consumidor HTTP, então precisa de orçamento
de tempo próprio e não pode bloquear um slot do `main_scan_queue` enquanto espera.

Recomendação: fila própria (`osint_external_queue`), como o `deep_port_queue` faz para
o sweep UDP — pelo mesmo motivo, que é não segurar o pipeline.

### 4.2 Mapeamento de evento → `OsintResult`

O `_sf_bucket` do commit `c449a3f` é a referência; vale reler o diff. O modelo
`OsintResult` já tem a forma certa (`bucket`, `event_type`, `data`, `source`,
`is_malicious`, `module`, `confidence`).

Ponto de atenção: o bucket `malicious` era exclusivo do SpiderFoot. Nenhuma outra
ferramenta o alimenta hoje — recuperá-lo é parte do ganho.

`source` deve ser `'spiderfoot'` novamente (hoje o default é `'osint'`), para que a
proveniência fique distinguível do theHarvester. As 92 linhas históricas continuam lá.

### 4.3 Chaves de API

O SpiderFoot tem os próprios provedores. **Não** replicar chave à mão: estender
`VAULT_TOOL_PROPAGATION` (`web/scanEngine/provider_keys.py`) com um terceiro destino,
e o `reconcile_provider_keys` passa a cobri-lo sozinho — inclusive no boot.

Lição recente que justifica isso: até 28/07/2026, `intelx`, `shodan`, `netlas` e `chaos`
estavam no cofre e **nenhum** chegava ao theHarvester, porque a propagação só rodava no
momento do save e não havia backfill. Repetir esse padrão com o SpiderFoot custaria as
mesmas fontes silenciosamente.

### 4.4 Gate de escopo

O SpiderFoot faz requisição externa a terceiros em nome do alvo. O `is_blocked_fetch_target`
já existe no `tasks.py` e deve valer para o alvo antes de qualquer `POST /scans` — mesmo
princípio do gate de scan ativo que já aplicamos.

---

## 5. Verificação depois de implantar

- `docker compose ps` — 5 serviços `Up`, postgres e api `healthy`
- `POST /api/v1/auth/login` → 200
- Scan de teste contra domínio **próprio** (`suricatoos.com`), não de cliente
- `GET /api/v1/scans/{id}` sai de `CREATED` em segundos — se ficar, é a fila `scan` sem
  worker (ver §2)
- `docker stats` sob carga: `sf-scan-worker` **não** deve encostar no teto de 2 GB. Se
  encostar, medir de novo antes de subir o limite
- No score: `OsintResult` com `source='spiderfoot'` e bucket `malicious` voltando a
  aparecer

---

## 6. O que este plano NÃO resolve

- **Custo de host.** É a razão de o SpiderFoot ter ficado fora até aqui, e continua
  sendo uma decisão de infraestrutura, não de código.
- **Qualidade dos achados.** Voltar o SpiderFoot aumenta o volume de OSINT; a curadoria
  por `template_id` (`FINDING_TEMPLATE_CLASS`) cobre nuclei, não eventos do SpiderFoot.
  Se o volume crescer, a taxonomia precisa de um capítulo próprio para eles — senão
  repete-se o problema que a curadoria resolveu: ruído soterrando o que importa.

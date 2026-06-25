# Scan Depth Tiers — Design Spec

**Data:** 2026-06-25
**Status:** aprovado no brainstorming (Seções 1–3); pendente revisão final do usuário antes do plano de implementação.

## Contexto e objetivo

Hoje o Suricatoos tem ~8 scan engines (fixture `web/fixtures/default_scan_engines.yaml`), cada
um com um `yaml_configuration` que define os estágios e parâmetros (ex: `port_scan.ports: ['top-100']`,
tools por estágio, `dir_file_fuzz`, `vulnerability_scan.nuclei.severities`, threads/rate/timeout). As
profundidades são ad-hoc e a maioria usa `top-100` portas.

**Objetivo:** oferecer **3 perfis de profundidade explícitos** que o usuário escolhe no dropdown de engine:

- 🟢 **Fast** — recon rápido e leve (triagem), minutos.
- 🟡 **Medium** — balanceado (≈ o "Recommended" de hoje), ~1h.
- 🔴 **Deep** — exaustivo: **TCP full 65535 + UDP full 65535**, mais ferramentas, podendo durar **dias a semanas**.

**Decisão estrutural:** os 3 tiers são **3 engines NOVOS** adicionados ao fixture (não-destrutivo). Os 8
engines atuais permanecem (incluindo os de estágio único: Subdomain/OSINT/Port/Vulnerability). O usuário
seleciona o tier escolhendo o engine.

## Não-objetivos (YAGNI)

- Não mudar o modelo de dados nem a UI além do fixture (nada de campo `depth` ortogonal — descartado no brainstorming por exigir migração/UI).
- Não remover/renomear engines existentes.
- Não tornar o port_scan Deep assíncrono/desacoplado do pipeline (descartado — mudança arquitetural grande).
- Sem migração de DB.

## Seção 1 — Matriz dos tiers

| Estágio | 🟢 Fast (min) | 🟡 Medium (~1h) | 🔴 Deep (dias–semanas) |
|---|---|---|---|
| **subdomain_discovery** | passivos só (subfinder, ctfr, sublist3r, oneforall, crt.sh) — **sem amass-active/brute** | passivos + **amass-active** (bounded) | **tudo** + amass-active + **brute** (deepmagic 50k) |
| **port_scan TCP** | naabu **top-100**, sem nmap | naabu **top-1000** + nmap service-detect | **full `-p-`** + nmap `-sV -sC` |
| **port_scan UDP** | — (nenhum) | — (nenhum; UDP é o diferenciador do Deep) | **full `-sU -p-`** |
| **osint** | off | theHarvester + spiderfoot (normal) | spiderfoot **max** + dorks completos |
| **dir_file_fuzz** | **off** | recursão depth 1, wordlist comum | recursão **depth 2–3**, wordlist grande |
| **fetch_url** | gau/waybackurls (passivo) | todos os crawlers | todos, sem limite de dedup |
| **vulnerability_scan** | nuclei **high+critical**, sem dalfox | nuclei low..critical + dalfox | nuclei **unknown..critical** + dalfox + crlfuzz |
| **waf_detection / screenshot / secret_scan** | off / leve | on | on (full) |
| **threads/rate/timeout** | agressivo/rápido | médio | paciente (rate baixo, timeouts altos) |

Cada tier é materializado num `yaml_configuration` completo no fixture, com os valores acima.

## Mecanismo de detecção do tier

Cada um dos 3 engines novos carrega uma chave `depth_tier: fast|medium|deep` no seu `yaml_configuration`.
O código lê `ctx['yaml_configuration'].get('depth_tier', 'medium')` para decidir fator de timer (Seção 2) e
roteamento de fila (Seção 3). Mantém tudo **fixture-driven**, sem mudança de modelo. Default ausente = `medium`
(retrocompatível com os engines existentes).

## Seção 2 — Escalonamento dos timers por tier

Compõe com os **timers proporcionais à capacidade** (PR #34, `web/Suricatoos/capacity.py`): o timer efetivo
passa a ser `base × fator_capacidade × **fator_tier**`. Todos os tetos permanecem **FINITOS** (preserva a
proteção anti-wedge dos PRs #23/#33/#31).

| Timer | Fast | Medium (base ×1) | Deep |
|---|---|---|---|
| **watchdog de comando** (`DEFAULT_COMMAND_EXEC_TIMEOUT`, por tool, em `tasks.py`) | ×0.4 | ×1 | ×4 (geral) |
| **port_scan (nmap) — teto DEDICADO** | minutos | ~min | **TCP full ~horas; UDP `-sU -p-` até ~14 dias** |
| **dir-fuzz `-maxtime`** | off (sem dir_fuzz) | ~30–40 min | ~horas |
| **Celery `time_limit`/`soft_time_limit` do scan** | ~30–60 min | atual | **teto multi-dia/semana (ex: ~21 dias)** |
| **amass_timeout / subdomain stage** | curto | médio | longo |

Nuance crítica: **não** é um multiplicador único. O `port_scan` (especialmente UDP `-sU -p-`) tem um **teto
próprio e generoso** (até ~14 dias) porque é o único estágio que justifica semanas; os demais estágios do Deep
usam só ×4. O `time_limit` do scan inteiro no Deep cobre a soma (~21 dias de teto).

Implementação: uma função `tier_factor(tier)` e `port_scan_ceiling(tier)` em `capacity.py` (ou módulo
adjacente), consumidas onde os timers são calculados (`tasks.py` watchdog/`_arm_command_watchdog`, o
`-maxtime` do ffuf, e os `time_limit` das tasks Celery).

## Seção 3 — Orquestração do Deep (isolamento de fila)

**Problema:** o fix de deadlock (PR #33) roda as tasks pesadas na `main_scan_queue` (worker prefork, ~4 slots).
Um `port_scan` Deep (`nmap -sU -p-` por dias/semanas) **segura 1 slot por toda a duração**; alguns Deep
concorrentes **famintariam** os scans Fast/Medium, que enfileirariam atrás de scans de semanas.

**Solução:** **fila dedicada** `deep_port_queue` com worker próprio de **baixa concorrência (1–2 slots)**.
Quando `depth_tier == 'deep'`, o subtask de `port_scan` é roteado pra essa fila (`.apply_async(queue='deep_port_queue')`),
isolando os nmaps de semanas pra que **nunca** consumam slots da `main_scan_queue`. Mesmo padrão de isolamento
que o PR #33 já aplica à `coordinator_queue`.

**Opcional (recomendado):** limitar a **1 port_scan Deep concorrente** via lock (cache/Redis), pra não
acumular múltiplos nmaps de semanas no box de recursos limitados.

Os demais estágios do Deep (subdomain/nuclei/etc.) continuam na `main_scan_queue` normal — só o `port_scan`
longo é isolado.

## Superfície de implementação (touchpoints)

1. **`web/fixtures/default_scan_engines.yaml`** — +3 engines (Fast/Medium/Deep) com `depth_tier` e os
   `yaml_configuration` da matriz. (Carregados por `loaddata` no `celery-entrypoint.sh`.)
2. **`web/Suricatoos/capacity.py`** — `tier_factor(tier)` + `port_scan_ceiling(tier)` + `scan_time_limit(tier)`.
3. **`web/Suricatoos/tasks.py`** — aplicar `fator_tier` no `_arm_command_watchdog`/`DEFAULT_COMMAND_EXEC_TIMEOUT`,
   no `-maxtime` do ffuf (dir_fuzz), e nos `time_limit` das tasks; no `port_scan`, montar `nmap -sU -p-` quando
   Deep e rotear pra `deep_port_queue`.
4. **`web/Suricatoos/definitions.py`** — constantes de portas/UDP e tetos por tier, se necessário.
5. **`docker-compose.yml`** + **`web/celery-entrypoint.sh`** — +1 worker gevent/prefork servindo
   `deep_port_queue` (baixa concorrência). (Sem volume novo.)

## Testes

- Unit: `tier_factor`/`port_scan_ceiling`/`scan_time_limit` retornam os valores esperados por tier (e default `medium`).
- Unit: o port_scan monta `nmap -sU -p-` + roteia pra `deep_port_queue` SÓ quando `depth_tier == 'deep'`; Fast usa top-100 TCP sem UDP.
- Unit: parsing de `depth_tier` ausente → `medium` (retrocompat).
- Fixture: os 3 engines carregam via `loaddata` sem erro (YAML válido).
- e2e (manual, pós-deploy): rodar Fast em demo.testfire.net (deve terminar em minutos) e confirmar que Deep roteia o port_scan pra `deep_port_queue` (sem rodar o UDP-full completo num teste).

## Deploy

- Rebuild da imagem (fixture + código bind-mount) + recreate dos workers (novo worker `deep_port_queue` no compose/entrypoint). Sem migração de DB. Nunca mid-scan.
- O `loaddata` no entrypoint insere/atualiza os engines novos (idempotente).

## Riscos / caveats

- **Deep monopoliza recursos**: mesmo isolado em fila própria, um `nmap -sU -p-` de semanas consome CPU/rede
  do box 2-vCPU por muito tempo. O lock de 1-concorrente mitiga acúmulo; o usuário deve usar Deep
  conscientemente.
- **UDP full é frequentemente impraticável** (semanas/host): documentado; é escolha explícita do usuário ao
  selecionar o engine Deep.
- **Tetos finitos do Deep** (~14d port_scan / ~21d scan) podem cortar um UDP-full genuíno que precise de mais;
  são generosos mas finitos por design (anti-wedge). Ajustáveis via env se preciso.

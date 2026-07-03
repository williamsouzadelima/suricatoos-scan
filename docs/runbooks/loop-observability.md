# Runbook — Observabilidade do loop reNgine→OpenVAS (ADR-0006)

O loop entrega os hosts vivos de uma recon do reNgine ao scanner OpenVAS e traz os
achados de volta como `Vulnerability` (ver ADR-0006 e o memo do loop). Ele roda em
prod mas, até aqui, **sem sonda de saúde**: um beat de poll parado, um push rejeitado
ou um import falhando passavam despercebidos. O comando `loop_health` fecha esse gap.

## Comando

```bash
# no contexto do worker (mesmas settings/env do celery):
docker compose exec celery python3 manage.py loop_health              # relatório humano, 24h
docker compose exec celery python3 manage.py loop_health --window-hours 6
docker compose exec celery python3 manage.py loop_health --json       # p/ máquina
docker compose exec celery python3 manage.py loop_health --json --quiet  # cron: silencioso se OK
```

Rode-o **no container do celery/celery-beat** — ele lê as mesmas settings que os
workers (`SURICATOOS_SCANNER_*`). Rodar no `web` pode divergir se o env não for igual.

**Exit codes** (é o contrato de alerting): `0` OK · `1` WARN · `2` CRITICAL.

O comando é **read-only** (só DB + settings, nada de rede) — seguro para rodar a
qualquer hora, inclusive em loop de monitoramento.

## O que ele checa

Métricas derivadas de `ScanBridgeJob` (loop externo) + `SensorImport` (sensor, ADR-0007 G):
distribuição de estados, jobs in-flight, throughput na janela, último import bem-sucedido,
falhas (FAILED/EXPIRED), e **invariantes** do modelo de dados.

## Códigos de issue → triagem

| Código | Nível | Significado | Primeira ação |
|---|---|---|---|
| `not_configured` | CRIT | `PUSH_ENABLED=True` mas falta URL/CERT/KEY | conferir `SURICATOOS_SCANNER_*` e o cert de enroll (`openvas_enroll`) montado em `/certs` |
| `poll_stalled` | CRIT | todos os jobs pollável(is) sem poll recente | **beat parado OU scanner inacessível**: 1) `celery-beat` de pé? `docker compose ps`; 2) a task `poll-scanner-jobs` está no schedule?; 3) o scanner responde? (a chamada `poll()` falhando congela `last_polled`). *Import estourando aparece como `import_failing`, não aqui.* |
| `no_request_id` | CRIT | job avançou mas sem `request_id` → o poll o ignora p/ sempre | o scanner respondeu o submit sem `request_id`; ver logs do ingest do scanner; o job precisa ser re-submetido/limpo |
| `import_failing` | CRIT | job `COMPLETED` não vira `IMPORTED` | `import_openvas_findings` está estourando; ver logs do worker; provável dado inesperado no report |
| `invariant_*` / `unknown_state` | CRIT | invariante do modelo violado (bug) | investigar como o job chegou nesse estado; abrir issue |
| `some_stale` | WARN | parte dos in-flight sem poll recente | intermitência de poll/scanner; observar; escala p/ `poll_stalled` se piorar |
| `submit_stuck` | WARN | jobs presos em `SUBMITTED` | a task `push_to_scanner` travou/morreu (retry/backoff); ver logs do worker |
| `near_expiry` | WARN | job perto do `max_age` sem completar | o scanner está lento; ver a task no lado do scanner (GSA) |
| `push_failed` | WARN | push(es) rejeitado(s) 4xx na janela | ver `failed_samples`; cert/enrollment, allowlist do scanner, ou payload |
| `expired` | WARN | job(s) expiraram sem completar | o scanner não completou em `max_age`h; investigar a task no scanner |
| `no_recent_success` | WARN | nenhum import OK apesar de atividade | correlacionar com os itens acima; provável causa upstream |
| `sensor_not_imported` | WARN | `SensorImport` com `imported=False` (esperado 0) | anomalia do receiver do sensor; ver `import_sensor_findings` |

## Alerta em cron

Exit code ≥ 1 dispara o alerta. Ex.: a cada 15 min, notifica só quando há problema:

```cron
*/15 * * * * cd /path/to/compose && docker compose exec -T celery python3 manage.py loop_health --json --quiet || /usr/local/bin/notify-loop-degradado.sh
```

Com `--json --quiet` (como no cron acima), a saída é vazia + exit 0 quando saudável e o
JSON (capturável pelo hook de notificação) + exit não-zero em WARN/CRITICAL. Note que
`--quiet` sozinho imprime o **relatório humano** em WARN/CRITICAL — para saída de máquina,
sempre combine com `--json`.

## Thresholds (settings-overridable)

| Setting | Default | Papel |
|---|---|---|
| `SURICATOOS_SCANNER_MAX_AGE_HOURS` | 8 | idade em que o poll marca o job `EXPIRED`; `near_expiry` = 75% disto |
| `SURICATOOS_LOOP_STALE_POLL_MIN` | max(10, 5×poll) | sem poll há mais que isto ⇒ stale |
| `SURICATOOS_LOOP_SUBMIT_STUCK_MIN` | 30 | `SUBMITTED` sem avançar por mais que isto ⇒ stuck |
| `SURICATOOS_LOOP_NO_SUCCESS_HOURS` | 24 | sem import OK por mais que isto (com atividade) ⇒ warn |

## Referências

- ADR-0006 — loop reNgine→OpenVAS (`suricatoos-infra/docs/adr/0006-loop-rengine-openvas.md`)
- Runbook do loop (`suricatoos-infra/docs/runbooks/loop-rengine-openvas.md`)
- Código: `Suricatoos/tasks.py` (`push_to_scanner`, `poll_scanner_jobs`), `startScan/models.py` (`ScanBridgeJob`)

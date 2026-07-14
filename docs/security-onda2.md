# Onda 2 — Segurança (execução)

Branch `fix/audit-wave2-security`. Segunda onda do programa de excelência
(ver `audit-2026-07-04-roadmap.md`). Recon adversarial confirmou os 11 achados
ainda presentes no código atual antes de corrigir.

## Corrigidos nesta onda

| # | Sev | Achado | Fix |
|---|---|---|---|
| 5 | HIGH | SSRF via redirect nos fetchers WAF/CMS | `wafw00f -r` + remove `--follow-redirect` do CMSeeK — o guard de origem passa a ser o único host contatado |
| 6 | MED | Dev server (`runserver`) em produção | `entrypoint.sh` → `gunicorn Suricatoos.wsgi:application` (1 worker + 4 threads) |
| 8 | MED | API DRF sem throttling global | `DEFAULT_THROTTLE_CLASSES/RATES` (Anon 60/min, User 600/min), env-flagged, sensor isento |
| 9 | MED | gunicorn 22.0.0 (CVE-2024-6827) | `gunicorn==23.0.0` |
| 10 | LOW | Bearer do sensor comparado com `==` (timing) | `hmac.compare_digest` |
| 11 | LOW | Chave mTLS world-readable antes do chmod (TOCTOU) | `os.open(..., mode)` + `os.fchmod` — nasce `0600` |
| 13 | LOW | UpdateTool/UninstallTool: comando do DB via shell sem allowlist | rejeita metacaracteres de shell; `git -C` sem shell; valida `github_clone_path` sob `/usr/src/github/` |
| 14 | LOW | `str(exc)` cru em HTTP 500 | log server-side (`exc_info`) + mensagem genérica |
| 15 | LOW | `ALLOWED_HOSTS` default `['*']` | fallback wildcard só em DEBUG; prod sem env → `localhost`/loopback |

## Residual aceito (mitigação de infra, não código)

**#12 — DNS-rebinding TOCTOU** no `is_blocked_fetch_target`: o guard resolve o host uma
vez e valida; a ferramenta (wafw00f/CMSeeK) re-resolve ao conectar → janela de rebind com
DNS de TTL baixo controlado pelo atacante. Pinar o IP validado quebraria SNI/vhost em
alvos CDN/shared-hosting (falso "não detectado"), então **não** aplicamos fix de código.
Mitigação recomendada (defense-in-depth, ops no host .124):
- Bloquear egresso do container de scan para link-local/RFC1918/metadata
  (`169.254.169.254`, `10/8`, `172.16/12`, `192.168/16`) via UFW/iptables no worker host,
  **exceto** quando engajamentos internos legítimos exigirem (`allow_private`) — regra
  por-ambiente, não global.
- Forçar IMDSv2 / hop-limit=1 na instância cloud (fecha o vetor de metadata).

## Deferido com plano (precisa de validação no container, não deploy cego)

**#7 — contêineres rodam como root** (sem `USER` no Dockerfile). O fix correto NÃO é um
`user: 10001` cego no compose porque, neste layout, **tanto web quanto celery** montam
volumes sob `/root` (`/root/.gf`, `/root/nuclei-templates`, `/root/.config`) e os usam em
runtime, e o `celery-entrypoint.sh` faz `apt install firefox` em runtime (exige root). Um
usuário não-root cego quebraria os endpoints de tool e o boot do celery. Plano seguro
(a executar com acesso ao container .124, com teste de fumaça):
1. Mover `apt install firefox` (e afins) do `celery-entrypoint.sh` para BUILD-TIME no
   Dockerfile (padrão já adotado p/ as demais OSINT tools).
2. Realocar os volumes `/root/.gf|/root/.config|/root/nuclei-templates` para
   `/home/suricatoos/...` no `docker-compose.yml` e criar o usuário + `chown` no Dockerfile.
3. `USER suricatoos` na imagem; validar: boot de web+celery, `collectstatic`, escrita de
   `scan_results`, execução de nuclei/gf, e um scan ponta-a-ponta antes de considerar fechado.

Enquanto #7 não é fechado, o container roda como root (estado atual, inalterado por esta onda).

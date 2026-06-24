# A06 — Briefs dos itens ADIADOS (arriscados / não aplicados no PR #35)

Contexto: auditoria A06 de 2026-06-24. 45 deps fixadas → 7 pacotes vulneráveis / 20 CVEs.
Triagem com verificação adversarial (14 agentes) concluiu que **nenhum dos 20 CVEs é
alcançável** neste app. O PR #35 aplicou os 4 bumps seguros + removeu scapy. Os itens
abaixo NÃO foram aplicados por terem blast-radius alto ou tocarem caminho sensível —
ficam aqui como brief para decisão/execução dedicada.

---

## 1. Django 3.2.x → 4.2 LTS (maior item; fecha o SQLi CRÍTICO)

**Por que importa:** os 3 CVEs mais graves do Django **só corrigem em 4.2+**:
- CVE-2025-64459 **CRÍTICO** — SQLi via `_connector` kwarg em `QuerySet`/`Q`.
- CVE-2025-57833 **HIGH** — SQLi via column aliases.
- CVE-2025-48432 MODERATE (log) + CVE-2024-45231 MODERATE (enum de e-mail no reset).

**Por que NÃO é urgente (apesar do "crítico"):** triagem+verificação confirmaram
**inalcançável** aqui. Os 5 sinks `filter(**dict)`/`get_or_create(**data)` (tasks.py
:4751/:5054/:3177/:3795/:5596) recebem chaves de parsers internos **literais**
(parse_nuclei_result, save_leaked_secret, parse_s3scanner_result); o atacante (output
de scan) controla só os **valores**, nunca as chaves. `grep **request.data/POST/GET`
em ORM = vazio. Annotates usam alias literal. → é **hardening/higiene**, não emergência.

**Blast-radius do upgrade (real, confirmado no código):**
- `django.conf.urls.url` removido na 4.0 — usado em `web/api/urls.py:1,28` e
  `web/Suricatoos/urls.py:2,25-26` → migrar para `re_path`/`path`.
- DRF 3.12.4 não é testado em Django 4.2 → bump acoplado para **DRF 3.15.2** (ver item 3).
- Settings deprecadas: `USE_L10N` (settings.py:254, removido na 4.0), revisar `USE_TZ`
  (255), `DEFAULT_AUTO_FIELD` (365), bloco CSRF (79-81).
- Outras libs: `drf-yasg`, `django-role-permissions`, `django-celery-beat` — checar
  compat com 4.2.

**Recomendação:** spec própria + branch dedicada + suite de testes rodada na imagem.
Alvo 4.2 LTS (suporte estendido até abr/2026... checar; senão 4.2.x mais recente).
Não fazer junto de outras mudanças.

---

## 2. weasyprint 53.3 SSRF (CVE-2025-68616, HIGH) — fix de código, NÃO bump

**Vuln:** bypass da proteção SSRF do weasyprint via redirect HTTP. Real no pacote
instalado (`weasyprint/urls.py` segue redirect sem revalidar o destino).

**Inalcançável:** único call site é `create_report` (startScan/views.py:1202),
gated por `@has_permission_decorator(PERM_MODIFY_SCAN_REPORT)` (operador autenticado).
Os únicos fetches http(s) são **Google Fonts (hardcoded, público)**; charts/logo são
**data: URIs base64**. Dados de scan (atacante-controlados) usam `|linebreaks` (escapa
HTML) ou caem em `<a href>`/texto, que o weasyprint não busca ao renderizar.

**Por que NÃO bumpar para 68.0:** quebra o pin `pydyf==0.1.1` (requirements.txt:40-42 —
`pydyf>=0.2` remove `Stream.transform`, que weasyprint 53.3 chama → PDF corrompido,
regressão já sofrida antes).

**Fix recomendado (defense-in-depth, baixo risco, mas toca caminho sensível do PDF):**
no `_report_url_fetcher` (views.py:33), revalidar o destino final do redirect:
```python
result = default_url_fetcher(url, timeout=min(timeout, 5), ssl_context=ssl_context)
redirected = result.get('redirected_url') if isinstance(result, dict) else None
if redirected and urlparse(redirected).scheme in ('http', 'https'):
    blocked, reason = is_blocked_fetch_target(redirected, allow_private=False)
    if blocked:
        raise ValueError(f'blocked report resource redirect: {reason}')
return result
```
Considerar também trocar o `allow_private=True` da checagem inicial (linha 40) por
`False` — não há fetch http(s) legítimo para host privado (fonts são públicas).
**Validação obrigatória:** o CI não exercita render de PDF → testar export PDF AO VIVO
num scan existente após deploy antes de considerar concluído.

---

## 3. djangorestframework 3.12.4 → 3.15.2 (XSS LOW) — acoplado ao Django 4.2

**Vuln:** CVE-2024-21520 LOW — XSS na browsable API (`break_long_headers`,
templatetags/rest_framework.py:315). A browsable API ESTÁ ligada (settings.py:213).

**Inalcançável:** nenhuma source atacante-controlada chega a um header de **resposta**
que passe pelo `break_long_headers`. Os `Content-Disposition` com `domain_name`
(views.py:461/476/492) são views Django puras que retornam `HttpResponse` cru — não
passam pelo `BrowsableAPIRenderer`. Dentro da superfície DRF, todo `response[...]` é
chave de dict do corpo JSON, não header. Defesas: `IsAuthenticated` default + todos os
viewsets com `HasPermission` (zero `AllowAny`).

**Bloqueio:** DRF 3.15.2 exige **Django ≥4.2** → só faz sentido junto do item 1.

---

**Resumo de prioridade:** todos inalcançáveis hoje. Ordem se/quando for endurecer:
(1) Django 4.2 LTS é o trabalho de fundo (arrasta o item 3); (2) weasyprint é um fix
de código pequeno mas precisa de verificação de PDF ao vivo.

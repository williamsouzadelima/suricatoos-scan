"""Sonda de saúde do loop reNgine→OpenVAS (ADR-0006) — observabilidade operacional.

O loop está vivo em prod mas sem monitoramento: jobs podem travar (beat de poll
parado), o push pode ser rejeitado (4xx), o scanner pode nunca completar (EXPIRED),
ou o import pode falhar em loop. Este comando lê SÓ o DB + settings (nada de rede)
e devolve um retrato de saúde com um veredito e um exit code, para servir tanto de
inspeção manual quanto de sonda de alerta em cron.

Exit codes (para alerting):
    0  OK            — nada a reportar
    1  WARN          — anomalia não-fatal (falhas, expirações, jobs perto de expirar)
    2  CRITICAL      — loop quebrado (misconfig, poll parado, invariante violado)

Uso:
    python manage.py loop_health                     # relatório humano, últimas 24h
    python manage.py loop_health --window-hours 6    # janela custom
    python manage.py loop_health --json              # saída para máquina/monitoramento
    python manage.py loop_health --quiet             # silencioso se OK (cron)

Rode-o no contexto do worker (mesmas settings/env do celery), p.ex.:
    docker compose exec celery python3 manage.py loop_health --json --quiet
"""

import json
import sys
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

# Estados terminais do ScanBridgeJob (espelha o filtro do poll_scanner_jobs).
TERMINAL = {"IMPORTED", "FAILED", "STOPPED", "EXPIRED"}
KNOWN_STATES = {
    "SUBMITTED", "PENDING", "RUNNING", "COMPLETED",
    "IMPORTED", "FAILED", "STOPPED", "EXPIRED",
}
# Fração do max_age a partir da qual um job in-flight é "perto de expirar".
NEAR_EXPIRY_FRACTION = 0.75

CRITICAL, WARN, OK = "critical", "warn", "ok"
_EXIT = {OK: 0, WARN: 1, CRITICAL: 2}


class Command(BaseCommand):
    help = "Sonda de saúde do loop reNgine→OpenVAS (ADR-0006) com exit code p/ alerting."

    def add_arguments(self, parser):
        parser.add_argument("--window-hours", type=int, default=24,
                            help="Janela para throughput/falhas recentes (default 24).")
        parser.add_argument("--json", action="store_true", dest="as_json",
                            help="Emite JSON estruturado em vez do relatório humano.")
        parser.add_argument("--quiet", action="store_true",
                            help="Não imprime nada quando o veredito é OK (útil em cron).")

    def handle(self, *args, **opts):
        report = self.collect(window_hours=opts["window_hours"])
        status = report["status"]

        if not (opts["quiet"] and status == OK):
            if opts["as_json"]:
                self.stdout.write(json.dumps(report, indent=2, default=str))
            else:
                self._render_human(report)

        sys.exit(_EXIT[status])

    # ------------------------------------------------------------------ #
    # Coleta (pura: só DB + settings). `now` injetável para os testes.
    # ------------------------------------------------------------------ #
    def collect(self, window_hours=24, now=None):
        from django.conf import settings
        from django.db.models import Count, Sum
        from Suricatoos import scanner_bridge
        from startScan.models import ScanBridgeJob, SensorImport

        now = now or timezone.now()
        window_start = now - timedelta(hours=window_hours)

        # --- config / thresholds (settings-overridable) ---
        push_enabled = bool(getattr(settings, "SURICATOOS_SCANNER_PUSH_ENABLED", False))
        configured = scanner_bridge.is_configured()
        max_age_h = float(getattr(settings, "SURICATOOS_SCANNER_MAX_AGE_HOURS", 8))
        poll_interval_s = self._poll_interval_s(settings)
        # Sem poll há > stale_poll_min ⇒ beat provavelmente parado (default: 5 ciclos, mín 10min).
        stale_poll_min = float(getattr(settings, "SURICATOOS_LOOP_STALE_POLL_MIN",
                                       max(10.0, poll_interval_s * 5 / 60.0)))
        # SUBMITTED que não avançou por > isto ⇒ push travou/morreu (default 30min).
        submit_stuck_min = float(getattr(settings, "SURICATOOS_LOOP_SUBMIT_STUCK_MIN", 30.0))
        # Sem nenhum import bem-sucedido há > isto, apesar de atividade ⇒ suspeito (default 24h).
        no_success_h = float(getattr(settings, "SURICATOOS_LOOP_NO_SUCCESS_HOURS", 24.0))

        config = {
            "push_enabled": push_enabled,
            "scanner_configured": configured,
            "scanner_url": getattr(settings, "SURICATOOS_SCANNER_URL", ""),
            "allow_private": bool(getattr(settings, "SURICATOOS_SCANNER_ALLOW_PRIVATE", False)),
            "max_age_hours": max_age_h,
            "poll_interval_s": poll_interval_s,
            "max_hosts": int(getattr(settings, "SURICATOOS_SCANNER_MAX_HOSTS", 256)),
            "window_hours": window_hours,
            "stale_poll_min": stale_poll_min,
        }

        # --- distribuição de estados (todos os jobs) ---
        states = {r["state"]: r["n"]
                  for r in ScanBridgeJob.objects.values("state").annotate(n=Count("id"))}
        total_jobs = sum(states.values())

        # --- jobs in-flight (espelha o filtro do poll) ---
        inflight_qs = ScanBridgeJob.objects.filter(imported=False).exclude(state__in=TERMINAL)
        stale, near_expiry, no_request_id, submitted_stuck, completed_stuck = [], [], [], [], []
        inflight_ids = []
        near_expiry_after = timedelta(hours=max_age_h * NEAR_EXPIRY_FRACTION)
        stale_after = timedelta(minutes=stale_poll_min)
        submit_stuck_after = timedelta(minutes=submit_stuck_min)
        for job in inflight_qs.only("id", "state", "request_id", "submitted_at", "last_polled"):
            inflight_ids.append(job.id)
            age = now - job.submitted_at
            poll_gap = now - (job.last_polled or job.submitted_at)
            if job.state == "SUBMITTED":
                # Nunca submetido com sucesso (push não avançou o estado).
                if age > submit_stuck_after:
                    submitted_stuck.append(job.id)
            elif not job.request_id:
                # Estado avançou mas sem request_id ⇒ o poll o pula para sempre (won't-poll).
                no_request_id.append(job.id)
            if job.state == "COMPLETED":
                # COMPLETED deveria virar IMPORTED no mesmo poll; persistir ⇒ import falhando.
                completed_stuck.append(job.id)
            if job.request_id and poll_gap > stale_after:
                stale.append(job.id)
            # Só jobs COM request_id chegam à transição EXPIRED no poll (o poll pula os sem
            # request_id antes de checar idade) ⇒ near_expiry só faz sentido para esses.
            if job.request_id and age > near_expiry_after:
                near_expiry.append(job.id)

        inflight = {
            "count": len(inflight_ids),
            "ids": inflight_ids,
            "stale_poll": stale,
            "near_expiry": near_expiry,
            "no_request_id": no_request_id,
            "submitted_stuck": submitted_stuck,
            "completed_stuck": completed_stuck,
        }

        # --- falhas na janela (FAILED/EXPIRED não gravam completed_at ⇒ ancora em submitted_at) ---
        # FAILED é setado no push, ~junto do submitted_at ⇒ janelar por submitted_at é fiel.
        failed_qs = ScanBridgeJob.objects.filter(state="FAILED", submitted_at__gte=window_start)
        # EXPIRED é carimbado ~max_age DEPOIS do submitted_at (poll_scanner_jobs), então
        # para capturar o que expirou DENTRO da janela a busca precisa recuar mais max_age —
        # senão, com window <= max_age, o filtro por submitted_at NUNCA casa (falso-OK em outage).
        expired_lookback = window_start - timedelta(hours=max_age_h)
        expired_qs = ScanBridgeJob.objects.filter(state="EXPIRED", submitted_at__gte=expired_lookback)
        failures = {
            "failed_count": failed_qs.count(),
            "expired_count": expired_qs.count(),
            "failed_samples": [
                {"id": j.id, "error": (j.error or "")[:200]}
                for j in failed_qs.order_by("-submitted_at").only("id", "error")[:5]
            ],
        }

        # --- throughput na janela + último sucesso ---
        imported_qs = ScanBridgeJob.objects.filter(state="IMPORTED", completed_at__gte=window_start)
        last = (ScanBridgeJob.objects.filter(state="IMPORTED", completed_at__isnull=False)
                .order_by("-completed_at").only("completed_at").first())
        last_success_at = last.completed_at if last else None
        throughput = {
            "imported_jobs": imported_qs.count(),
            "findings_imported": imported_qs.aggregate(s=Sum("findings_imported"))["s"] or 0,
            "last_success_at": last_success_at,
            "hours_since_success": (
                round((now - last_success_at).total_seconds() / 3600.0, 2)
                if last_success_at else None),
        }

        # --- invariantes (violação ⇒ bug de código, nunca deveria ocorrer) ---
        integrity = {
            "imported_but_not_imported_state":
                ScanBridgeJob.objects.filter(imported=True).exclude(state="IMPORTED").count(),
            "imported_state_but_not_imported":
                ScanBridgeJob.objects.filter(state="IMPORTED", imported=False).count(),
            "unknown_states": sorted(
                ScanBridgeJob.objects.exclude(state__in=KNOWN_STATES)
                .values_list("state", flat=True).distinct()),
        }

        # --- sensor interno (ADR-0007 G): SensorImport só existe com imported=True ---
        sensor_window = SensorImport.objects.filter(created_at__gte=window_start)
        sensor = {
            "total": SensorImport.objects.count(),
            "window": sensor_window.count(),
            "findings_window": sensor_window.aggregate(s=Sum("findings_imported"))["s"] or 0,
            "tenants": SensorImport.objects.values("tenant").distinct().count(),
            "not_imported": SensorImport.objects.filter(imported=False).count(),
        }

        report = {
            "generated_at": now,
            "config": config,
            "total_jobs": total_jobs,
            "states": states,
            "inflight": inflight,
            "failures": failures,
            "throughput": throughput,
            "integrity": integrity,
            "sensor": sensor,
        }
        report["issues"] = self._assess(report, push_enabled, no_success_h)
        report["status"] = self._status_of(report["issues"])
        return report

    # ------------------------------------------------------------------ #
    # Avaliação: transforma métricas em issues classificadas.
    # ------------------------------------------------------------------ #
    @staticmethod
    def _assess(report, push_enabled, no_success_h):
        issues = []

        def add(level, code, msg):
            issues.append({"level": level, "code": code, "msg": msg})

        inflight = report["inflight"]
        integ = report["integrity"]
        fail = report["failures"]
        tp = report["throughput"]

        # Invariantes: sempre crítico, mesmo com o loop desabilitado (é bug).
        if integ["imported_but_not_imported_state"]:
            add(CRITICAL, "invariant_imported_flag",
                f'{integ["imported_but_not_imported_state"]} job(s) com imported=True mas state!=IMPORTED')
        if integ["imported_state_but_not_imported"]:
            add(CRITICAL, "invariant_imported_state",
                f'{integ["imported_state_but_not_imported"]} job(s) com state=IMPORTED mas imported=False')
        if integ["unknown_states"]:
            add(CRITICAL, "unknown_state",
                f'estado(s) desconhecido(s): {", ".join(integ["unknown_states"])}')
        if report["sensor"]["not_imported"]:
            add(WARN, "sensor_not_imported",
                f'{report["sensor"]["not_imported"]} SensorImport com imported=False (esperado 0)')

        if not push_enabled:
            # Loop desligado: staleness/expiração não são anomalias. Só invariantes acima contam.
            if not issues:
                add(OK, "disabled", "loop desabilitado (SURICATOOS_SCANNER_PUSH_ENABLED=False)")
            return issues

        if not report["config"]["scanner_configured"]:
            add(CRITICAL, "not_configured",
                "push habilitado mas scanner não configurado (URL/CERT/KEY ausente) — nada será entregue")

        # Jobs que nunca serão pollados / import travado ⇒ crítico.
        if inflight["no_request_id"]:
            add(CRITICAL, "no_request_id",
                f'{len(inflight["no_request_id"])} job(s) in-flight sem request_id — o poll os ignora '
                f'(ids {inflight["no_request_id"][:10]})')
        if inflight["completed_stuck"]:
            add(CRITICAL, "import_failing",
                f'{len(inflight["completed_stuck"])} job(s) COMPLETED não importados — import falhando '
                f'(ids {inflight["completed_stuck"][:10]})')

        # Poll parado: TODOS os jobs pollável(is) sem poll recente ⇒ o beat de poll_scanner_jobs
        # parou, OU o scanner está inacessível (a chamada poll() falha e o job não avança). Falha
        # de import NÃO cai aqui: é capturada e o last_polled avança ⇒ vira 'import_failing'.
        # Compara conjuntos coerentes: stale ∩ pollable vs pollable (n_stale cru incluiria
        # jobs SUBMITTED, que não entram em pollable, distorcendo o denominador).
        n_inflight = inflight["count"]
        n_stale = len(inflight["stale_poll"])
        pollable = set(inflight["ids"]) - set(inflight["no_request_id"]) - set(inflight["submitted_stuck"])
        stale_pollable = [i for i in inflight["stale_poll"] if i in pollable]
        if stale_pollable and len(stale_pollable) >= len(pollable):
            add(CRITICAL, "poll_stalled",
                f'{len(stale_pollable)} job(s) pollável(is) sem poll recente — beat parado ou scanner inacessível?')
        elif n_stale:
            add(WARN, "some_stale",
                f'{n_stale}/{n_inflight} job(s) in-flight sem poll recente')

        if inflight["submitted_stuck"]:
            add(WARN, "submit_stuck",
                f'{len(inflight["submitted_stuck"])} job(s) presos em SUBMITTED — push travou? '
                f'(ids {inflight["submitted_stuck"][:10]})')
        if inflight["near_expiry"]:
            add(WARN, "near_expiry",
                f'{len(inflight["near_expiry"])} job(s) perto de expirar (>{int(NEAR_EXPIRY_FRACTION*100)}% do max_age)')
        if fail["failed_count"]:
            add(WARN, "push_failed",
                f'{fail["failed_count"]} push rejeitado(s) permanentemente na janela')
        if fail["expired_count"]:
            add(WARN, "expired",
                f'{fail["expired_count"]} job(s) expiraram sem completar na janela')

        # "Parou de ter sucesso": só alarma quando JÁ houve sucesso e ele envelheceu além do
        # limiar. "Nunca teve sucesso" num sistema novo com scan em andamento é SAUDÁVEL — os
        # detectores concretos (near_expiry/expired/stale/push_failed) é que pegam problema real
        # ali; tratar hss=None como falha daria falso-positivo a cada deploy novo/resetado.
        active = n_inflight or fail["failed_count"] or fail["expired_count"]
        hss = tp["hours_since_success"]
        if active and hss is not None and hss > no_success_h:
            add(WARN, "no_recent_success",
                f'último import bem-sucedido há {hss}h apesar de atividade na janela')

        if not issues:
            add(OK, "healthy", "loop saudável")
        return issues

    @staticmethod
    def _status_of(issues):
        levels = {i["level"] for i in issues}
        if CRITICAL in levels:
            return CRITICAL
        if WARN in levels:
            return WARN
        return OK

    @staticmethod
    def _poll_interval_s(settings):
        try:
            return float(settings.CELERY_BEAT_SCHEDULE["poll-scanner-jobs"]["schedule"])
        except (AttributeError, KeyError, TypeError, ValueError):
            return 120.0

    # ------------------------------------------------------------------ #
    # Render humano.
    # ------------------------------------------------------------------ #
    def _render_human(self, report):
        w = self.stdout.write
        cfg = report["config"]
        st = report["status"]
        banner = {OK: self.style.SUCCESS, WARN: self.style.WARNING, CRITICAL: self.style.ERROR}[st]

        w(banner(f"═══ Loop reNgine→OpenVAS — saúde: {st.upper()} ═══"))
        w(f"  gerado em     : {report['generated_at']}")
        w(f"  push_enabled  : {cfg['push_enabled']}   scanner_configured: {cfg['scanner_configured']}")
        w(f"  scanner_url   : {cfg['scanner_url']}")
        w(f"  max_age       : {cfg['max_age_hours']}h   poll: {cfg['poll_interval_s']}s   "
          f"janela: {cfg['window_hours']}h")

        w("")
        w(f"  jobs (total {report['total_jobs']}): " +
          (", ".join(f"{k}={v}" for k, v in sorted(report["states"].items())) or "—"))

        inf = report["inflight"]
        w(f"  in-flight     : {inf['count']}"
          + (f"  stale={len(inf['stale_poll'])}" if inf["stale_poll"] else "")
          + (f"  near_expiry={len(inf['near_expiry'])}" if inf["near_expiry"] else "")
          + (f"  no_request_id={len(inf['no_request_id'])}" if inf["no_request_id"] else "")
          + (f"  submitted_stuck={len(inf['submitted_stuck'])}" if inf["submitted_stuck"] else "")
          + (f"  completed_stuck={len(inf['completed_stuck'])}" if inf["completed_stuck"] else ""))

        tp = report["throughput"]
        w(f"  throughput    : {tp['imported_jobs']} import(s), {tp['findings_imported']} vuln(s) na janela")
        w(f"  último sucesso: {tp['last_success_at'] or '—'}"
          + (f" ({tp['hours_since_success']}h atrás)" if tp["hours_since_success"] is not None else ""))

        fa = report["failures"]
        w(f"  falhas janela : FAILED={fa['failed_count']}  EXPIRED={fa['expired_count']}")
        for s in fa["failed_samples"]:
            w(f"      job {s['id']}: {s['error']}")

        se = report["sensor"]
        w(f"  sensor (0007) : {se['window']} import(s)/janela, {se['tenants']} tenant(s), "
          f"{se['findings_window']} vuln(s); total {se['total']}")

        w("")
        w("  issues:")
        marks = {CRITICAL: self.style.ERROR("  ✗"), WARN: self.style.WARNING("  !"),
                 OK: self.style.SUCCESS("  ✓")}
        for i in report["issues"]:
            w(f"{marks[i['level']]} [{i['code']}] {i['msg']}")

"""Sonda de saúde do loop reNgine→OpenVAS (ADR-0006) — comando loop_health.

Cobre a classificação de saúde (collect/_assess) montando ScanBridgeJob em cada
estado e afirmando o veredito + os códigos de issue. `submitted_at` é auto_now_add,
então os campos de tempo são fixados via .update() (bypassa o auto) e o `now` é
injetado — testes determinísticos, sem depender do relógio.

Run with:  python3 manage.py test tests.test_loop_health
"""
from datetime import timedelta

from django.test import TestCase, override_settings
from django.utils import timezone

from dashboard.models import Project
from targetApp.models import Domain
from startScan.models import ScanHistory, EngineType, ScanBridgeJob, SensorImport
from startScan.management.commands.loop_health import Command

ENABLED = dict(
    SURICATOOS_SCANNER_PUSH_ENABLED=True,
    SURICATOOS_SCANNER_URL="https://scanner.suricatoos.com/ingest",
    SURICATOOS_SCANNER_CERT="/certs/score-hub.crt",
    SURICATOOS_SCANNER_KEY="/certs/score-hub.key",
)


class LoopHealthBase(TestCase):
    def setUp(self):
        self.T0 = timezone.now()
        self.project = Project.objects.create(name="t", slug="t", insert_date=self.T0)
        self.domain = Domain.objects.create(name="ex.com", project=self.project, insert_date=self.T0)
        self.engine = EngineType.objects.create(
            engine_name="e", yaml_configuration="", default_engine=False)

    def mk_job(self, state="PENDING", request_id="r", imported=False,
               submitted_delta=timedelta(minutes=1), last_polled_delta=None,
               completed_delta=None, findings=0, error=None):
        sh = ScanHistory.objects.create(
            start_scan_date=self.T0, domain=self.domain, scan_type=self.engine, scan_status=2)
        job = ScanBridgeJob.objects.create(
            scan_history=sh, state=state, request_id=request_id, imported=imported,
            findings_imported=findings, error=error)
        upd = {"submitted_at": self.T0 - submitted_delta}
        if last_polled_delta is not None:
            upd["last_polled"] = self.T0 - last_polled_delta
        if completed_delta is not None:
            upd["completed_at"] = self.T0 - completed_delta
        ScanBridgeJob.objects.filter(pk=job.pk).update(**upd)
        return job.pk

    def report(self):
        return Command().collect(window_hours=24, now=self.T0)

    def codes(self):
        return {i["code"] for i in self.report()["issues"]}


class DisabledAndHealthy(LoopHealthBase):
    def test_disabled_is_ok(self):
        r = self.report()
        self.assertEqual(r["status"], "ok")
        self.assertIn("disabled", {i["code"] for i in r["issues"]})

    @override_settings(**ENABLED)
    def test_healthy(self):
        self.mk_job(state="IMPORTED", imported=True, findings=3,
                    submitted_delta=timedelta(hours=1, minutes=5),
                    completed_delta=timedelta(hours=1))
        r = self.report()
        self.assertEqual(r["status"], "ok")
        self.assertIn("healthy", {i["code"] for i in r["issues"]})
        self.assertEqual(r["throughput"]["imported_jobs"], 1)
        self.assertEqual(r["throughput"]["findings_imported"], 3)


class CriticalConditions(LoopHealthBase):
    @override_settings(SURICATOOS_SCANNER_PUSH_ENABLED=True,
                       SURICATOOS_SCANNER_URL="", SURICATOOS_SCANNER_CERT="", SURICATOOS_SCANNER_KEY="")
    def test_not_configured(self):
        r = self.report()
        self.assertEqual(r["status"], "critical")
        self.assertIn("not_configured", {i["code"] for i in r["issues"]})

    @override_settings(**ENABLED)
    def test_no_request_id(self):
        self.mk_job(state="PENDING", request_id="", submitted_delta=timedelta(minutes=5))
        r = self.report()
        self.assertEqual(r["status"], "critical")
        self.assertIn("no_request_id", {i["code"] for i in r["issues"]})

    @override_settings(**ENABLED)
    def test_completed_stuck(self):
        self.mk_job(state="COMPLETED", request_id="r", imported=False,
                    submitted_delta=timedelta(minutes=5), last_polled_delta=timedelta(minutes=1))
        r = self.report()
        self.assertEqual(r["status"], "critical")
        self.assertIn("import_failing", {i["code"] for i in r["issues"]})

    @override_settings(**ENABLED)
    def test_poll_stalled(self):
        # in-flight pollável cujo last_polled é antigo (>stale) ⇒ beat parece parado.
        self.mk_job(state="RUNNING", request_id="r",
                    submitted_delta=timedelta(minutes=30), last_polled_delta=timedelta(minutes=20))
        r = self.report()
        self.assertEqual(r["status"], "critical")
        self.assertIn("poll_stalled", {i["code"] for i in r["issues"]})

    def test_integrity_violation_even_when_disabled(self):
        # imported=True mas state!=IMPORTED é bug — crítico mesmo com loop desligado.
        self.mk_job(state="COMPLETED", imported=True, submitted_delta=timedelta(hours=1))
        r = self.report()
        self.assertEqual(r["status"], "critical")
        self.assertIn("invariant_imported_flag", {i["code"] for i in r["issues"]})
        self.assertNotIn("disabled", {i["code"] for i in r["issues"]})


class WarnConditions(LoopHealthBase):
    @override_settings(**ENABLED)
    def test_push_failed(self):
        self.mk_job(state="FAILED", request_id="r", error="403: rejeitado",
                    submitted_delta=timedelta(hours=1))
        r = self.report()
        self.assertEqual(r["status"], "warn")
        self.assertIn("push_failed", {i["code"] for i in r["issues"]})
        self.assertEqual(r["failures"]["failed_count"], 1)

    @override_settings(**ENABLED)
    def test_expired(self):
        self.mk_job(state="EXPIRED", request_id="r", submitted_delta=timedelta(hours=1))
        r = self.report()
        self.assertEqual(r["status"], "warn")
        self.assertIn("expired", {i["code"] for i in r["issues"]})

    @override_settings(**ENABLED)
    def test_near_expiry_not_stalled(self):
        # 7h de idade (>75% de 8h) mas poll recente ⇒ near_expiry, não poll_stalled.
        self.mk_job(state="RUNNING", request_id="r",
                    submitted_delta=timedelta(hours=7), last_polled_delta=timedelta(minutes=1))
        c = {i["code"] for i in self.report()["issues"]}
        self.assertIn("near_expiry", c)
        self.assertNotIn("poll_stalled", c)

    @override_settings(**ENABLED)
    def test_no_recent_success(self):
        self.mk_job(state="IMPORTED", imported=True, completed_delta=timedelta(hours=30),
                    submitted_delta=timedelta(hours=30, minutes=5))
        self.mk_job(state="PENDING", request_id="r",
                    submitted_delta=timedelta(minutes=5), last_polled_delta=timedelta(minutes=1))
        c = {i["code"] for i in self.report()["issues"]}
        self.assertIn("no_recent_success", c)

    def test_sensor_not_imported_warns(self):
        SensorImport.objects.create(correlation_id="x", tenant="t", imported=False)
        r = self.report()
        self.assertEqual(r["status"], "warn")
        self.assertIn("sensor_not_imported", {i["code"] for i in r["issues"]})


class RegressionCoverage(LoopHealthBase):
    """Casos que travam os defeitos achados na review adversária (2026-07-03)."""

    @override_settings(**ENABLED)
    def test_never_succeeded_is_healthy(self):
        # Deploy novo: scan em andamento, nenhum import ainda ⇒ SAUDÁVEL, não 'no_recent_success'.
        self.mk_job(state="PENDING", request_id="r",
                    submitted_delta=timedelta(minutes=5), last_polled_delta=timedelta(minutes=1))
        c = {i["code"] for i in self.report()["issues"]}
        self.assertIn("healthy", c)
        self.assertNotIn("no_recent_success", c)

    @override_settings(**ENABLED)
    def test_expired_caught_in_short_window(self):
        # EXPIRED é carimbado ~max_age(8h) após o submit; uma janela de 6h precisa recuar
        # o lookback por max_age p/ pegá-lo (antes do fix, expired_count era sempre 0 aqui).
        self.mk_job(state="EXPIRED", request_id="r", submitted_delta=timedelta(hours=9))
        r = Command().collect(window_hours=6, now=self.T0)
        self.assertEqual(r["failures"]["expired_count"], 1)
        self.assertIn("expired", {i["code"] for i in r["issues"]})

    @override_settings(**ENABLED)
    def test_some_stale_not_poll_stalled(self):
        # 2 pollável(is), só 1 stale ⇒ WARN some_stale, não CRITICAL poll_stalled.
        self.mk_job(state="RUNNING", request_id="r",
                    submitted_delta=timedelta(minutes=30), last_polled_delta=timedelta(minutes=20))
        self.mk_job(state="RUNNING", request_id="r",
                    submitted_delta=timedelta(minutes=30), last_polled_delta=timedelta(minutes=1))
        c = {i["code"] for i in self.report()["issues"]}
        self.assertIn("some_stale", c)
        self.assertNotIn("poll_stalled", c)

    @override_settings(**ENABLED)
    def test_submit_stuck_warns(self):
        self.mk_job(state="SUBMITTED", request_id="", submitted_delta=timedelta(minutes=40))
        r = self.report()
        self.assertEqual(r["status"], "warn")
        self.assertIn("submit_stuck", {i["code"] for i in r["issues"]})

    def test_invariant_imported_state(self):
        # state=IMPORTED mas imported=False é bug — crítico mesmo com loop desligado.
        self.mk_job(state="IMPORTED", imported=False, submitted_delta=timedelta(hours=1))
        r = self.report()
        self.assertEqual(r["status"], "critical")
        self.assertIn("invariant_imported_state", {i["code"] for i in r["issues"]})

    def test_unknown_state(self):
        self.mk_job(state="WEIRD", submitted_delta=timedelta(hours=1))
        r = self.report()
        self.assertEqual(r["status"], "critical")
        self.assertIn("unknown_state", {i["code"] for i in r["issues"]})

    @override_settings(**ENABLED)
    def test_submit_stuck_not_escalated_to_poll_stalled(self):
        # Edge que discrimina o fix do conjunto: um SUBMITTED-stuck com request_id cai em
        # stale E submitted_stuck; comparar n_stale cru vs pollable (bug antigo) o contaria e
        # escalaria a CRITICAL. Com stale∩pollable, ele sai do numerador ⇒ só submit_stuck (WARN).
        self.mk_job(state="SUBMITTED", request_id="r",
                    submitted_delta=timedelta(minutes=40), last_polled_delta=timedelta(minutes=20))
        self.mk_job(state="RUNNING", request_id="r",
                    submitted_delta=timedelta(minutes=30), last_polled_delta=timedelta(minutes=1))
        c = {i["code"] for i in self.report()["issues"]}
        self.assertNotIn("poll_stalled", c)
        self.assertIn("submit_stuck", c)

    def test_disabled_suppresses_staleness(self):
        # Loop desligado: um job in-flight stale NÃO é anomalia (não alarma).
        self.mk_job(state="RUNNING", request_id="r",
                    submitted_delta=timedelta(minutes=30), last_polled_delta=timedelta(minutes=20))
        r = self.report()
        self.assertEqual(r["status"], "ok")
        self.assertIn("disabled", {i["code"] for i in r["issues"]})
        self.assertNotIn("poll_stalled", {i["code"] for i in r["issues"]})


if __name__ == "__main__":
    import unittest
    unittest.main()

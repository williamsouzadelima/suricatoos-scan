"""Endpoint inbound de import dos achados do sensor (ADR-0007 G).

Cobre a autenticação Bearer do POST /api/sensor/import (máquina-a-máquina, sem
sessão) sem tocar o DB: a task import_sensor_findings.delay é mockada.

Run with:  python3 manage.py test tests.test_sensor_import
"""
from unittest import mock

from django.test import TestCase, override_settings
from rest_framework.test import APIClient


@override_settings(SURICATOOS_SENSOR_IMPORT_SECRET="sc-secret")
class SensorImportAuthTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = "/api/sensor/import/"
        self.payload = {
            "schema_version": "1.0.0",
            "tenant": "acme",
            "correlation_id": "c1",
            "source": "sensor",
            "findings": [{"host": "10.20.5.5", "port": "443/tcp", "oid": "o1"}],
        }

    def test_sem_bearer_401(self):
        resp = self.client.post(self.url, self.payload, format="json")
        self.assertEqual(resp.status_code, 401)

    def test_bearer_errado_401(self):
        resp = self.client.post(self.url, self.payload, format="json",
                                HTTP_AUTHORIZATION="Bearer errado")
        self.assertEqual(resp.status_code, 401)

    @mock.patch("Suricatoos.tasks.import_sensor_findings.delay")
    def test_bearer_ok_202_dispatcha(self, mock_delay):
        resp = self.client.post(self.url, self.payload, format="json",
                                HTTP_AUTHORIZATION="Bearer sc-secret")
        self.assertEqual(resp.status_code, 202)
        # Dispatchou a task com o tenant + findings.
        mock_delay.assert_called_once()
        args = mock_delay.call_args[0]
        self.assertEqual(args[0], "acme")
        self.assertEqual(len(args[2]), 1)

    @mock.patch("Suricatoos.tasks.import_sensor_findings.delay")
    def test_tenant_vazio_400(self, mock_delay):
        bad = dict(self.payload, tenant="")
        resp = self.client.post(self.url, bad, format="json",
                                HTTP_AUTHORIZATION="Bearer sc-secret")
        self.assertEqual(resp.status_code, 400)
        mock_delay.assert_not_called()


@override_settings(SURICATOOS_SENSOR_IMPORT_SECRET="")
class SensorImportDisabledTests(TestCase):
    def test_secret_vazio_nega_tudo(self):
        client = APIClient()
        resp = client.post("/api/sensor/import/", {"tenant": "acme"}, format="json",
                           HTTP_AUTHORIZATION="Bearer qualquer")
        self.assertEqual(resp.status_code, 401)

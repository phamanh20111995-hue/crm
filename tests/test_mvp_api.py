import json
import os
import sqlite3
import subprocess
import time
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API_URL = "http://127.0.0.1:8100"
DB_PATH = ROOT / "data" / "mvp_api.db"


def request_json(path: str, method: str = "GET", payload: dict | None = None, token: str | None = None) -> tuple[int, dict]:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{API_URL}{path}", data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


class TestMvpApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if DB_PATH.exists():
            DB_PATH.unlink()
        cls.proc = subprocess.Popen(
            ["python", "backend/mvp_api.py"],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(50):
            try:
                status, body = request_json("/health")
                if status == 200 and body.get("ok") is True:
                    return
            except Exception:
                pass
            time.sleep(0.1)
        raise RuntimeError("API server did not start in time.")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=5)

    def test_missing_credentials_uses_standard_error_shape(self):
        status, body = request_json("/auth/login", method="POST", payload={"user_code": "admin"})
        self.assertEqual(status, 400)
        self.assertIn("error", body)
        self.assertEqual(body["error"]["code"], "missing_credentials")
        self.assertIn("message", body["error"])

    def test_payments_missing_fields_returns_fields_list(self):
        status, body = request_json("/api/payments", method="POST", payload={"invoice_id": 1})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "missing_fields")
        self.assertIn("fields", body["error"])
        self.assertIn("branch_code", body["error"]["fields"])

    def test_admin_can_approve_hoan_khach(self):
        status, login = request_json("/auth/login", method="POST", payload={"user_code": "admin", "password": "123456"})
        self.assertEqual(status, 200)
        token = login["token"]

        status, invoice = request_json(
            "/api/invoices",
            method="POST",
            payload={
                "branch_code": "HN",
                "invoice_no": "INV-T-0001",
                "seller_code": "tele01",
                "sale_result": "Đã mua",
                "actual_revenue": 1000000,
            },
        )
        self.assertEqual(status, 201)

        status, req = request_json(
            "/api/hoan-khach/request",
            method="POST",
            payload={
                "invoice_id": invoice["id"],
                "requested_by_code": "tele01",
                "reason_group": "DN từ chối nhận",
                "reason_detail": "khách hủy sau xác nhận",
            },
        )
        self.assertEqual(status, 201)

        status, decision = request_json(
            "/api/hoan-khach/approve",
            method="POST",
            token=token,
            payload={"request_id": req["id"], "decision": "approve"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(decision["status"], "approved")

    def test_admin_can_read_audit_logs(self):
        status, login = request_json("/auth/login", method="POST", payload={"user_code": "admin", "password": "123456"})
        self.assertEqual(status, 200)
        token = login["token"]

        status, _ = request_json(
            "/api/kpi/monthly/upsert",
            method="POST",
            token=token,
            payload={"month_key": "2026-04", "user_code": "admin", "branch_code": "HN"},
        )
        self.assertEqual(status, 200)

        status, logs = request_json("/api/admin/audit-logs?limit=10", method="GET", token=token)
        self.assertEqual(status, 200)
        self.assertIn("items", logs)
        self.assertTrue(any(item.get("action") == "kpi_monthly_upsert" for item in logs["items"]))

    def test_reassign_lead_requires_leader_or_admin(self):
        status, created = request_json(
            "/api/leads",
            method="POST",
            payload={"branch_code": "HN", "platform": "Facebook", "page_qualified": True},
        )
        self.assertEqual(status, 201)
        lead_id = created["id"]

        status, staff_login = request_json("/auth/login", method="POST", payload={"user_code": "tele01", "password": "123456"})
        self.assertEqual(status, 200)
        staff_token = staff_login["token"]

        status, _ = request_json(
            f"/api/leads/{lead_id}/reassign",
            method="POST",
            token=staff_token,
            payload={"new_tele_owner_code": "tele02"},
        )
        self.assertEqual(status, 403)

        status, leader_login = request_json("/auth/login", method="POST", payload={"user_code": "tl_hn", "password": "123456"})
        self.assertEqual(status, 200)
        leader_token = leader_login["token"]

        status, reassigned = request_json(
            f"/api/leads/{lead_id}/reassign",
            method="POST",
            token=leader_token,
            payload={"new_tele_owner_code": "tele02"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(reassigned["tele_owner_code"], "tele02")

    def test_admin_can_export_and_delete_customer_invoice(self):
        status, login = request_json("/auth/login", method="POST", payload={"user_code": "admin", "password": "123456"})
        self.assertEqual(status, 200)
        token = login["token"]

        status, lead = request_json(
            "/api/leads",
            method="POST",
            payload={"branch_code": "HN", "platform": "Facebook", "page_qualified": True, "customer_name": "Demo"},
        )
        self.assertEqual(status, 201)

        status, invoice = request_json(
            "/api/invoices",
            method="POST",
            payload={
                "branch_code": "HN",
                "invoice_no": f"INV-T-{lead['id']}",
                "seller_code": "tele01",
                "sale_result": "Đã mua",
                "lead_id": lead["id"],
            },
        )
        self.assertEqual(status, 201)

        status, exported = request_json("/api/admin/customers/export", method="POST", token=token, payload={})
        self.assertEqual(status, 200)
        self.assertGreaterEqual(exported["count"], 1)

        status, _ = request_json(f"/api/admin/customers/{lead['id']}", method="DELETE", token=token)
        self.assertEqual(status, 200)

        status, _ = request_json(f"/api/admin/invoices/{invoice['id']}", method="DELETE", token=token)
        self.assertEqual(status, 200)

    def test_session_expires_after_ttl(self):
        status, login = request_json("/auth/login", method="POST", payload={"user_code": "admin", "password": "123456"})
        self.assertEqual(status, 200)
        token = login["token"]

        expired_at = (datetime.utcnow() - timedelta(hours=24)).isoformat(timespec="seconds") + "Z"
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("UPDATE auth_sessions SET created_at = ? WHERE token = ?", (expired_at, token))

        status, body = request_json("/auth/me", method="GET", token=token)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "unauthorized")

    def test_login_rate_limit_after_repeated_failures(self):
        payload = {"user_code": "unknown_user_for_limit", "password": "wrong"}
        for _ in range(5):
            status, body = request_json("/auth/login", method="POST", payload=payload)
            self.assertEqual(status, 401)
            self.assertEqual(body["error"]["code"], "invalid_credentials")

        status, body = request_json("/auth/login", method="POST", payload=payload)
        self.assertEqual(status, 429)
        self.assertEqual(body["error"]["code"], "too_many_login_attempts")

    def test_production_preflight_blocks_default_passwords(self):
        env = os.environ.copy()
        env["CRM_ENV"] = "production"
        env["CRM_COOKIE_SECURE"] = "1"
        env["CRM_COOKIE_SAMESITE"] = "Strict"
        env["CRM_PORT"] = "8111"
        p = subprocess.Popen(
            ["python", "backend/mvp_api.py"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        out, err = p.communicate(timeout=5)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("Production preflight failed", out + err)

    def test_admin_can_reset_user_password(self):
        status, login = request_json("/auth/login", method="POST", payload={"user_code": "admin", "password": "123456"})
        self.assertEqual(status, 200)
        token = login["token"]

        status, body = request_json(
            "/api/admin/users/reset-password",
            method="POST",
            token=token,
            payload={"user_code": "page01", "new_password": "page01_new_pw"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["user_code"], "page01")

        status, _ = request_json("/auth/login", method="POST", payload={"user_code": "page01", "password": "123456"})
        self.assertEqual(status, 401)

        status, _ = request_json("/auth/login", method="POST", payload={"user_code": "page01", "password": "page01_new_pw"})
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()

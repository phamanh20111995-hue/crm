from __future__ import annotations

import json
import secrets
import sqlite3
import hashlib
import hmac
import os
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("CRM_DB_PATH", str(BASE_DIR / "data" / "mvp_api.db")))
SESSION_TTL_HOURS = int(os.getenv("CRM_SESSION_TTL_HOURS", "12"))
LOGIN_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("CRM_LOGIN_LIMIT_WINDOW_SECONDS", "60"))
LOGIN_RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv("CRM_LOGIN_LIMIT_MAX_ATTEMPTS", "5"))
LOGIN_RATE_LIMIT_BLOCK_SECONDS = int(os.getenv("CRM_LOGIN_LIMIT_BLOCK_SECONDS", "120"))
SERVER_HOST = os.getenv("CRM_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("CRM_PORT", "8100"))
COOKIE_SAMESITE = os.getenv("CRM_COOKIE_SAMESITE", "Lax")
COOKIE_SECURE = os.getenv("CRM_COOKIE_SECURE", "0") == "1"
APP_ENV = os.getenv("CRM_ENV", "development").lower()
LOGIN_ATTEMPTS: dict[str, list[datetime]] = {}


def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def hash_password(raw_password: str) -> str:
    iterations = 120_000
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", raw_password.encode("utf-8"), salt.encode("utf-8"), iterations).hex()
    return f"pbkdf2_sha256${iterations}${salt}${digest}"


def verify_password(raw_password: str, stored_password: str) -> bool:
    if not stored_password:
        return False
    if stored_password.startswith("pbkdf2_sha256$"):
        parts = stored_password.split("$")
        # New format: pbkdf2_sha256$120000$salt_hex$digest_hex
        if len(parts) == 4:
            _, iter_str, salt, expected_digest = parts
            try:
                iterations = int(iter_str)
            except ValueError:
                return False
            digest = hashlib.pbkdf2_hmac(
                "sha256",
                raw_password.encode("utf-8"),
                salt.encode("utf-8"),
                iterations,
            ).hex()
            return hmac.compare_digest(digest, expected_digest)
        # Legacy format kept for backward compatibility: pbkdf2_sha256$digest_hex
        if len(parts) == 2:
            legacy_digest = hashlib.pbkdf2_hmac(
                "sha256", raw_password.encode("utf-8"), b"crm_mvp_salt_v1", 120_000
            ).hex()
            return hmac.compare_digest(legacy_digest, parts[1])
        return False
    # Backward compatibility for demo DBs seeded with plaintext previously.
    return raw_password == stored_password


def is_default_password(stored_password: str) -> bool:
    return verify_password("123456", stored_password)


def parse_iso_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _login_rate_limit_key(user_code: str, ip: str) -> str:
    return f"{ip}:{(user_code or '').strip().lower()}"


def check_login_rate_limit(user_code: str, ip: str) -> bool:
    now = datetime.utcnow()
    key = _login_rate_limit_key(user_code, ip)
    attempts = LOGIN_ATTEMPTS.get(key, [])
    recent = [t for t in attempts if (now - t).total_seconds() <= LOGIN_RATE_LIMIT_BLOCK_SECONDS]
    LOGIN_ATTEMPTS[key] = recent
    if len(recent) < LOGIN_RATE_LIMIT_MAX_ATTEMPTS:
        return True
    oldest = recent[0]
    return (now - oldest).total_seconds() > LOGIN_RATE_LIMIT_BLOCK_SECONDS


def register_login_failure(user_code: str, ip: str) -> None:
    now = datetime.utcnow()
    key = _login_rate_limit_key(user_code, ip)
    attempts = LOGIN_ATTEMPTS.get(key, [])
    attempts = [t for t in attempts if (now - t).total_seconds() <= LOGIN_RATE_LIMIT_WINDOW_SECONDS]
    attempts.append(now)
    LOGIN_ATTEMPTS[key] = attempts


def clear_login_failures(user_code: str, ip: str) -> None:
    LOGIN_ATTEMPTS.pop(_login_rate_limit_key(user_code, ip), None)


def build_session_cookie(token: str, max_age: int | None = None) -> str:
    parts = [f"crm_token={token}", "Path=/", "HttpOnly", f"SameSite={COOKIE_SAMESITE}"]
    if COOKIE_SECURE:
        parts.append("Secure")
    if max_age is not None:
        parts.append(f"Max-Age={max_age}")
    return "; ".join(parts)


def run_production_preflight(conn: sqlite3.Connection) -> None:
    if APP_ENV != "production":
        return
    errors: list[str] = []
    if not COOKIE_SECURE:
        errors.append("CRM_COOKIE_SECURE=1 is required in production.")
    if COOKIE_SAMESITE.lower() != "strict":
        errors.append("CRM_COOKIE_SAMESITE=Strict is required in production.")
    if SESSION_TTL_HOURS > 24:
        errors.append("CRM_SESSION_TTL_HOURS must be <= 24 in production.")
    if LOGIN_RATE_LIMIT_MAX_ATTEMPTS > 10:
        errors.append("CRM_LOGIN_LIMIT_MAX_ATTEMPTS must be <= 10 in production.")

    weak_users = [
        (row[0],)
        for row in conn.execute("SELECT user_code, password FROM users WHERE active = 1").fetchall()
        if is_default_password(row[1])
    ]
    if weak_users:
        users = ", ".join([r[0] for r in weak_users])
        errors.append(f"Default password still active for users: {users}. Rotate passwords before production.")

    if errors:
        raise RuntimeError("Production preflight failed: " + " | ".join(errors))


def ensure_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS leads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                branch_code TEXT NOT NULL,
                customer_name TEXT,
                customer_phone TEXT,
                platform TEXT NOT NULL,
                campaign_name TEXT,
                service_interest TEXT,
                page_qualified INTEGER NOT NULL DEFAULT 0,
                page_owner_code TEXT,
                tele_owner_code TEXT,
                sale_owner_code TEXT,
                lead_status TEXT NOT NULL DEFAULT 'new',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tele_call_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lead_id INTEGER NOT NULL,
                call_no INTEGER NOT NULL,
                tele_owner_code TEXT NOT NULL,
                call_status TEXT NOT NULL,
                call_result TEXT NOT NULL,
                appointment_at TEXT,
                appointment_confirm_status TEXT,
                next_follow_up_at TEXT,
                note TEXT,
                created_at TEXT NOT NULL,
                UNIQUE (lead_id, call_no)
            );

            CREATE TABLE IF NOT EXISTS invoices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                branch_code TEXT NOT NULL,
                lead_id INTEGER,
                invoice_no TEXT UNIQUE NOT NULL,
                seller_code TEXT NOT NULL,
                sale_result TEXT NOT NULL,
                actual_revenue REAL NOT NULL DEFAULT 0,
                debt_revenue REAL NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                deleted_at TEXT
            );

            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                branch_code TEXT NOT NULL,
                invoice_id INTEGER NOT NULL,
                paid_amount REAL NOT NULL,
                paid_at TEXT NOT NULL,
                method TEXT,
                created_by_code TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS hoan_khach_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invoice_id INTEGER NOT NULL,
                requested_by_code TEXT NOT NULL,
                reason_group TEXT NOT NULL,
                reason_detail TEXT NOT NULL,
                evidence_url TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                approved_by_branch_manager_code TEXT,
                decided_at TEXT,
                decision_note TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_code TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                role_code TEXT NOT NULL,
                branch_code TEXT,
                team_code TEXT,
                manager_user_code TEXT,
                password TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS auth_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                user_code TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS kpi_monthly_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                month_key TEXT NOT NULL,
                user_code TEXT NOT NULL,
                branch_code TEXT NOT NULL,
                team_code TEXT,
                inbox_count INTEGER NOT NULL DEFAULT 0,
                qualified_data_count INTEGER NOT NULL DEFAULT 0,
                tele_data_count INTEGER NOT NULL DEFAULT 0,
                tele_arrived_count INTEGER NOT NULL DEFAULT 0,
                sale_order_count INTEGER NOT NULL DEFAULT 0,
                actual_collected_revenue REAL NOT NULL DEFAULT 0,
                debt_revenue REAL NOT NULL DEFAULT 0,
                ad_cost REAL NOT NULL DEFAULT 0,
                committed_target_revenue REAL NOT NULL DEFAULT 0,
                UNIQUE(month_key, user_code)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_user_code TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT,
                detail_json TEXT,
                created_at TEXT NOT NULL
            );
            """
        )

        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count == 0:
            conn.executemany(
                """
                INSERT INTO users (
                    user_code, full_name, role_code, branch_code, team_code, manager_user_code, password, active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                """,
                [
                    ("admin", "System Admin", "ADMIN", None, None, None, hash_password("123456")),
                    ("bm_hn", "Branch Manager HN", "BRANCH_MANAGER", "HN", None, None, hash_password("123456")),
                    ("tl_hn", "Tele Leader HN", "LEADER", "HN", "TELE", "bm_hn", hash_password("123456")),
                    ("tele01", "Tele 01", "STAFF", "HN", "TELE", "tl_hn", hash_password("123456")),
                    ("page01", "Page 01", "STAFF", "HN", "PAGE", "bm_hn", hash_password("123456")),
                ],
            )
        else:
            # Migrate old plaintext passwords to hashed representation.
            rows = conn.execute("SELECT id, password FROM users").fetchall()
            for row_id, pw in rows:
                if not pw:
                    continue
                if not str(pw).startswith("pbkdf2_sha256$"):
                    conn.execute("UPDATE users SET password = ? WHERE id = ?", (hash_password(str(pw)), row_id))
        run_production_preflight(conn)


def parse_json(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length) if length else b"{}"
    return json.loads(raw.decode("utf-8"))


def send_json(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def send_api_error(
    handler: BaseHTTPRequestHandler,
    status: int,
    code: str,
    message: str,
    fields: list[str] | None = None,
) -> None:
    payload: dict = {"error": {"code": code, "message": message}}
    if fields:
        payload["error"]["fields"] = fields
    send_json(handler, status, payload)


def write_audit_log(
    actor_user_code: str,
    action: str,
    target_type: str,
    target_id: str | None = None,
    detail: dict | None = None,
) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO audit_logs (actor_user_code, action, target_type, target_id, detail_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                actor_user_code,
                action,
                target_type,
                target_id,
                json.dumps(detail or {}, ensure_ascii=False),
                now_iso(),
            ),
        )


def get_user_by_token(handler: BaseHTTPRequestHandler) -> dict | None:
    auth_header = handler.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header.replace("Bearer ", "", 1).strip()
    if not token:
        return None

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT u.user_code, u.full_name, u.role_code, u.branch_code, u.team_code, u.manager_user_code, s.created_at AS session_created_at
            FROM auth_sessions s
            JOIN users u ON u.user_code = s.user_code
            WHERE s.token = ? AND u.active = 1
            """,
            (token,),
        ).fetchone()
    if not row:
        return None

    user = _dict(row)
    created_at = parse_iso_ts(user.get("session_created_at"))
    if not created_at or datetime.utcnow() - created_at > timedelta(hours=SESSION_TTL_HOURS):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM auth_sessions WHERE token = ?", (token,))
        return None

    user.pop("session_created_at", None)
    return user

def get_user_by_token_value(token: str) -> dict | None:
    if not token:
        return None
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT u.user_code, u.full_name, u.role_code, u.branch_code, u.team_code, u.manager_user_code, s.created_at AS session_created_at
            FROM auth_sessions s
            JOIN users u ON u.user_code = s.user_code
            WHERE s.token = ? AND u.active = 1
            """,
            (token,),
        ).fetchone()
    if not row:
        return None
    user = dict(row)
    created_at = parse_iso_ts(user.get("session_created_at"))
    if not created_at or datetime.utcnow() - created_at > timedelta(hours=SESSION_TTL_HOURS):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM auth_sessions WHERE token = ?", (token,))
        return None
    user.pop("session_created_at", None)
    return user


def parse_form(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length).decode("utf-8") if length else ""
    parsed = parse_qs(raw)
    return {k: (v[0] if isinstance(v, list) and v else "") for k, v in parsed.items()}


def get_cookie_token(handler: BaseHTTPRequestHandler) -> str:
    cookie = handler.headers.get("Cookie", "")
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("crm_token="):
            return part.split("=", 1)[1].strip()
    return ""


def send_html(handler: BaseHTTPRequestHandler, status: int, html_body: str, set_cookie: str | None = None, location: str | None = None) -> None:
    body = html_body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    if set_cookie:
        handler.send_header("Set-Cookie", set_cookie)
    if location:
        handler.send_header("Location", location)
    handler.end_headers()
    handler.wfile.write(body)


def render_login(error: str = "") -> str:
    err = (
        f"<div class='alert'>{error}</div>"
        if error
        else ""
    )
    return f"""
    <html>
      <head>
        <meta charset='utf-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <title>CRM Login</title>
        <style>
          :root {{
            --bg: #f4f7fc;
            --card: #ffffff;
            --line: #dfe6f2;
            --text: #172b4d;
            --muted: #6b7a90;
            --primary: #2f6fff;
            --danger-bg: #fff2f2;
            --danger-text: #bc1c1c;
          }}
          * {{ box-sizing: border-box; }}
          body {{
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            background: radial-gradient(circle at 10% 10%, #eaf0ff 0%, var(--bg) 45%, #eef3fb 100%);
            font-family: Inter, Segoe UI, Arial, sans-serif;
            color: var(--text);
          }}
          .login-card {{
            width: min(420px, 92vw);
            background: var(--card);
            border: 1px solid var(--line);
            border-radius: 14px;
            box-shadow: 0 12px 35px rgba(20, 40, 80, 0.12);
            padding: 22px;
          }}
          h1 {{
            font-size: 22px;
            margin: 0 0 8px;
          }}
          .sub {{
            margin: 0 0 16px;
            color: var(--muted);
            font-size: 13px;
          }}
          .alert {{
            background: var(--danger-bg);
            color: var(--danger-text);
            border: 1px solid #ffd1d1;
            border-radius: 10px;
            padding: 10px;
            margin-bottom: 12px;
            font-size: 13px;
          }}
          label {{
            font-size: 13px;
            font-weight: 600;
            display: block;
            margin-bottom: 6px;
          }}
          input {{
            width: 100%;
            border: 1px solid var(--line);
            border-radius: 10px;
            padding: 10px 12px;
            margin-bottom: 12px;
          }}
          button {{
            width: 100%;
            border: none;
            border-radius: 10px;
            padding: 10px 12px;
            font-weight: 600;
            cursor: pointer;
            color: #fff;
            background: var(--primary);
          }}
          .hint {{
            margin: 12px 0 0;
            color: var(--muted);
            font-size: 12px;
          }}
        </style>
      </head>
      <body>
        <section class='login-card'>
          <h1>CRM Quản Trị</h1>
          <p class='sub'>Đăng nhập để quản lý lead, doanh thu, KPI và vận hành chi nhánh.</p>
          {err}
          <form method='post' action='/app/login'>
            <label>User code</label>
            <input name='user_code' autocomplete='username' />
            <label>Password</label>
            <input name='password' type='password' autocomplete='current-password' />
            <button>Đăng nhập</button>
          </form>
          <p class='hint'>Demo account: <b>bm_hn / 123456</b></p>
        </section>
      </body>
    </html>
    """


def render_sidebar(active: str) -> str:
    groups = [
        ("Lead Pipeline", "/app/leads", "leads"),
        ("Invoices", "/app/invoices", "invoices"),
        ("KPI Monthly", "/app/kpi", "kpi"),
        ("Hoàn khách", "/app/hoan-khach", "hoan-khach"),
    ]
    links = "".join(
        [
            f"<a class='{'active' if active == key else ''}' href='{href}'>{label}</a>"
            for label, href, key in groups
        ]
    )
    return f"""
      <aside class='sidebar'>
        <div class='brand'>
          <h2>CRM Pro</h2>
          <p>Vận hành · Doanh thu · KPI</p>
        </div>
        <nav class='menu'>
          {links}
        </nav>
        <a class='logout' href='/app/logout'>Đăng xuất</a>
      </aside>
    """


def render_layout(user: dict, title: str, subtitle: str, active: str, content: str) -> str:
    return f"""
    <html>
      <head>
        <meta charset='utf-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <title>{title}</title>
        <style>
          :root {{
            --bg: #f5f7fb;
            --card: #ffffff;
            --line: #e6ebf4;
            --text: #1b2b4a;
            --muted: #6e7e97;
            --primary: #2f6fff;
            --primary-soft: #ecf2ff;
            --ok: #15b37d;
            --warn: #ff9a1a;
            --danger: #f25c54;
          }}
          * {{ box-sizing: border-box; }}
          body {{
            margin: 0;
            background: var(--bg);
            color: var(--text);
            font-family: Inter, Segoe UI, Arial, sans-serif;
          }}
          .app {{
            display: grid;
            grid-template-columns: 248px 1fr;
            min-height: 100vh;
          }}
          .sidebar {{
            background: #fff;
            border-right: 1px solid var(--line);
            padding: 18px 14px;
          }}
          .brand {{
            border-radius: 12px;
            padding: 12px;
            color: #fff;
            background: linear-gradient(130deg, #18356c, #2f6fff);
            margin-bottom: 16px;
          }}
          .brand h2 {{ margin: 0; font-size: 18px; }}
          .brand p {{ margin: 6px 0 0; font-size: 12px; color: #dbe7ff; }}
          .menu a {{
            display: block;
            text-decoration: none;
            color: var(--text);
            border-radius: 10px;
            padding: 10px;
            margin-bottom: 6px;
            font-size: 13px;
            border: 1px solid transparent;
          }}
                    .menu a.active {{
            color: var(--primary);
            background: var(--primary-soft);
            border-color: #d5e3ff;
            font-weight: 700;
          }}
          .logout {{
            margin-top: 14px;
            display: inline-block;
            text-decoration: none;
            color: #d42f2f;
            border: 1px solid #ffd2d2;
            border-radius: 8px;
            padding: 6px 10px;
            font-size: 12px;
          }}
          .main {{
            padding: 24px;
            max-width: 1400px;
          }}
          .header {{
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            margin-bottom: 16px;
            gap: 16px;
          }}
          .header h1 {{ margin: 0; font-size: 26px; }}
          .meta {{ color: var(--muted); font-size: 13px; margin-top: 6px; }}
          .subtitle {{ color: var(--muted); margin-top: 6px; font-size: 14px; }}
          .card {{
            background: #fff;
            border: 1px solid var(--line);
            border-radius: 12px;
            padding: 14px;
            box-shadow: 0 8px 18px rgba(26, 45, 84, 0.05);
          }}
          .actions {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin-bottom: 12px;
          }}
          .actions .card {{
            min-width: 160px;
            margin: 0;
          }}
          .status-tab {{
            background: #fff;
            border: 1px solid var(--line);
            border-radius: 10px;
            padding: 9px 10px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 12px;
            min-width: 120px;
          }}
          .status-tab b {{
            padding: 2px 7px;
            border-radius: 999px;
            color: #fff;
            background: var(--warn);
            font-size: 11px;
          }}
          .status-tab.active {{
            border-color: #c8d9ff;
            background: var(--primary-soft);
            color: var(--primary);
            font-weight: 600;
          }}
          .btn {{
            border: none;
            border-radius: 10px;
            background: var(--primary);
            color: #fff;
            font-weight: 700;
            padding: 10px 14px;
            text-decoration: none;
            display: inline-block;
            cursor: pointer;
          }}
          .btn.secondary {{
            background: #fff;
            color: var(--text);
            border: 1px solid var(--line);
            font-weight: 600;
          }}
          label {{
            display: block;
            margin-bottom: 4px;
            color: var(--muted);
            font-size: 12px;
          }}
          input, select, button {{
            width: 100%;
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 9px 10px;
            font-size: 13px;
            background: #fff;
          }}
          form.grid {{
            display: grid;
            grid-template-columns: repeat(4, minmax(120px, 1fr));
            gap: 10px;
            align-items: end;
          }}
          .table-card {{
            margin-top: 12px;
            background: #fff;
            border: 1px solid var(--line);
            border-radius: 12px;
            box-shadow: 0 8px 18px rgba(26, 45, 84, 0.05);
            overflow: hidden;
          }}
          .table-card h3 {{ margin: 0; padding: 14px 14px 4px; font-size: 15px; }}
          .table-wrap {{ overflow: auto; padding: 0 14px 14px; }}
          table {{ width: 100%; border-collapse: collapse; min-width: 920px; }}
          th, td {{
            border-bottom: 1px solid var(--line);
            padding: 11px 10px;
            font-size: 13px;
            text-align: left;
            white-space: nowrap;
          }}
          th {{ background: #f8fbff; color: #475d80; }}
          @media (max-width: 1220px) {{
            .app {{ grid-template-columns: 1fr; }}
            .sidebar {{ border-right: 0; border-bottom: 1px solid var(--line); }}
            .main {{ padding: 16px; }}
            form.grid {{ grid-template-columns: 1fr 1fr; }}
          }}
        </style>
      </head>
      <body>
        <div class='app'>
          {render_sidebar(active)}
          <main class='main'>
            <div class='header'>
              <div>
                <h1>{title}</h1>
                <div class='meta'>Xin chào <b>{user['full_name']}</b> ({user['role_code']}) · Chi nhánh: {user.get('branch_code') or '-'}</div>
                <div class='subtitle'>{subtitle}</div>
              </div>
            </div>
            {content}
          </main>
        </div>
      </body>
    </html>
    """


def render_leads_page(
    user: dict,
    leads: list[sqlite3.Row],
    kpis: list[sqlite3.Row],
    kpi_scope: str,
    kpi_month: str,
) -> str:
    lead_status_counts: dict[str, int] = {}
    for lead in leads:
        key = (lead["lead_status"] or "new").strip()
        lead_status_counts[key] = lead_status_counts.get(key, 0) + 1

    status_tabs = [
        ("Tất cả", len(leads), True),
        ("new", lead_status_counts.get("new", 0), False),
        ("contacted", lead_status_counts.get("contacted", 0), False),
        ("appointment", lead_status_counts.get("appointment", 0), False),
        ("closed_won", lead_status_counts.get("closed_won", 0), False),
        ("closed_lost", lead_status_counts.get("closed_lost", 0), False),
    ]
    tabs_html = "".join(
        [
            f"<div class='status-tab {'active' if active else ''}'><span>{label}</span><b>{count}</b></div>"
            for label, count, active in status_tabs
        ]
    )

    rows = "".join(
        [
            "<tr>"
            f"<td>{r['id']}</td><td>{r['customer_name'] or ''}</td><td>{r['customer_phone'] or ''}</td><td>{r['platform']}</td>"
            f"<td>{r['campaign_name'] or ''}</td><td>{r['service_interest'] or ''}</td><td>{r['lead_status']}</td>"
            "</tr>"
            for r in leads
        ]
    )
    kpi_data = sum(int(r["tele_data_count"] or 0) for r in kpis)
    kpi_arrived = sum(int(r["tele_arrived_count"] or 0) for r in kpis)
    kpi_revenue = sum(float(r["actual_collected_revenue"] or 0) for r in kpis)
    kpi_cards = (
        f"<section class='actions'>"
        f"<div class='card'><label>Data Tele</label><div><b>{kpi_data}</b></div></div>"
        f"<div class='card'><label>Đã đến</label><div><b>{kpi_arrived}</b></div></div>"
        f"<div class='card'><label>Doanh thu thực</label><div><b>{kpi_revenue:.0f}</b></div></div>"
        "</section>"
    )
    content = f"""
      <section class='actions'>
        <a class='btn' href='/app/leads/new'>+ Thêm mới</a>
        <a class='btn secondary' href='/app/calls'>Ghi Call Log</a>
        <a class='btn secondary' href='/app/invoices'>Invoices & Payments</a>
      </section>
      <section class='card'>
        <form class='grid' method='get' action='/app/leads'>
          <div>
            <label>Scope KPI</label>
            <select name='kpi_scope'>
              <option value='self' {'selected' if kpi_scope=='self' else ''}>self</option>
              <option value='team' {'selected' if kpi_scope=='team' else ''}>team</option>
              <option value='branch' {'selected' if kpi_scope=='branch' else ''}>branch</option>
              <option value='all' {'selected' if kpi_scope=='all' else ''}>all</option>
            </select>
          </div>
          <div>
            <label>Tháng KPI</label>
            <input name='kpi_month' value='{kpi_month}'>
          </div>
          <button class='btn'>Lọc</button>
        </form>
      </section>
      <section class='actions'>{tabs_html}</section>
      {kpi_cards}
      <section class='table-card'>
        <h3>Danh sách Lead</h3>
        <div class='table-wrap'>
          <table>
            <tr><th>ID</th><th>Tên KH</th><th>SĐT</th><th>Platform</th><th>Campaign</th><th>Dịch vụ</th><th>Status</th></tr>
            {rows}
          </table>
        </div>
      </section>
    """
    return render_layout(
        user=user,
        title="Lead Pipeline",
        subtitle="Màn hình quản lý lead tập trung: lọc, theo dõi trạng thái và theo dõi KPI nhanh.",
        active="leads",
        content=content,
    )
    def render_lead_create_page(user: dict) -> str:
    content = f"""
      <section class='card'>
        <h3>Tạo Lead mới</h3>
        <form class='grid' method='post' action='/app/leads/create'>
          <div><label>Branch</label><input name='branch_code' value='{user.get('branch_code') or 'HN'}'></div>
          <div><label>Platform</label><input name='platform' value='Facebook'></div>
          <div><label>Phone</label><input name='customer_phone'></div>
          <div><label>Qualified</label><select name='page_qualified'><option value='0'>0</option><option value='1'>1</option></select></div>
          <button class='btn'>Tạo Lead</button>
        </form>
      </section>
    """
    return render_layout(user, "Tạo Lead", "Tạo lead mới cho pipeline.", "leads", content)


def render_calls_page(user: dict) -> str:
    content = """
      <section class='card'>
        <h3>Ghi Call Log (Tele)</h3>
        <form class='grid' method='post' action='/app/calls/create'>
          <div><label>Lead ID</label><input name='lead_id'></div>
          <div><label>Lần gọi</label><input name='call_no' value='1'></div>
          <div><label>Tele</label><input name='tele_owner_code' value='tele01'></div>
          <div><label>Status</label><input name='call_status' value='Đã gọi'></div>
          <div><label>Result</label><input name='call_result' value='Đặt lịch'></div>
          <div><label>Appointment</label><input name='appointment_at' placeholder='2026-04-10T10:00:00'></div>
          <button class='btn'>Ghi Log</button>
        </form>
      </section>
    """
    return render_layout(user, "Tele Call Log", "Module ghi nhận lịch sử cuộc gọi tele.", "leads", content)


def render_invoices_page(user: dict, invoices: list[sqlite3.Row]) -> str:
    invoice_rows = "".join(
        [
            "<tr>"
            f"<td>{r['id']}</td><td>{r['invoice_no']}</td><td>{r['seller_code']}</td>"
            f"<td>{r['sale_result']}</td><td>{r['actual_revenue']}</td><td>{r['debt_revenue']}</td>"
            "</tr>"
            for r in invoices
        ]
    )
    content = f"""
      <section class='card'>
        <h3>Tạo Invoice</h3>
        <form class='grid' method='post' action='/app/invoices/create'>
          <div><label>Branch</label><input name='branch_code' value='{user.get('branch_code') or 'HN'}'></div>
          <div><label>Lead ID</label><input name='lead_id'></div>
          <div><label>Invoice No</label><input name='invoice_no' placeholder='INV-0001'></div>
          <div><label>Seller</label><input name='seller_code' value='tele01'></div>
          <div><label>Kết quả TV</label><input name='sale_result' value='Đã mua'></div>
          <div><label>DT thực</label><input name='actual_revenue' value='0'></div>
          <div><label>DT nợ</label><input name='debt_revenue' value='0'></div>
          <button class='btn'>Tạo Invoice</button>
        </form>
      </section>
      <section class='card'>
        <h3>Tạo Payment</h3>
        <form class='grid' method='post' action='/app/payments/create'>
          <div><label>Branch</label><input name='branch_code' value='{user.get('branch_code') or 'HN'}'></div>
          <div><label>Invoice ID</label><input name='invoice_id'></div>
          <div><label>Paid Amount</label><input name='paid_amount'></div>
          <div><label>Paid At</label><input name='paid_at' placeholder='2026-04-10T10:00:00'></div>
          <div><label>Method</label><input name='method' value='Tiền mặt'></div>
          <button class='btn'>Tạo Payment</button>
        </form>
      </section>
      <section class='table-card'>
        <h3>Danh sách Invoice</h3>
        <div class='table-wrap'>
          <table>
            <tr><th>ID</th><th>Invoice No</th><th>Seller</th><th>Kết quả TV</th><th>DT thực</th><th>DT nợ</th></tr>
            {invoice_rows}
          </table>
        </div>
      </section>
    """
    return render_layout(user, "Invoices", "Quản lý hóa đơn và thanh toán.", "invoices", content)


def render_kpi_page(user: dict, kpis: list[sqlite3.Row], scope: str, month: str) -> str:
    kpi_rows = "".join(
        [
            "<tr>"
            f"<td>{r['month_key']}</td><td>{r['user_code']}</td><td>{r['team_code'] or ''}</td>"
            f"<td>{r['tele_data_count']}</td><td>{r['tele_arrived_count']}</td><td>{r['actual_collected_revenue']}</td>"
            "</tr>"
            for r in kpis
        ]
    )
    content = f"""
      <section class='card'>
        <form class='grid' method='get' action='/app/kpi'>
          <div>
            <label>Scope</label>
            <select name='kpi_scope'>
              <option value='self' {'selected' if scope=='self' else ''}>self</option>
              <option value='team' {'selected' if scope=='team' else ''}>team</option>
              <option value='branch' {'selected' if scope=='branch' else ''}>branch</option>
              <option value='all' {'selected' if scope=='all' else ''}>all</option>
            </select>
          </div>
          <div><label>Tháng</label><input name='kpi_month' value='{month}'></div>
          <button class='btn'>Lọc KPI</button>
        </form>
      </section>
      <section class='table-card'>
        <h3>KPI Monthly</h3>
        <div class='table-wrap'>
          <table>
            <tr><th>Month</th><th>User</th><th>Team</th><th>Data</th><th>Arrived</th><th>Actual Revenue</th></tr>
            {kpi_rows}
          </table>
        </div>
      </section>
    """
    return render_layout(user, "KPI Monthly", "Theo dõi KPI theo scope và theo tháng.", "kpi", content)


def render_hoan_khach_page(user: dict, hoan_requests: list[sqlite3.Row]) -> str:
    hoan_rows = "".join(
        [
            "<tr>"
            f"<td>{r['id']}</td><td>{r['invoice_id']}</td><td>{r['requested_by_code']}</td>"
            f"<td>{r['reason_group']}</td><td>{r['status']}</td><td>{r['approved_by_branch_manager_code'] or ''}</td>"
            "</tr>"
            for r in hoan_requests
        ]
    )
    content = """
      <section class='card'>
        <h3>Tạo yêu cầu Hoàn khách</h3>
        <form class='grid' method='post' action='/app/hoan-khach/request'>
          <div><label>Invoice ID</label><input name='invoice_id'></div>
          <div><label>Reason Group</label><input name='reason_group' value='DN từ chối nhận'></div>
          <div><label>Reason Detail</label><input name='reason_detail'></div>
          <div><label>Evidence URL</label><input name='evidence_url'></div>
          <button class='btn'>Tạo Request</button>
        </form>
      </section>
      <section class='card'>
        <h3>Duyệt Hoàn khách</h3>
        <form class='grid' method='post' action='/app/hoan-khach/approve'>
          <div><label>Request ID</label><input name='request_id'></div>
          <div><label>Decision</label><select name='decision'><option value='approve'>approve</option><option value='reject'>reject</option></select></div>
          <div><label>Note</label><input name='decision_note'></div>
          <button class='btn'>Duyệt</button>
        </form>
      </section>
    """
    content += f"""
      <section class='table-card'>
        <h3>Danh sách yêu cầu hoàn khách</h3>
        <div class='table-wrap'>
          <table>
            <tr><th>ID</th><th>Invoice ID</th><th>Requested by</th><th>Reason Group</th><th>Status</th><th>Approved by</th></tr>
            {hoan_rows}
          </table>
        </div>
      </section>
    """
    return render_layout(user, "Hoàn khách", "Quản lý request và duyệt hoàn khách.", "hoan-khach", content)


def require_auth(handler: BaseHTTPRequestHandler) -> dict | None:
    user = get_user_by_token(handler)
    if not user:
        send_api_error(handler, 401, "unauthorized", "Bearer token is missing or invalid.")
        return None
    return user


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/app/login":
            return send_html(self, 200, render_login())
        if parsed.path == "/app/logout":
            return send_html(
                self,
                302,
                "",
                set_cookie=build_session_cookie("", max_age=0),
                location="/app/login",
            )
                    if parsed.path == "/app/leads":
            token = get_cookie_token(self)
            user = get_user_by_token_value(token)
            if not user:
                return send_html(self, 302, "", location="/app/login")
            qs = parse_qs(parsed.query)
            kpi_scope = (qs.get("kpi_scope", ["self"])[0] or "self").strip()
            kpi_month = (qs.get("kpi_month", [datetime.utcnow().strftime("%Y-%m")])[0] or datetime.utcnow().strftime("%Y-%m")).strip()

            where = ["month_key = ?"]
            args: list = [kpi_month]
            if kpi_scope == "self":
                where.append("user_code = ?")
                args.append(user["user_code"])
            elif kpi_scope == "team":
                if user["role_code"] not in ("LEADER", "BRANCH_MANAGER", "ADMIN"):
                    return send_html(self, 200, "<p>Bạn không có quyền scope team. <a href='/app/leads'>Quay lại</a></p>")
                where.append("team_code = ?")
                args.append(user.get("team_code"))
                where.append("branch_code = ?")
                args.append(user.get("branch_code"))
            elif kpi_scope == "branch":
                if user["role_code"] not in ("BRANCH_MANAGER", "ADMIN"):
                    return send_html(self, 200, "<p>Bạn không có quyền scope branch. <a href='/app/leads'>Quay lại</a></p>")
                where.append("branch_code = ?")
                args.append(user.get("branch_code"))
            elif kpi_scope == "all":
                if user["role_code"] != "ADMIN":
                    return send_html(self, 200, "<p>Scope all chỉ dành cho Admin. <a href='/app/leads'>Quay lại</a></p>")
            else:
                kpi_scope = "self"
                where.append("user_code = ?")
                args.append(user["user_code"])

            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                leads = conn.execute(
                    "SELECT id, customer_name, customer_phone, platform, campaign_name, service_interest, lead_status FROM leads ORDER BY id DESC LIMIT 100"
                ).fetchall()
                kpis = conn.execute(
                    f"""
                    SELECT month_key, user_code, team_code, tele_data_count, tele_arrived_count, actual_collected_revenue
                    FROM kpi_monthly_snapshots
                    WHERE {' AND '.join(where)}
                    ORDER BY month_key DESC, user_code
                    LIMIT 100
                    """,
                    args,
                ).fetchall()
            return send_html(self, 200, render_leads_page(user, leads, kpis, kpi_scope, kpi_month))
        if parsed.path == "/app/leads/new":
            token = get_cookie_token(self)
            user = get_user_by_token_value(token)
            if not user:
                return send_html(self, 302, "", location="/app/login")
            return send_html(self, 200, render_lead_create_page(user))
        if parsed.path == "/app/calls":
            token = get_cookie_token(self)
            user = get_user_by_token_value(token)
            if not user:
                return send_html(self, 302, "", location="/app/login")
            return send_html(self, 200, render_calls_page(user))
        if parsed.path == "/app/invoices":
            token = get_cookie_token(self)
            user = get_user_by_token_value(token)
            if not user:
                return send_html(self, 302, "", location="/app/login")
            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                invoices = conn.execute(
                    "SELECT id, invoice_no, seller_code, sale_result, actual_revenue, debt_revenue FROM invoices ORDER BY id DESC LIMIT 100"
                ).fetchall()
            return send_html(self, 200, render_invoices_page(user, invoices))
        if parsed.path == "/app/kpi":
            token = get_cookie_token(self)
            user = get_user_by_token_value(token)
            if not user:
                return send_html(self, 302, "", location="/app/login")
            qs = parse_qs(parsed.query)
            kpi_scope = (qs.get("kpi_scope", ["self"])[0] or "self").strip()
            kpi_month = (qs.get("kpi_month", [datetime.utcnow().strftime("%Y-%m")])[0] or datetime.utcnow().strftime("%Y-%m")).strip()

            where = ["month_key = ?"]
            args: list = [kpi_month]
            if kpi_scope == "self":
                where.append("user_code = ?")
                args.append(user["user_code"])
            elif kpi_scope == "team":
                if user["role_code"] not in ("LEADER", "BRANCH_MANAGER", "ADMIN"):
                    return send_html(self, 200, "<p>Bạn không có quyền scope team. <a href='/app/kpi'>Quay lại</a></p>")
                where.append("team_code = ?")
                args.append(user.get("team_code"))
                where.append("branch_code = ?")
                args.append(user.get("branch_code"))
            elif kpi_scope == "branch":
                if user["role_code"] not in ("BRANCH_MANAGER", "ADMIN"):
                    return send_html(self, 200, "<p>Bạn không có quyền scope branch. <a href='/app/kpi'>Quay lại</a></p>")
                where.append("branch_code = ?")
                args.append(user.get("branch_code"))
            elif kpi_scope == "all":
                if user["role_code"] != "ADMIN":
                    return send_html(self, 200, "<p>Scope all chỉ dành cho Admin. <a href='/app/kpi'>Quay lại</a></p>")
            else:
                kpi_scope = "self"
                where.append("user_code = ?")
                args.append(user["user_code"])

            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                kpis = conn.execute(
                    f"""
                    SELECT month_key, user_code, team_code, tele_data_count, tele_arrived_count, actual_collected_revenue
                    FROM kpi_monthly_snapshots
                    WHERE {' AND '.join(where)}
                    ORDER BY month_key DESC, user_code
                    LIMIT 100
                    """,
                    args,
                ).fetchall()
            return send_html(self, 200, render_kpi_page(user, kpis, kpi_scope, kpi_month))
        if parsed.path == "/app/hoan-khach":
            token = get_cookie_token(self)
            user = get_user_by_token_value(token)
            if not user:
                return send_html(self, 302, "", location="/app/login")
            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                hoan_requests = conn.execute(
                    "SELECT id, invoice_id, requested_by_code, reason_group, status, approved_by_branch_manager_code FROM hoan_khach_requests ORDER BY id DESC LIMIT 100"
                ).fetchall()
            return send_html(self, 200, render_hoan_khach_page(user, hoan_requests))
        if parsed.path == "/health":
            return send_json(
                self,
                200,
                {
                    "ok": True,
                    "service": "mvp_api",
                    "env": APP_ENV,
                    "db": str(DB_PATH),
                    "session_ttl_hours": SESSION_TTL_HOURS,
                    "login_rate_limit": {
                        "window_seconds": LOGIN_RATE_LIMIT_WINDOW_SECONDS,
                        "max_attempts": LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
                        "block_seconds": LOGIN_RATE_LIMIT_BLOCK_SECONDS,
                    },
                },
            )
        if parsed.path == "/api/leads":
            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT id, branch_code, customer_name, customer_phone, platform, campaign_name, service_interest, page_qualified, tele_owner_code, lead_status, created_at FROM leads ORDER BY id DESC LIMIT 100"
                ).fetchall()
            return send_json(self, 200, {"items": [dict(r) for r in rows]})
        if parsed.path == "/auth/me":
            user = require_auth(self)
            if not user:
                return
            return send_json(self, 200, {"user": user})
        if parsed.path == "/api/kpi/monthly":
            user = require_auth(self)
            if not user:
                return

            # scope: self/team/branch/all (all only admin)
            query = parsed.query or ""
            qs = {}
            for part in query.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    qs[k] = v
            scope = qs.get("scope", "self")
            month_key = qs.get("month", datetime.utcnow().strftime("%Y-%m"))

            where = ["month_key = ?"]
            args: list = [month_key]

            if scope == "self":
                where.append("user_code = ?")
                args.append(user["user_code"])
            elif scope == "team":
                if user["role_code"] not in ("LEADER", "BRANCH_MANAGER", "ADMIN"):
                    return send_api_error(self, 403, "forbidden_scope", "You are not allowed to view team scope.")
                where.append("team_code = ?")
                args.append(user.get("team_code"))
                where.append("branch_code = ?")
                args.append(user.get("branch_code"))
            elif scope == "branch":
                if user["role_code"] not in ("BRANCH_MANAGER", "ADMIN"):
                    return send_api_error(self, 403, "forbidden_scope", "You are not allowed to view branch scope.")
                where.append("branch_code = ?")
                args.append(user.get("branch_code"))
            elif scope == "all":
                if user["role_code"] != "ADMIN":
                    return send_api_error(self, 403, "admin_only", "This scope is only available to admin.")
            else:
                return send_api_error(self, 400, "invalid_scope", "Scope must be one of self/team/branch/all.")

            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    f"""
                    SELECT month_key, user_code, branch_code, team_code, inbox_count,
                           qualified_data_count, tele_data_count, tele_arrived_count,
                           sale_order_count, actual_collected_revenue, debt_revenue,
                           ad_cost, committed_target_revenue
                    FROM kpi_monthly_snapshots
                    WHERE {' AND '.join(where)}
                    ORDER BY user_code
                    """,
                    args,
                ).fetchall()
            return send_json(self, 200, {"items": [dict(r) for r in rows], "scope": scope, "month": month_key})
        if parsed.path == "/api/admin/audit-logs":
            user = require_auth(self)
            if not user:
                return
            if user["role_code"] != "ADMIN":
                return send_api_error(self, 403, "admin_only", "Only admin can view audit logs.")
            query = parse_qs(parsed.query)
            limit_raw = (query.get("limit", ["50"])[0] or "50").strip()
            try:
                limit = max(1, min(int(limit_raw), 200))
            except ValueError:
                return send_api_error(self, 400, "invalid_limit", "limit must be an integer between 1 and 200.")
            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    """
                    SELECT id, actor_user_code, action, target_type, target_id, detail_json, created_at
                    FROM audit_logs
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            items = []
            for r in rows:
                item = dict(r)
                try:
                    item["detail"] = json.loads(item.pop("detail_json") or "{}")
                except json.JSONDecodeError:
                    item["detail"] = {}
                items.append(item)
            return send_json(self, 200, {"items": items, "limit": limit})
        return send_api_error(self, 404, "not_found", "Endpoint not found.")

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/app/login":
            form = parse_form(self)
            user_code = form.get("user_code") or ""
            ip = self.client_address[0] if self.client_address else "unknown"
            if not check_login_rate_limit(user_code, ip):
                return send_html(self, 429, "<p>Quá nhiều lần đăng nhập sai. Vui lòng thử lại sau 2 phút.</p>")
                            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                user = conn.execute(
                    """
                    SELECT user_code, full_name, role_code, branch_code, team_code, manager_user_code, password
                    FROM users
                    WHERE user_code = ? AND active = 1
                    """,
                    (user_code,),
                ).fetchone()
                if not user or not verify_password(form.get("password") or "", user["password"]):
                    register_login_failure(user_code, ip)
                    return send_html(self, 200, render_login("Sai tài khoản hoặc mật khẩu"))
                clear_login_failures(user_code, ip)
                token = secrets.token_urlsafe(24)
                conn.execute(
                    "INSERT INTO auth_sessions (token, user_code, created_at) VALUES (?, ?, ?)",
                    (token, user["user_code"], now_iso()),
                )
            return send_html(
                self,
                302,
                "",
                set_cookie=build_session_cookie(token),
                location="/app/leads",
            )

        if parsed.path == "/app/leads/create":
            token = get_cookie_token(self)
            user = get_user_by_token_value(token)
            if not user:
                return send_html(self, 302, "", location="/app/login")

            form = parse_form(self)
            page_qualified = 1 if form.get("page_qualified") == "1" else 0
            phone = form.get("customer_phone", "")
            if phone and page_qualified == 0:
                return send_html(self, 200, "<p>Phone requires qualified=1. <a href='/app/leads'>Quay lại</a></p>")

            ts = now_iso()
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    """
                    INSERT INTO leads (
                        branch_code, customer_phone, platform, page_qualified, lead_status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'new', ?, ?)
                    """,
                    (form.get("branch_code") or user.get("branch_code") or "HN", phone, form.get("platform") or "Facebook", page_qualified, ts, ts),
                )
            return send_html(self, 302, "", location="/app/leads")

        if parsed.path == "/app/calls/create":
            token = get_cookie_token(self)
            user = get_user_by_token_value(token)
            if not user:
                return send_html(self, 302, "", location="/app/login")
            form = parse_form(self)
            if not form.get("lead_id") or not form.get("call_no"):
                return send_html(self, 200, "<p>Thiếu lead_id hoặc call_no. <a href='/app/leads'>Quay lại</a></p>")
            if form.get("call_result") == "Đặt lịch" and not form.get("appointment_at"):
                return send_html(self, 200, "<p>Đặt lịch cần appointment_at. <a href='/app/leads'>Quay lại</a></p>")
            with sqlite3.connect(DB_PATH) as conn:
                try:
                    conn.execute(
                        """
                        INSERT INTO tele_call_logs (
                            lead_id, call_no, tele_owner_code, call_status, call_result,
                            appointment_at, appointment_confirm_status, next_follow_up_at, note, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            int(form.get("lead_id")),
                            int(form.get("call_no")),
                            form.get("tele_owner_code") or user["user_code"],
                            form.get("call_status") or "Đã gọi",
                            form.get("call_result") or "Đặt lịch",
                            form.get("appointment_at"),
                            form.get("appointment_confirm_status"),
                            form.get("next_follow_up_at"),
                            form.get("note"),
                            now_iso(),
                        ),
                    )
                except sqlite3.IntegrityError:
                    return send_html(self, 200, "<p>Trùng call_no theo lead. <a href='/app/leads'>Quay lại</a></p>")
            return send_html(self, 302, "", location="/app/leads")

        if parsed.path == "/app/invoices/create":
            token = get_cookie_token(self)
            user = get_user_by_token_value(token)
            if not user:
                return send_html(self, 302, "", location="/app/login")
            form = parse_form(self)
            required = ["branch_code", "invoice_no", "seller_code", "sale_result"]
            missing = [k for k in required if not form.get(k)]
            if missing:
                return send_html(self, 200, f"<p>Thiếu: {', '.join(missing)}. <a href='/app/leads'>Quay lại</a></p>")
            with sqlite3.connect(DB_PATH) as conn:
                try:
                    conn.execute(
                        """
                        INSERT INTO invoices (
                            branch_code, lead_id, invoice_no, seller_code, sale_result,
                            actual_revenue, debt_revenue, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            form.get("branch_code"),
                            int(form.get("lead_id")) if form.get("lead_id") else None,
                            form.get("invoice_no"),
                            form.get("seller_code"),
                            form.get("sale_result"),
                            float(form.get("actual_revenue") or 0),
                            float(form.get("debt_revenue") or 0),
                            now_iso(),
                        ),
                    )
                except sqlite3.IntegrityError:
                    return send_html(self, 200, "<p>invoice_no đã tồn tại. <a href='/app/leads'>Quay lại</a></p>")
            return send_html(self, 302, "", location="/app/leads")

        if parsed.path == "/app/payments/create":
            token = get_cookie_token(self)
            user = get_user_by_token_value(token)
            if not user:
                return send_html(self, 302, "", location="/app/login")
            form = parse_form(self)
            required = ["branch_code", "invoice_id", "paid_amount", "paid_at"]
            missing = [k for k in required if not form.get(k)]
            if missing:
                return send_html(self, 200, f"<p>Thiếu: {', '.join(missing)}. <a href='/app/leads'>Quay lại</a></p>")
            with sqlite3.connect(DB_PATH) as conn:
                exists = conn.execute("SELECT id FROM invoices WHERE id = ?", (int(form.get("invoice_id")),)).fetchone()
                if not exists:
                    return send_html(self, 200, "<p>Invoice không tồn tại. <a href='/app/leads'>Quay lại</a></p>")
                conn.execute(
                    """
                    INSERT INTO payments (
                        branch_code, invoice_id, paid_amount, paid_at, method, created_by_code, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        form.get("branch_code"),
                        int(form.get("invoice_id")),
                        float(form.get("paid_amount")),
                        form.get("paid_at"),
                        form.get("method"),
                        user["user_code"],
                        now_iso(),
                    ),
                )
            return send_html(self, 302, "", location="/app/leads")

        if parsed.path == "/app/hoan-khach/request":
            token = get_cookie_token(self)
            user = get_user_by_token_value(token)
            if not user:
                return send_html(self, 302, "", location="/app/login")
            form = parse_form(self)
            required = ["invoice_id", "reason_group", "reason_detail"]
            missing = [k for k in required if not form.get(k)]
            if missing:
                return send_html(self, 200, f"<p>Thiếu: {', '.join(missing)}. <a href='/app/leads'>Quay lại</a></p>")
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    """
                    INSERT INTO hoan_khach_requests (
                        invoice_id, requested_by_code, reason_group, reason_detail, evidence_url, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, 'pending', ?)
                    """,
                    (
                        int(form.get("invoice_id")),
                        user["user_code"],
                        form.get("reason_group"),
                        form.get("reason_detail"),
                        form.get("evidence_url"),
                        now_iso(),
                    ),
                )
            return send_html(self, 302, "", location="/app/leads")

        if parsed.path == "/app/hoan-khach/approve":
            token = get_cookie_token(self)
            user = get_user_by_token_value(token)
            if not user:
                return send_html(self, 302, "", location="/app/login")
            if user["role_code"] not in ("BRANCH_MANAGER", "ADMIN"):
                return send_html(self, 200, "<p>Chỉ Branch Manager hoặc Admin mới được duyệt hoàn khách. <a href='/app/leads'>Quay lại</a></p>")
            form = parse_form(self)
            if not form.get("request_id") or not form.get("decision"):
                return send_html(self, 200, "<p>Thiếu request_id/decision. <a href='/app/leads'>Quay lại</a></p>")
            new_status = "approved" if form.get("decision") == "approve" else "rejected"
            with sqlite3.connect(DB_PATH) as conn:
                cur = conn.execute(
                    """
                    UPDATE hoan_khach_requests
                    SET status = ?, approved_by_branch_manager_code = ?, decided_at = ?, decision_note = ?
                    WHERE id = ?
                    """,
                    (new_status, user["user_code"], now_iso(), form.get("decision_note"), int(form.get("request_id"))),
                )
                if cur.rowcount == 0:
                    return send_html(self, 200, "<p>Không tìm thấy request. <a href='/app/leads'>Quay lại</a></p>")
            write_audit_log(
                actor_user_code=user["user_code"],
                action=f"hoan_khach_{new_status}",
                target_type="hoan_khach_request",
                target_id=form.get("request_id"),
                detail={"channel": "web_app", "decision_note": form.get("decision_note")},
            )
            return send_html(self, 302, "", location="/app/leads")

        if parsed.path == "/auth/login":
            data = parse_json(self)
            if not data.get("user_code") or not data.get("password"):
                return send_api_error(self, 400, "missing_credentials", "user_code and password are required.")
            user_code = data.get("user_code") or ""
            ip = self.client_address[0] if self.client_address else "unknown"
            if not check_login_rate_limit(user_code, ip):
                return send_api_error(self, 429, "too_many_login_attempts", "Too many failed login attempts. Please retry later.")

            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                user = conn.execute(
                    """
                    SELECT user_code, full_name, role_code, branch_code, team_code, manager_user_code, password
                    FROM users
                    WHERE user_code = ? AND active = 1
                    """,
                    (user_code,),
                ).fetchone()
                if not user or not verify_password(data.get("password") or "", user["password"]):
                    register_login_failure(user_code, ip)
                    return send_api_error(self, 401, "invalid_credentials", "Invalid user_code or password.")
                clear_login_failures(user_code, ip)

                token = secrets.token_urlsafe(24)
                conn.execute(
                    "INSERT INTO auth_sessions (token, user_code, created_at) VALUES (?, ?, ?)",
                    (token, user["user_code"], now_iso()),
                )
            user_dict = dict(user)
            user_dict.pop("password", None)
            return send_json(self, 200, {"token": token, "user": user_dict})

        if parsed.path == "/api/leads":
            data = parse_json(self)
            required = ["branch_code", "platform"]
            missing = [k for k in required if not data.get(k)]
            if missing:
                return send_api_error(self, 400, "missing_fields", "Required fields are missing.", missing)

            page_qualified = 1 if data.get("page_qualified") else 0
            customer_phone = data.get("customer_phone")
            if customer_phone and page_qualified == 0:
                return send_api_error(
                    self,
                    400,
                    "phone_requires_page_qualified",
                    "Page chỉ nhập số khi lead đủ điều kiện",
                )

            ts = now_iso()
            with sqlite3.connect(DB_PATH) as conn:
                cur = conn.execute(
                    """
                    INSERT INTO leads (
                        branch_code, customer_name, customer_phone, platform, campaign_name,
                        service_interest, page_qualified, page_owner_code, tele_owner_code,
                        sale_owner_code, lead_status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        data.get("branch_code"),
                        data.get("customer_name"),
                        customer_phone,
                        data.get("platform"),
                        data.get("campaign_name"),
                        data.get("service_interest"),
                        page_qualified,
                        data.get("page_owner_code"),
                        data.get("tele_owner_code"),
                        data.get("sale_owner_code"),
                        data.get("lead_status", "new"),
                        ts,
                        ts,
                    ),
                )
                lead_id = cur.lastrowid
            return send_json(self, 201, {"id": lead_id})

        if parsed.path.startswith("/api/leads/") and parsed.path.endswith("/calls"):
            # /api/leads/{id}/calls
            try:
                lead_id = int(parsed.path.split("/")[3])
            except Exception:
                return send_api_error(self, 400, "invalid_lead_id", "lead_id in URL must be an integer.")

            data = parse_json(self)
            required = ["call_no", "tele_owner_code", "call_status", "call_result"]
            missing = [k for k in required if not data.get(k)]
            if missing:
                return send_api_error(self, 400, "missing_fields", "Required fields are missing.", missing)

            if data.get("call_result") == "Đặt lịch" and not data.get("appointment_at"):
                return send_api_error(
                    self,
                    400,
                    "appointment_required_for_dat_lich",
                    "appointment_at is required when call_result is 'Đặt lịch'.",
                )

            if data.get("call_result") == "Hẹn gọi lại" and not data.get("next_follow_up_at"):
                return send_api_error(
                    self,
                    400,
                    "next_follow_up_required_for_hen_goi_lai",
                    "next_follow_up_at is required when call_result is 'Hẹn gọi lại'.",
                )

            with sqlite3.connect(DB_PATH) as conn:
                try:
                    conn.execute(
                        """
                        INSERT INTO tele_call_logs (
                            lead_id, call_no, tele_owner_code, call_status, call_result,
                            appointment_at, appointment_confirm_status, next_follow_up_at,
                            note, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            lead_id,
                            int(data.get("call_no")),
                            data.get("tele_owner_code"),
                            data.get("call_status"),
                            data.get("call_result"),
                            data.get("appointment_at"),
                            data.get("appointment_confirm_status"),
                            data.get("next_follow_up_at"),
                            data.get("note"),
                            now_iso(),
                        ),
                    )
                except sqlite3.IntegrityError:
                    return send_api_error(self, 409, "duplicate_call_no_for_lead", "call_no already exists for this lead.")
            return send_json(self, 201, {"ok": True})

        if parsed.path.startswith("/api/leads/") and parsed.path.endswith("/reassign"):
            user = require_auth(self)
            if not user:
                return
            if user["role_code"] not in ("LEADER", "ADMIN"):
                return send_api_error(self, 403, "leader_or_admin_required", "Only leader or admin can reassign tele lead.")
            try:
                lead_id = int(parsed.path.split("/")[3])
            except Exception:
                return send_api_error(self, 400, "invalid_lead_id", "lead_id in URL must be an integer.")
            data = parse_json(self)
            new_tele_owner_code = (data.get("new_tele_owner_code") or "").strip()
            if not new_tele_owner_code:
                return send_api_error(self, 400, "missing_new_tele_owner_code", "new_tele_owner_code is required.")
            with sqlite3.connect(DB_PATH) as conn:
                cur = conn.execute(
                    "UPDATE leads SET tele_owner_code = ?, updated_at = ? WHERE id = ?",
                    (new_tele_owner_code, now_iso(), lead_id),
                )
                if cur.rowcount == 0:
                    return send_api_error(self, 404, "lead_not_found", "Lead not found.")
            write_audit_log(
                actor_user_code=user["user_code"],
                action="lead_reassign",
                target_type="lead",
                target_id=str(lead_id),
                detail={"new_tele_owner_code": new_tele_owner_code},
            )
            return send_json(self, 200, {"ok": True, "lead_id": lead_id, "tele_owner_code": new_tele_owner_code})

        if parsed.path == "/api/invoices":
            data = parse_json(self)
            required = ["branch_code", "invoice_no", "seller_code", "sale_result"]
            missing = [k for k in required if not data.get(k)]
            if missing:
                return send_api_error(self, 400, "missing_fields", "Required fields are missing.", missing)

            with sqlite3.connect(DB_PATH) as conn:
                try:
                    cur = conn.execute(
                        """
                        INSERT INTO invoices (
                            branch_code, lead_id, invoice_no, seller_code, sale_result,
                            actual_revenue, debt_revenue, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            data.get("branch_code"),
                            data.get("lead_id"),
                            data.get("invoice_no"),
                            data.get("seller_code"),
                            data.get("sale_result"),
                            float(data.get("actual_revenue", 0)),
                            float(data.get("debt_revenue", 0)),
                            now_iso(),
                        ),
                    )
                    invoice_id = cur.lastrowid
                except sqlite3.IntegrityError:
                    return send_api_error(self, 409, "invoice_no_exists", "invoice_no already exists.")
            return send_json(self, 201, {"id": invoice_id})

        if parsed.path == "/api/payments":
            data = parse_json(self)
            required = ["branch_code", "invoice_id", "paid_amount", "paid_at"]
            missing = [k for k in required if not data.get(k)]
            if missing:
                return send_api_error(self, 400, "missing_fields", "Required fields are missing.", missing)

            with sqlite3.connect(DB_PATH) as conn:
                cur = conn.execute("SELECT id FROM invoices WHERE id = ?", (int(data.get("invoice_id")),))
                if cur.fetchone() is None:
                    return send_api_error(self, 404, "invoice_not_found", "Invoice does not exist.")

                cur = conn.execute(
                    """
                    INSERT INTO payments (
                        branch_code, invoice_id, paid_amount, paid_at, method,
                        created_by_code, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        data.get("branch_code"),
                        int(data.get("invoice_id")),
                        float(data.get("paid_amount")),
                        data.get("paid_at"),
                        data.get("method"),
                        data.get("created_by_code"),
                        now_iso(),
                    ),
                )
            return send_json(self, 201, {"id": cur.lastrowid})

        if parsed.path == "/api/hoan-khach/request":
            data = parse_json(self)
            required = ["invoice_id", "requested_by_code", "reason_group", "reason_detail"]
            missing = [k for k in required if not data.get(k)]
            if missing:
                return send_api_error(self, 400, "missing_fields", "Required fields are missing.", missing)

            with sqlite3.connect(DB_PATH) as conn:
                cur = conn.execute(
                    """
                    INSERT INTO hoan_khach_requests (
                        invoice_id, requested_by_code, reason_group, reason_detail,
                        evidence_url, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, 'pending', ?)
                    """,
                    (
                        int(data.get("invoice_id")),
                        data.get("requested_by_code"),
                        data.get("reason_group"),
                        data.get("reason_detail"),
                        data.get("evidence_url"),
                        now_iso(),
                    ),
                )
            return send_json(self, 201, {"id": cur.lastrowid, "status": "pending"})

        if parsed.path == "/api/hoan-khach/approve":
            user = require_auth(self)
            if not user:
                return
            if user["role_code"] not in ("BRANCH_MANAGER", "ADMIN"):
                return send_api_error(
                    self,
                    403,
                    "branch_manager_or_admin_required",
                    "Only branch manager or admin can approve hoan-khach.",
                )

            data = parse_json(self)
            required = ["request_id", "decision"]
            missing = [k for k in required if not data.get(k)]
            if missing:
                return send_api_error(self, 400, "missing_fields", "Required fields are missing.", missing)

            new_status = "approved" if data.get("decision") == "approve" else "rejected"
            with sqlite3.connect(DB_PATH) as conn:
                cur = conn.execute(
                    """
                    UPDATE hoan_khach_requests
                    SET status = ?, approved_by_branch_manager_code = ?,
                        decided_at = ?, decision_note = ?
                    WHERE id = ?
                    """,
                    (
                        new_status,
                        user["user_code"],
                        now_iso(),
                        data.get("decision_note"),
                        int(data.get("request_id")),
                    ),
                )
                if cur.rowcount == 0:
                    return send_api_error(self, 404, "request_not_found", "Hoan-khach request not found.")
            write_audit_log(
                actor_user_code=user["user_code"],
                action=f"hoan_khach_{new_status}",
                target_type="hoan_khach_request",
                target_id=str(data.get("request_id")),
                detail={"channel": "api", "decision_note": data.get("decision_note")},
            )
            return send_json(self, 200, {"id": int(data.get("request_id")), "status": new_status})

        if parsed.path == "/api/kpi/monthly/upsert":
            user = require_auth(self)
            if not user:
                return
            if user["role_code"] not in ("LEADER", "BRANCH_MANAGER", "ADMIN"):
                return send_api_error(self, 403, "forbidden", "You are not allowed to upsert KPI data.")

            data = parse_json(self)
            required = ["month_key", "user_code", "branch_code"]
            missing = [k for k in required if not data.get(k)]
            if missing:
                return send_api_error(self, 400, "missing_fields", "Required fields are missing.", missing)

            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    """
                    INSERT INTO kpi_monthly_snapshots (
                        month_key, user_code, branch_code, team_code, inbox_count,
                        qualified_data_count, tele_data_count, tele_arrived_count,
                        sale_order_count, actual_collected_revenue, debt_revenue,
                        ad_cost, committed_target_revenue
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(month_key, user_code) DO UPDATE SET
                        branch_code = excluded.branch_code,
                        team_code = excluded.team_code,
                        inbox_count = excluded.inbox_count,
                        qualified_data_count = excluded.qualified_data_count,
                        tele_data_count = excluded.tele_data_count,
                        tele_arrived_count = excluded.tele_arrived_count,
                        sale_order_count = excluded.sale_order_count,
                        actual_collected_revenue = excluded.actual_collected_revenue,
                        debt_revenue = excluded.debt_revenue,
                        ad_cost = excluded.ad_cost,
                        committed_target_revenue = excluded.committed_target_revenue
                    """,
                    (
                        data.get("month_key"),
                        data.get("user_code"),
                        data.get("branch_code"),
                        data.get("team_code"),
                        int(data.get("inbox_count", 0)),
                        int(data.get("qualified_data_count", 0)),
                        int(data.get("tele_data_count", 0)),
                        int(data.get("tele_arrived_count", 0)),
                        int(data.get("sale_order_count", 0)),
                        float(data.get("actual_collected_revenue", 0)),
                        float(data.get("debt_revenue", 0)),
                        float(data.get("ad_cost", 0)),
                        float(data.get("committed_target_revenue", 0)),
                    ),
                )
            write_audit_log(
                actor_user_code=user["user_code"],
                action="kpi_monthly_upsert",
                target_type="kpi_month",
                target_id=f"{data.get('month_key')}:{data.get('user_code')}",
                detail={"branch_code": data.get("branch_code"), "team_code": data.get("team_code")},
            )
            return send_json(self, 200, {"ok": True})

        if parsed.path == "/api/admin/customers/export":
            user = require_auth(self)
            if not user:
                return
            if user["role_code"] != "ADMIN":
                return send_api_error(self, 403, "admin_only", "Only admin can export customer data.")
            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    """
                    SELECT id, customer_name, customer_phone, branch_code, platform, created_at
                    FROM leads
                    ORDER BY id DESC
                    LIMIT 500
                    """
                ).fetchall()
            items = [dict(r) for r in rows]
            write_audit_log(
                actor_user_code=user["user_code"],
                action="customer_export",
                target_type="customer",
                detail={"export_count": len(items)},
            )
            return send_json(self, 200, {"items": items, "count": len(items)})

        if parsed.path == "/api/admin/users/reset-password":
            user = require_auth(self)
            if not user:
                return
            if user["role_code"] != "ADMIN":
                return send_api_error(self, 403, "admin_only", "Only admin can reset user password.")
            data = parse_json(self)
            target_user_code = (data.get("user_code") or "").strip()
            new_password = data.get("new_password") or ""
            if not target_user_code or not new_password:
                return send_api_error(self, 400, "missing_fields", "user_code and new_password are required.")
            if len(new_password) < 8:
                return send_api_error(self, 400, "weak_password", "new_password must be at least 8 characters.")
            with sqlite3.connect(DB_PATH) as conn:
                cur = conn.execute(
                    "UPDATE users SET password = ? WHERE user_code = ? AND active = 1",
                    (hash_password(new_password), target_user_code),
                )
                if cur.rowcount == 0:
                    return send_api_error(self, 404, "user_not_found", "User not found.")
            write_audit_log(
                actor_user_code=user["user_code"],
                action="user_password_reset",
                target_type="user",
                target_id=target_user_code,
            )
            return send_json(self, 200, {"ok": True, "user_code": target_user_code})

        return send_api_error(self, 404, "not_found", "Endpoint not found.")

    def do_DELETE(self):
        parsed = urlparse(self.path)
        user = require_auth(self)
        if not user:
            return
        if user["role_code"] != "ADMIN":
            return send_api_error(self, 403, "admin_only", "Only admin can delete data.")

        if parsed.path.startswith("/api/admin/customers/"):
            try:
                lead_id = int(parsed.path.split("/")[4])
            except Exception:
                return send_api_error(self, 400, "invalid_customer_id", "customer id must be an integer.")
            with sqlite3.connect(DB_PATH) as conn:
                cur = conn.execute("DELETE FROM leads WHERE id = ?", (lead_id,))
                if cur.rowcount == 0:
                    return send_api_error(self, 404, "customer_not_found", "Customer not found.")
            write_audit_log(
                actor_user_code=user["user_code"],
                action="customer_delete",
                target_type="customer",
                target_id=str(lead_id),
            )
            return send_json(self, 200, {"ok": True, "deleted_customer_id": lead_id})

        if parsed.path.startswith("/api/admin/invoices/"):
            try:
                invoice_id = int(parsed.path.split("/")[4])
            except Exception:
                return send_api_error(self, 400, "invalid_invoice_id", "invoice id must be an integer.")
            with sqlite3.connect(DB_PATH) as conn:
                cur = conn.execute(
                    "UPDATE invoices SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL",
                    (now_iso(), invoice_id),
                )
                if cur.rowcount == 0:
                    return send_api_error(self, 404, "invoice_not_found", "Invoice not found.")
            write_audit_log(
                actor_user_code=user["user_code"],
                action="invoice_delete",
                target_type="invoice",
                target_id=str(invoice_id),
            )
            return send_json(self, 200, {"ok": True, "deleted_invoice_id": invoice_id})

        return send_api_error(self, 404, "not_found", "Endpoint not found.")


def main() -> None:
    ensure_db()
    server = HTTPServer((SERVER_HOST, SERVER_PORT), Handler)
    print(f"MVP API running at http://{SERVER_HOST}:{SERVER_PORT} (DB: {DB_PATH})")
    server.serve_forever()


if __name__ == "__main__":
    main()

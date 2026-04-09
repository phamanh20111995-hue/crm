from __future__ import annotations

import html
import sqlite3
from datetime import date
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse, urlencode

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "crm_demo.db"

STATUS_TABS = [
    "Tất cả",
    "CONTACT",
    "PARTTIME",
    "QTL CHƯA TT ĐƯỢC",
    "QUAN TÂM LẠI",
    "KẾT NỐI ZALO",
    "ĐANG TƯƠNG TÁC ZALO",
    "ĐẶT LỊCH",
    "DATA NÓNG",
]


def fetch_data(q: str, status: str, owner: str, branch: str, date_filter: str):
    if not DB_PATH.exists():
        raise FileNotFoundError(
            f"Missing demo DB: {DB_PATH}. Run `python scripts/init_demo.py` first."
        )
    conditions = []
    params = []

    if q:
        conditions.append("(customer_name LIKE ? OR phone LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%"])
    if status and status != "Tất cả":
        conditions.append("relation_status = ?")
        params.append(status)
    if owner:
        conditions.append("owner_name = ?")
        params.append(owner)
    if branch:
        conditions.append("branch = ?")
        params.append(branch)
    if date_filter == "today":
        conditions.append("created_date = ?")
        params.append(date.today().isoformat())

    where_sql = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        items = conn.execute(
            f"""
            SELECT id, customer_name, phone, address, description,
                   source_name, customer_group, appointment_date,
                   relation_status, owner_name, creator_name, branch, gender
            FROM customers
            {where_sql}
            ORDER BY id DESC
            LIMIT 100
            """,
            params,
        ).fetchall()

        counts = {
            row["relation_status"]: row["c"]
            for row in conn.execute(
                "SELECT relation_status, COUNT(*) AS c FROM customers GROUP BY relation_status"
            ).fetchall()
        }
        owners = [r[0] for r in conn.execute("SELECT DISTINCT owner_name FROM customers ORDER BY owner_name")]
        branches = [r[0] for r in conn.execute("SELECT DISTINCT branch FROM customers ORDER BY branch")]

    return items, counts, owners, branches


def render_page(q: str, status: str, owner: str, branch: str, date_filter: str) -> str:
    items, counts, owners, branches = fetch_data(q, status, owner, branch, date_filter)

    tabs = []
    for tab in STATUS_TABS:
        query = urlencode({"status": tab, "q": q, "owner": owner, "branch": branch, "date_filter": date_filter})
        active = "active" if tab == status else ""
        tabs.append(
            f'<a class="tab {active}" href="/?{query}">{html.escape(tab)} '
            f'<span class="count">{counts.get(tab, 0)}</span></a>'
        )

    owner_options = ['<option value="">Tất cả người phụ trách</option>']
    owner_options += [
        f'<option value="{html.escape(o)}" {"selected" if o == owner else ""}>{html.escape(o)}</option>' for o in owners
    ]

    branch_options = ['<option value="">Tất cả chi nhánh</option>']
    branch_options += [
        f'<option value="{html.escape(b)}" {"selected" if b == branch else ""}>{html.escape(b)}</option>' for b in branches
    ]

    rows = []
    for c in items:
        rows.append(
            "<tr>"
            f"<td>{c['id']}</td>"
            f"<td>{html.escape(c['customer_name'] or '')}</td>"
            f"<td>{html.escape(c['phone'] or '')}</td>"
            f"<td>{html.escape(c['address'] or '')}</td>"
            f"<td>{html.escape(c['description'] or '')}</td>"
            f"<td>{html.escape(c['source_name'] or '')}</td>"
            f"<td>{html.escape(c['customer_group'] or '')}</td>"
            f"<td>{html.escape(c['appointment_date'] or '')}</td>"
            f"<td>{html.escape(c['relation_status'] or '')}</td>"
            f"<td>{html.escape(c['owner_name'] or '')}</td>"
            f"<td>{html.escape(c['creator_name'] or '')}</td>"
            f"<td>{html.escape(c['branch'] or '')}</td>"
            f"<td>{html.escape(c['gender'] or '')}</td>"
            "</tr>"
        )

    return f"""
<!doctype html>
<html lang='vi'>
<head>
<meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>
<title>CRM Demo - Danh sách khách hàng</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 16px; background: #f5f7fb; }}
.header {{ font-size: 24px; font-weight: 700; margin-bottom: 12px; }}
.filters {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }}
input, select, button {{ padding: 8px; border-radius: 6px; border: 1px solid #cfd6e0; }}
.tabs {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }}
.tab {{ background: #e6ebf5; color: #213f7a; border-radius: 16px; padding: 6px 10px; font-size: 13px; text-decoration: none; }}
.tab.active {{ background: #1f4ea0; color: white; }}
.count {{ background: #ff8b00; color: #fff; border-radius: 10px; padding: 0 6px; margin-left: 6px; }}
table {{ width: 100%; border-collapse: collapse; background: white; }}
th, td {{ border: 1px solid #e1e6ef; padding: 8px; font-size: 13px; }}
th {{ background: #eef2f8; text-align: left; }}
</style>
</head>
<body>
<div class='header'>Khách hàng · Danh sách khách hàng (Demo)</div>
<form method='get' class='filters'>
<input type='text' name='q' placeholder='Tìm tên, sđt' value='{html.escape(q)}' />
<select name='owner'>{''.join(owner_options)}</select>
<select name='branch'>{''.join(branch_options)}</select>
<select name='date_filter'>
<option value='all' {'selected' if date_filter == 'all' else ''}>Thời gian: Tất cả</option>
<option value='today' {'selected' if date_filter == 'today' else ''}>Thời gian: Hôm nay</option>
</select>
<input type='hidden' name='status' value='{html.escape(status)}' />
<button type='submit'>Lọc</button>
</form>
<div class='tabs'>{''.join(tabs)}</div>
<table>
<thead><tr><th>#</th><th>Tên khách hàng</th><th>Điện thoại</th><th>Địa chỉ</th><th>Mô tả</th><th>Nguồn KH</th><th>Nhóm KH</th><th>Ngày hẹn</th><th>Mối quan hệ</th><th>Người phụ trách</th><th>Người tạo</th><th>Chi nhánh</th><th>Giới tính</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)

            q = params.get("q", [""])[0].strip()
            status = params.get("status", ["Tất cả"])[0].strip() or "Tất cả"
            owner = params.get("owner", [""])[0].strip()
            branch = params.get("branch", [""])[0].strip()
            date_filter = params.get("date_filter", ["today"])[0].strip() or "today"

            page = render_page(q, status, owner, branch, date_filter)
            body = page.encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:  # noqa: BLE001
            message = (
                "<h3>Demo server error</h3>"
                f"<pre>{html.escape(str(exc))}</pre>"
                "<p>Tip: run <code>python scripts/init_demo.py</code> first.</p>"
            )
            body = message.encode("utf-8")
            self.send_response(500)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


def run_server(port: int = 8000):
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"CRM demo running at http://0.0.0.0:{port}/")
    server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Shiny CRM demo server")
    parser.add_argument("--port", type=int, default=8000, help="HTTP port (default: 8000)")
    args = parser.parse_args()
    run_server(port=args.port)

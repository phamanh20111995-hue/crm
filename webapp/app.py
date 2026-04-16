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

    total_customers = sum(counts.values())
    hot_data = counts.get("DATA NÓNG", 0)
    appointments = counts.get("ĐẶT LỊCH", 0)
    interacted = counts.get("ĐANG TƯƠNG TÁC ZALO", 0)

    return f"""
<!doctype html>
<html lang='vi'>
<head>
<meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>
<title>CRM Demo - Danh sách khách hàng</title>
<style>
:root {{
  --bg: #f4f7fc;
  --card: #ffffff;
  --text: #15223b;
  --subtext: #6d7a93;
  --line: #e6ebf4;
  --primary: #2e6bff;
  --primary-soft: #eaf0ff;
  --accent: #ff8b00;
  --shadow: 0 8px 24px rgba(21, 34, 59, 0.08);
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font-family: Inter, Segoe UI, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
}}
.layout {{
  max-width: 1400px;
  margin: 0 auto;
  padding: 20px;
}}
.topbar {{
  background: linear-gradient(120deg, #17315f, #274f9b);
  color: #fff;
  border-radius: 16px;
  padding: 18px 22px;
  box-shadow: var(--shadow);
  margin-bottom: 16px;
}}
.topbar h1 {{ margin: 0; font-size: 24px; }}
.topbar p {{ margin: 6px 0 0; color: #d7e3ff; }}
.stats {{
  display: grid;
  grid-template-columns: repeat(4, minmax(180px, 1fr));
  gap: 12px;
  margin-bottom: 14px;
}}
.stat {{
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 14px;
  padding: 14px;
  box-shadow: var(--shadow);
}}
.stat .label {{ font-size: 12px; color: var(--subtext); margin-bottom: 6px; text-transform: uppercase; letter-spacing: .03em; }}
.stat .value {{ font-size: 24px; font-weight: 700; }}
.panel {{
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 14px;
  box-shadow: var(--shadow);
  padding: 14px;
  margin-bottom: 12px;
}}
.filters {{
  display: grid;
  grid-template-columns: 2fr 1fr 1fr 1fr auto;
  gap: 10px;
}}
input, select, button {{
  width: 100%;
  padding: 10px 12px;
  border-radius: 10px;
  border: 1px solid #d3dced;
  background: #fff;
  color: var(--text);
}}
button {{
  width: auto;
  min-width: 120px;
  background: var(--primary);
  color: #fff;
  border: none;
  font-weight: 600;
  cursor: pointer;
}}
.tabs {{
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}}
.tab {{
  background: #f2f5fb;
  color: #31456b;
  border-radius: 999px;
  padding: 7px 12px;
  font-size: 13px;
  text-decoration: none;
  border: 1px solid #e0e7f5;
}}
.tab.active {{
  background: var(--primary-soft);
  color: var(--primary);
  border-color: #cbd9ff;
  font-weight: 600;
}}
.count {{
  background: var(--accent);
  color: #fff;
  border-radius: 999px;
  padding: 1px 7px;
  margin-left: 6px;
  font-size: 12px;
}}
.table-wrap {{
  overflow: auto;
  border-radius: 12px;
  border: 1px solid var(--line);
}}
table {{
  width: 100%;
  border-collapse: collapse;
  background: white;
  min-width: 1150px;
}}
th, td {{ border-bottom: 1px solid var(--line); padding: 10px 9px; font-size: 13px; text-align: left; }}
th {{
  background: #f7f9ff;
  color: #3a4c71;
  position: sticky;
  top: 0;
  z-index: 1;
}}
tr:hover td {{ background: #f9fbff; }}
.muted {{ color: var(--subtext); font-size: 13px; margin: 0 0 10px; }}
@media (max-width: 1024px) {{
  .stats {{ grid-template-columns: repeat(2, minmax(180px, 1fr)); }}
  .filters {{ grid-template-columns: 1fr; }}
  button {{ width: 100%; }}
}}
</style>
</head>
<body>
<div class='layout'>
  <div class='topbar'>
    <h1>CRM Dashboard · Quản lý khách hàng</h1>
    <p>Giao diện demo theo phong cách dashboard quản trị hiện đại · dữ liệu đồng bộ theo bộ lọc</p>
  </div>

  <div class='stats'>
    <div class='stat'><div class='label'>Tổng khách hàng</div><div class='value'>{total_customers}</div></div>
    <div class='stat'><div class='label'>Data nóng</div><div class='value'>{hot_data}</div></div>
    <div class='stat'><div class='label'>Đặt lịch</div><div class='value'>{appointments}</div></div>
    <div class='stat'><div class='label'>Đang tương tác Zalo</div><div class='value'>{interacted}</div></div>
  </div>

  <div class='panel'>
    <p class='muted'>Lọc dữ liệu theo từ khóa, người phụ trách, chi nhánh và thời gian.</p>
    <form method='get' class='filters'>
      <input type='text' name='q' placeholder='Tìm theo tên hoặc số điện thoại...' value='{html.escape(q)}' />
      <select name='owner'>{''.join(owner_options)}</select>
      <select name='branch'>{''.join(branch_options)}</select>
      <select name='date_filter'>
      <option value='all' {'selected' if date_filter == 'all' else ''}>Thời gian: Tất cả</option>
      <option value='today' {'selected' if date_filter == 'today' else ''}>Thời gian: Hôm nay</option>
      </select>
      <input type='hidden' name='status' value='{html.escape(status)}' />
      <button type='submit'>Áp dụng lọc</button>
    </form>
  </div>

  <div class='panel'><div class='tabs'>{''.join(tabs)}</div></div>

  <div class='panel table-wrap'>
    <table>
      <thead>
        <tr><th>#</th><th>Tên khách hàng</th><th>Điện thoại</th><th>Địa chỉ</th><th>Mô tả</th><th>Nguồn KH</th><th>Nhóm KH</th><th>Ngày hẹn</th><th>Mối quan hệ</th><th>Người phụ trách</th><th>Người tạo</th><th>Chi nhánh</th><th>Giới tính</th></tr>
      </thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </div>
</div>
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

from __future__ import annotations

import html
import sqlite3
from datetime import date
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

BASE_DIR = Path(__file__).resolve().parent if "__file__" in globals() else Path.cwd()
DB_PATH = BASE_DIR / "crm_demo_single.db"

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


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS customers (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              customer_name TEXT NOT NULL,
              phone TEXT NOT NULL,
              address TEXT,
              description TEXT,
              source_name TEXT,
              customer_group TEXT,
              appointment_date TEXT,
              relation_status TEXT NOT NULL,
              owner_name TEXT NOT NULL,
              creator_name TEXT NOT NULL,
              branch TEXT NOT NULL,
              gender TEXT,
              created_date TEXT NOT NULL
            );
            """
        )

        c = conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0]
        if c == 0:
            rows = [
                ("Tan Dat", "0338954380", "sg", "", "RIO SPA SAI GON", "BS HOAN, SẸO RỖ AirFusion", "2026-04-11", "CONTACT", "Nguyen Kieu Anh", "Pham The Hien", "HCM", "Nam"),
                ("Dinh Dai Duong", "0965856531", "soc son", "44t", "DAISY", "XOA NHAN, BS KIEN", "2026-04-11", "CARE ĐI CARE LẠI", "Le Hai Yen", "Ngo Thu Hang", "HN", "Nam"),
                ("Binh Nguyen", "0338863414", ".", "", "RIO SPA SAI GON", "BS HOAN, SẸO RỖ AirFusion", "2026-04-07", "ĐẶT LỊCH", "Thanh Hoa", "Pham The Hien", "HCM", "Nữ"),
                ("Cherry Dau Tay", "0702659642", "đg ở Trung Quốc", "", "RIO SPA SAI GON", "CHĂM SÓC DA, BS HOAN", "2026-04-16", "KẾT NỐI ZALO", "Nguyen Kieu Anh", "Ngo Thu Hang", "HCM", "Nữ"),
                ("Do Huong", "0946952662", "sg", "", "RIO SPA SAI GON", "BS HOAN, SẸO RỖ AirFusion", "2026-04-07", "ĐẶT LỊCH", "Nguyen Thi Thuy Linh", "Pham The Hien", "HCM", "Nữ"),
                ("Vien Vu", "0796690008", "thu duc", "", "RIO SPA SAI GON", "BS HOAN, SẸO RỖ AirFusion", "2026-04-08", "ĐẶT LỊCH", "Thanh Hoa", "Pham The Hien", "HCM", "Nữ"),
                ("Vu Yen Phuong", "0915354768", "hn", "", "DAISY", "BS KIEN, SẸO RỖ AirFusion", "2026-04-07", "KHÔNG NGHE MÁY", "Do Linh Nhi", "Pham The Hien", "HN", "Nữ"),
            ]
            conn.executemany(
                """
                INSERT INTO customers (
                  customer_name, phone, address, description, source_name,
                  customer_group, appointment_date, relation_status, owner_name,
                  creator_name, branch, gender, created_date
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [(*row, date.today().isoformat()) for row in rows],
            )


def query_data(q: str, status: str, owner: str, branch: str, date_filter: str):
    cond = []
    vals = []
    if q:
        cond.append("(customer_name LIKE ? OR phone LIKE ?)")
        vals.extend([f"%{q}%", f"%{q}%"])
    if status != "Tất cả":
        cond.append("relation_status = ?")
        vals.append(status)
    if owner:
        cond.append("owner_name = ?")
        vals.append(owner)
    if branch:
        cond.append("branch = ?")
        vals.append(branch)
    if date_filter == "today":
        cond.append("created_date = ?")
        vals.append(date.today().isoformat())

    where = f"WHERE {' AND '.join(cond)}" if cond else ""

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        items = conn.execute(
            f"""
            SELECT id, customer_name, phone, address, description, source_name,
                   customer_group, appointment_date, relation_status,
                   owner_name, creator_name, branch, gender
            FROM customers {where}
            ORDER BY id DESC
            LIMIT 100
            """,
            vals,
        ).fetchall()

        counts = {
            r["relation_status"]: r["c"]
            for r in conn.execute(
                "SELECT relation_status, COUNT(*) as c FROM customers GROUP BY relation_status"
            ).fetchall()
        }
        owners = [r[0] for r in conn.execute("SELECT DISTINCT owner_name FROM customers ORDER BY owner_name")]
        branches = [r[0] for r in conn.execute("SELECT DISTINCT branch FROM customers ORDER BY branch")]
    return items, counts, owners, branches


def render(q: str, status: str, owner: str, branch: str, date_filter: str) -> str:
    items, counts, owners, branches = query_data(q, status, owner, branch, date_filter)

    tabs = []
    for t in STATUS_TABS:
        query = urlencode({"q": q, "status": t, "owner": owner, "branch": branch, "date_filter": date_filter})
        tabs.append(
            f"<a class='tab {'active' if t == status else ''}' href='/?{query}'>{html.escape(t)} <span class='count'>{counts.get(t,0)}</span></a>"
        )

    owner_opts = "<option value=''>Tất cả người phụ trách</option>" + "".join(
        [f"<option {'selected' if o==owner else ''}>{html.escape(o)}</option>" for o in owners]
    )
    branch_opts = "<option value=''>Tất cả chi nhánh</option>" + "".join(
        [f"<option {'selected' if b==branch else ''}>{html.escape(b)}</option>" for b in branches]
    )

    rows = "".join(
        [
            "<tr>"
            f"<td>{r['id']}</td>"
            f"<td>{html.escape(r['customer_name'] or '')}</td>"
            f"<td>{html.escape(r['phone'] or '')}</td>"
            f"<td>{html.escape(r['address'] or '')}</td>"
            f"<td>{html.escape(r['description'] or '')}</td>"
            f"<td>{html.escape(r['source_name'] or '')}</td>"
            f"<td>{html.escape(r['customer_group'] or '')}</td>"
            f"<td>{html.escape(r['appointment_date'] or '')}</td>"
            f"<td>{html.escape(r['relation_status'] or '')}</td>"
            f"<td>{html.escape(r['owner_name'] or '')}</td>"
            f"<td>{html.escape(r['creator_name'] or '')}</td>"
            f"<td>{html.escape(r['branch'] or '')}</td>"
            f"<td>{html.escape(r['gender'] or '')}</td>"
            "</tr>"
            for r in items
        ]
    )

    return f"""
<!doctype html><html lang='vi'><head><meta charset='utf-8'><title>CRM Demo</title>
<style>
body{{font-family:Arial;background:#f5f7fb;margin:16px}}.filters{{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}}
input,select,button{{padding:8px;border:1px solid #cfd6e0;border-radius:6px}}.tabs{{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}}
.tab{{background:#e6ebf5;padding:6px 10px;border-radius:16px;text-decoration:none;color:#1f4ea0;font-size:13px}}
.active{{background:#1f4ea0;color:#fff}}.count{{background:#ff8b00;color:#fff;padding:0 6px;border-radius:10px;margin-left:6px}}
table{{width:100%;border-collapse:collapse;background:#fff}}th,td{{border:1px solid #e1e6ef;padding:8px;font-size:13px}}th{{background:#eef2f8;text-align:left}}
</style></head><body>
<h2>Khách hàng · Danh sách khách hàng (1 file Python)</h2>
<form class='filters' method='get'>
<input name='q' value='{html.escape(q)}' placeholder='Tìm tên, sđt'>
<select name='owner'>{owner_opts}</select>
<select name='branch'>{branch_opts}</select>
<select name='date_filter'>
<option value='all' {'selected' if date_filter=='all' else ''}>Thời gian: Tất cả</option>
<option value='today' {'selected' if date_filter=='today' else ''}>Thời gian: Hôm nay</option>
</select>
<input type='hidden' name='status' value='{html.escape(status)}'>
<button>Lọc</button>
</form>
<div class='tabs'>{''.join(tabs)}</div>
<table><thead><tr><th>#</th><th>Tên KH</th><th>Điện thoại</th><th>Địa chỉ</th><th>Mô tả</th><th>Nguồn KH</th><th>Nhóm KH</th><th>Ngày hẹn</th><th>Mối quan hệ</th><th>Người phụ trách</th><th>Người tạo</th><th>Chi nhánh</th><th>Giới tính</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        params = parse_qs(urlparse(self.path).query)
        q = params.get("q", [""])[0].strip()
        status = params.get("status", ["Tất cả"])[0].strip() or "Tất cả"
        owner = params.get("owner", [""])[0].strip()
        branch = params.get("branch", [""])[0].strip()
        date_filter = params.get("date_filter", ["today"])[0].strip() or "today"

        body = render(q, status, owner, branch, date_filter).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    init_db()
    server = HTTPServer(("0.0.0.0", 8000), Handler)
    print("Open browser: http://127.0.0.1:8000/")
    server.serve_forever()


if __name__ == "__main__":
    main()

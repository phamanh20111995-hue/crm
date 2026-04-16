from __future__ import annotations

import sqlite3
from datetime import date
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "crm_demo.db"

schema = """
DROP TABLE IF EXISTS customers;

CREATE TABLE customers (
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

sample = [
    ("Tan Dat", "0338954380", "sg", "", "RIO SPA SAI GON", "BS HOAN, SẸO RỖ AirFusion", "2026-04-11", "CONTACT", "Nguyen Kieu Anh", "Pham The Hien", "HCM", "Nam"),
    ("Dinh Dai Duong", "0965856531", "soc son", "44t", "DAISY", "XOA NHAN, BS KIEN", "2026-04-11", "CARE ĐI CARE LẠI", "Le Hai Yen", "Ngo Thu Hang", "HN", "Nam"),
    ("Binh Nguyen", "0338863414", ".", "", "RIO SPA SAI GON", "BS HOAN, SẸO RỖ AirFusion", "2026-04-07", "ĐẶT LỊCH", "Thanh Hoa", "Pham The Hien", "HCM", "Nữ"),
    ("Cherry Dau Tay", "0702659642", "đg ở Trung Quốc", "", "RIO SPA SAI GON", "CHĂM SÓC DA, BS HOAN", "2026-04-16", "KẾT NỐI ZALO", "Nguyen Kieu Anh", "Ngo Thu Hang", "HCM", "Nữ"),
    ("Do Huong", "0946952662", "sg", "", "RIO SPA SAI GON", "BS HOAN, SẸO RỖ AirFusion", "2026-04-07", "ĐẶT LỊCH", "Nguyen Thi Thuy Linh", "Pham The Hien", "HCM", "Nữ"),
    ("Vien Vu", "0796690008", "thu duc", "", "RIO SPA SAI GON", "BS HOAN, SẸO RỖ AirFusion", "2026-04-08", "ĐẶT LỊCH", "Thanh Hoa", "Pham The Hien", "HCM", "Nữ"),
    ("Vu Yen Phuong", "0915354768", "hn", "", "DAISY", "BS KIEN, SẸO RỖ AirFusion", "2026-04-07", "KHÔNG NGHE MÁY", "Do Linh Nhi", "Pham The Hien", "HN", "Nữ"),
]

with sqlite3.connect(DB_PATH) as conn:
    conn.executescript(schema)
    conn.executemany(
        """
        INSERT INTO customers (
          customer_name, phone, address, description, source_name,
          customer_group, appointment_date, relation_status, owner_name,
          creator_name, branch, gender, created_date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [(*row, date.today().isoformat()) for row in sample],
    )

print(f"Initialized demo DB at: {DB_PATH}")

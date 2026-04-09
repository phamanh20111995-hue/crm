# Shiny Clinic CRM (MVP Kickoff + Demo Run)

This repository now includes a runnable **customer list demo** so you can test the CRM feel similar to your current system.

## What is included

- Locked rules/spec docs (`docs/`)
- Permission matrix (`docs/permission-matrix.csv`)
- PostgreSQL core schema draft (`db/schema.sql`)
- OpenAPI draft (`api/openapi.yaml`)
- **Runnable Python demo UI** (`webapp/`) for customer listing/filtering/tabs

## Quick start (run thử ngay)

> ⚠️ Quan trọng: `python scripts/run_demo.py` là lệnh chạy trong **Terminal / CMD / PowerShell**,
> không nhập vào ô tìm kiếm của trình duyệt.

### Cách dễ nhất (1 lệnh)

```bash
python scripts/run_demo.py
```

Script sẽ tự:
1. tạo dữ liệu demo
2. chọn port trống (8000-8010)
3. in ra URL để bạn mở

### Nếu bạn chỉ muốn 1 file Python duy nhất (dán Notepad)

Bạn có thể dùng `onefile_crm_demo.py`:

```bash
python onefile_crm_demo.py
```

File này tự tạo DB SQLite và chạy giao diện luôn (không cần `.bat`). 

### Mở nhanh theo hệ điều hành

- **Windows**: double-click `scripts/start_demo.bat`
- **Windows PowerShell (copy-paste 1 lần chạy)**:
  ```powershell
  Set-ExecutionPolicy -Scope Process Bypass; .\scripts\start_demo.ps1
  ```
- **macOS/Linux**:
  ```bash
  ./scripts/start_demo.sh
  ```

### Cách chạy thủ công

1) Initialize demo data
```bash
python scripts/init_demo.py
```

2) Run web app
```bash
python webapp/app.py --port 8000
```

Open: `http://127.0.0.1:8000/` (hoặc port mà script in ra)

If you run in Docker/VM/remote terminal, use your host IP with port `8000`
(the app now binds to `0.0.0.0`).

### Quick troubleshoot for `ERR_CONNECTION_REFUSED`

1. Chạy bằng 1 lệnh: `python scripts/run_demo.py`
2. Giữ terminal đang chạy (đừng tắt), sau đó mới mở browser.
3. Nếu port 8000 bận, dùng port khác: `python webapp/app.py --port 8001`
4. Kiểm tra local URL có trả HTML không:
   ```bash
   curl -I http://127.0.0.1:8000/
   ```

## Demo features similar to your CRM screen

- Customer table list
- Search by customer name/phone
- Filter by owner, branch, date (today/all)
- Status tabs with counts (CONTACT, ĐẶT LỊCH, ...)

## Notes

- This is an MVP UI prototype for trial workflow.
- Next step after your review: implement full auth + RBAC + pipeline + KPI + revenue/debt modules on top of the approved schema/rules.

# Admin Review Checklist (CRM MVP)

Mục tiêu: quản trị theo 2 tầng để vừa theo dõi tiến độ tổng quan, vừa bám sát comment kỹ thuật theo từng file/dòng.

## Tầng 1 — Checklist quản trị

- [x] RBAC duyệt Hoàn khách cho `BRANCH_MANAGER` và `ADMIN`.
- [x] Đồng bộ OpenAPI cho `POST /payments` (request/response cơ bản).
- [x] Đồng bộ OpenAPI cho `POST /hoan-khach/{requestId}/approve` (security + body + response).
- [x] Bổ sung test tự động cho các flow chính.
- [x] Chuẩn hóa validation lỗi theo một schema thống nhất.
- [x] Thiết lập CI quality gate (compile + test) trên push/pull_request.
- [x] Nâng OpenAPI thành full contract cho các endpoint API hiện có.
- [x] Bổ sung audit log cho hành động quản trị nhạy cảm (approve hoàn khách, KPI upsert) + API tra cứu cho Admin.
- [x] Triển khai API reassign Tele lead (Leader/Admin), export customer, delete customer, delete invoice theo permission matrix.
- [x] Hardening auth: hash password seed/user cũ + session token TTL (12h) và auto-expire.
- [x] Hardening login: rate limit đăng nhập sai (API/Web) để giảm brute-force.
- [x] Cấu hình hóa runtime bằng env vars (DB path, host/port, TTL, login limit, cookie secure/samesite) để sẵn sàng deploy thật.
- [x] Thêm production preflight gate (fail startup nếu chưa đạt yêu cầu bảo mật tối thiểu).
- [x] Bổ sung API Admin reset password để xử lý xoay mật khẩu mặc định trước khi bật production.
- [x] Thêm CLI `scripts/rotate_default_passwords.py` để xoay toàn bộ mật khẩu mặc định trước khi bật production.

## Tầng 2 — Mapping kỹ thuật (inline-style)

1. `backend/mvp_api.py`
   - `POST /app/hoan-khach/approve`: mở quyền cho `ADMIN`.
   - `POST /api/hoan-khach/approve`: mở quyền cho `ADMIN`, bỏ required `approved_by_code` để tránh giả mạo user, lấy người duyệt từ session token.
2. `api/openapi.yaml`
   - Bổ sung schema cho `POST /payments`.
   - Cập nhật quyền/contract cho `POST /hoan-khach/{requestId}/approve` sang `Branch Manager or Admin`.

## Definition of done

- Tài liệu OpenAPI phản ánh đúng contract tối thiểu của API hiện hành.
- Quyền duyệt Hoàn khách giữa UI và API đồng nhất.
- Mỗi thay đổi có commit message rõ ràng + kiểm tra cú pháp Python pass.

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

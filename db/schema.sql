-- PostgreSQL schema for Shiny Clinic CRM MVP

create table branches (
  id bigserial primary key,
  code text unique not null,
  name text not null
);

create table roles (
  id bigserial primary key,
  code text unique not null,
  name text not null
);

create table departments (
  id bigserial primary key,
  code text unique not null,
  name text not null,
  has_leader boolean not null default true
);

create table employees (
  id bigserial primary key,
  employee_code text unique not null,
  full_name text not null,
  branch_id bigint not null references branches(id),
  department_id bigint not null references departments(id),
  role_id bigint not null references roles(id),
  manager_employee_id bigint references employees(id),
  status text not null default 'active',
  joined_at date,
  left_at date,
  created_at timestamptz not null default now()
);

create table leads (
  id bigserial primary key,
  branch_id bigint not null references branches(id),
  customer_name text,
  customer_phone text,
  platform text not null,
  campaign_name text,
  service_interest text,
  is_page_qualified boolean not null default false,
  page_owner_id bigint references employees(id),
  tele_owner_id bigint references employees(id),
  sale_owner_id bigint references employees(id),
  lead_status text not null default 'new',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index leads_branch_phone_uniq
on leads (branch_id, customer_phone)
where customer_phone is not null;

create table lead_reassignment_logs (
  id bigserial primary key,
  lead_id bigint not null references leads(id),
  from_tele_owner_id bigint references employees(id),
  to_tele_owner_id bigint references employees(id),
  changed_by_employee_id bigint not null references employees(id),
  reason text not null,
  created_at timestamptz not null default now()
);

create table tele_call_logs (
  id bigserial primary key,
  lead_id bigint not null references leads(id),
  call_no int not null,
  tele_owner_id bigint not null references employees(id),
  call_status text not null,
  call_result text not null,
  appointment_at timestamptz,
  appointment_confirm_status text,
  next_follow_up_at timestamptz,
  note text,
  created_at timestamptz not null default now(),
  unique (lead_id, call_no)
);

create table invoices (
  id bigserial primary key,
  branch_id bigint not null references branches(id),
  lead_id bigint references leads(id),
  invoice_no text unique not null,
  seller_id bigint not null references employees(id),
  sale_result text not null,
  actual_revenue numeric(18,2) not null default 0,
  debt_revenue numeric(18,2) not null default 0,
  created_at timestamptz not null default now(),
  deleted_at timestamptz
);

create table payments (
  id bigserial primary key,
  branch_id bigint not null references branches(id),
  invoice_id bigint not null references invoices(id),
  paid_amount numeric(18,2) not null,
  paid_at timestamptz not null,
  method text,
  created_by_employee_id bigint references employees(id),
  created_at timestamptz not null default now()
);

create table hoan_khach_requests (
  id bigserial primary key,
  invoice_id bigint not null references invoices(id),
  requested_by_employee_id bigint not null references employees(id),
  reason_group text not null,
  reason_detail text not null,
  evidence_url text,
  status text not null default 'pending', -- pending|approved|rejected
  branch_manager_id bigint references employees(id),
  decided_at timestamptz,
  decision_note text,
  created_at timestamptz not null default now()
);

create table kpi_monthly_snapshots (
  id bigserial primary key,
  branch_id bigint not null references branches(id),
  employee_id bigint not null references employees(id),
  month_key date not null,
  inbox_count int not null default 0,
  qualified_data_count int not null default 0,
  tele_data_count int not null default 0,
  tele_arrived_count int not null default 0,
  sale_order_count int not null default 0,
  actual_collected_revenue numeric(18,2) not null default 0,
  debt_revenue numeric(18,2) not null default 0,
  ad_cost numeric(18,2) not null default 0,
  committed_target_revenue numeric(18,2),
  created_at timestamptz not null default now(),
  unique (branch_id, employee_id, month_key)
);

create table audit_logs (
  id bigserial primary key,
  actor_employee_id bigint references employees(id),
  action text not null,
  entity_type text not null,
  entity_id bigint,
  payload jsonb,
  created_at timestamptz not null default now()
);

-- Seed core data
insert into branches(code, name) values
('HN', 'Ha Noi'),
('HCM', 'Ho Chi Minh City');

insert into roles(code, name) values
('ADMIN', 'Admin'),
('BRANCH_MANAGER', 'Branch Manager'),
('LEADER', 'Leader'),
('STAFF', 'Staff');

insert into departments(code, name, has_leader) values
('PAGE', 'Truc Page', true),
('ADS', 'Ads', true),
('TELE', 'Tele', true),
('TV', 'Tu Van', true),
('KTV', 'Ky Thuat Vien', true),
('BS', 'Bac Si', true),
('CSKH', 'Cham Soc Khach Hang', true),
('BAOVE', 'Bao Ve', false),
('TAPVU', 'Tap Vu', false);

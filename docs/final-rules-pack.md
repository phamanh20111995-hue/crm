# Final Rules Pack (Locked)

## Scope

- Cloud CRM, multi-branch: Ha Noi + Ho Chi Minh City
- MVP: Lead, KPI, Revenue/Debt, HR + Permission
- Next: CSKH module (post-MVP)

## Org and Roles

- Roles: Admin, Branch Manager, Leader, Staff
- Departments with leader: Page, Ads, Tele, Tu Van, KTV, Bac Si, CSKH
- Departments without leader: Bao Ve, Tap Vu

## Permission Core

- Staff: own records
- Leader: team records
- Branch Manager: branch records
- Admin: all records

## Hard permission constraints

- Only Tele Leader can reassign tele leads
- Only Admin can export customer data
- Only Admin can delete customer data
- Only Admin can delete invoice

## Lead and Tele Flow

- Page can only save phone number after lead qualifies
- Tele call history is append-only (no overwrite)
- Tele call has: call status, call result, appointment confirmation

## Sale + KPI

- Personal revenue KPI = actual collected only
- Debt is excluded from personal revenue KPI
- KPI closing by payment date
- One order = one seller
- Money uses exact value (no rounding)

## Hoan Khach rule

- Sale result supports: Hoan Khach
- Must include reason category, detailed reason, evidence
- Only Branch Manager can approve/reject
- Before approval: counted as Khong Mua
- After approval: excluded from conversion KPI denominator

## Added KPI

- Page: Data/Inbox
- Ads: Cost/Revenue
- Tu Van: Average Bill
- KTV: Monthly committed revenue
- Branch Manager: Monthly committed branch revenue

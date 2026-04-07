# Shiny Clinic CRM (MVP Kickoff)

This repository contains the first build artifacts for a multi-branch CRM MVP aligned to the approved business scope.

## Included in this kickoff

- Final business rules pack
- Permission matrix for Staff/Leader/Branch Manager/Admin
- PostgreSQL schema for MVP modules
- Minimal API contract for lead, tele-call history, revenue/debt, and approval flow

## MVP modules

1. Lead pipeline (Page -> Tele -> Sale)
2. KPI foundation by role/department
3. Revenue and debt tracking
4. HR + role-based access scope

## Branch setup

- Hanoi
- Ho Chi Minh City

## Critical rules already encoded in schema/contract

- Personal KPI revenue uses **actual collected cash only**
- Debt amount is tracked separately and excluded from personal revenue KPI
- Closing period uses **payment date**
- One order has one seller
- Tele lead reassignment permission: **Tele Leader only**
- Export/delete customer data and invoice deletion: **Admin only**
- "Hoan khach" is excluded from conversion KPI only after **Branch Manager approval**

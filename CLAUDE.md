# OKRSYNC — Zero Trust OKR & Agile Sprint Portal

## What this project is

A production-grade enterprise OKR portal based on John Doerr's "What Matters" framework, with Agile sprint task tracking, Zero Trust RBAC, and a dual-portal sync for external partners. Built for an investment bank context.

**Stack:**
- Frontend: React + Vite + TypeScript + Tailwind (existing UI shell, to be wired to real APIs)
- Backend: Python 3.11+ / Flask (Flask-SQLAlchemy, Flask-SocketIO, Celery)
- Database: PostgreSQL 15+
- Async: Celery + Redis (for outbox worker and background scoring)
- Auth: JWT (short-lived access + refresh token rotation)

## Repository layout (target state)
/
├── CLAUDE.md                 (this file)
├── README.md
├── backend/
│   └── app/
│       ├── models.py         (Phase 1 — DONE, already in repo)
│       ├── services/         (Phase 2)
│       │   ├── scoring.py
│       │   ├── alignment.py
│       │   ├── rbac.py
│       │   └── sanitization.py
│       ├── routes.py         (Phase 2)
│       ├── sockets.py        (Phase 4)
│       └── tasks.py          (Phase 4 — Celery tasks)
└── frontend/                 (Phase 3 — existing React shell to be imported)

## The OKR framework (non-negotiable domain rules)

These come from the "What Matters" framework PDFs and are baked into the schema. Do not change these without explicit instruction:

1. **Hierarchy is explicit.** Objectives have a `level` field: NORTH_STAR → COMPANY → DEPARTMENT → TEAM → INDIVIDUAL. North Star is a special top-level kind.

2. **Cascading ≠ Laddering.** Both produce the same parent→child link (`Objective.parent_key_result_id`), but `alignment_type` distinguishes top-down (CASCADE) from bottom-up (LADDER). The distinction matters for governance/audit.

3. **Committed vs Aspirational with override.** `commitment_type` is set on the Objective as the default. `KeyResult.commitment_type_override` is nullable and, if set, takes precedence for that specific KR. The scoring engine resolves it as:
effective = kr.commitment_type_override or kr.objective.commitment_type

4. **Stoplight bands:** 0–30 = RED, 40–60 = YELLOW, 70–100 = GREEN. The gaps (31–39, 61–69) round DOWN — you only get promoted to the next band at clean thresholds (40, 70).

5. **Committed OKRs target 100%; Aspirational target ~70%.** The scoring engine uses different curves based on the resolved commitment type.

6. **Derived fields are CACHED, not computed on read.** `Objective.progress`, `Objective.status`, `KeyResult.progress`, `KeyResult.status` are written by `scoring_service.recompute_*()` inside the same transaction as the triggering update. Never compute these on read; never update them outside the scoring service.

## Zero Trust RBAC (non-negotiable security rules)

Four roles: `ADMIN > EXECUTIVE > EMPLOYEE > PARTNER`.

**PARTNER is the zero-trust boundary.** Partners must be completely isolated:
- They can ONLY see `Task` rows where `is_external = True` AND `assignee_id = <their user_id>`.
- They must NEVER be able to query `Objective`, `KeyResult`, `CheckIn`, `Reflection`, `ChatMessage` (except for task-scoped chat they're a participant in), `AuditLog`, or `TransactionalOutbox`.
- Any task they can see must carry `sanitized_title` and `sanitized_description` — never expose the raw internal wording.
- Enforce this with explicit query filters in `services/rbac.py`, NOT with ORM-level magic. Every read path for partners must be a direct indexed lookup on `(assignee_id, is_external)`, never a join upward through the hierarchy.

**All other roles** get scoped reads based on ownership and department. Admins see everything.

## Security requirements (OWASP Top 10)

- All DB access via SQLAlchemy ORM or parameterized queries. No string-formatted SQL anywhere.
- JWT secrets from environment, never committed. Use `python-dotenv` for local dev, real secrets management in prod.
- Access tokens short-lived (15 min), refresh tokens rotated on use, stored in HttpOnly + Secure + SameSite=Strict cookies.
- CORS locked to known frontend origins.
- Rate limiting on all auth endpoints (Flask-Limiter).
- WebSocket payloads validated with the same schema layer as REST payloads (use `marshmallow` or `pydantic` — pick one and be consistent).
- All privileged actions write to `AuditLog` in the same transaction.

## Dual-portal sync (Transactional Outbox)

On Task create/update/complete/delete, the domain write AND an `TransactionalOutbox` row write happen in the **same DB transaction**. A Celery worker drains `status='pending'` rows, computes HMAC-SHA256 over the serialized payload with a shared secret, POSTs to the partner webhook, and moves the row to DELIVERED (or retries with exponential backoff up to `max_retries`, then DEAD_LETTER).

The outbox payload uses `Task.sanitized_*` fields only — never raw internal titles/descriptions.

## Phased build plan

We are executing this in four phases. Do not skip ahead.

- **Phase 1 — DONE.** `backend/app/models.py` contains the full SQLAlchemy schema.
- **Phase 2 — Current.** Build `backend/app/services/` (scoring, alignment, rbac, sanitization) and `backend/app/routes.py` wiring them to Flask blueprints. Write unit tests alongside each service — the scoring math and RBAC filters need tests at spec time, not retrofitted.
- **Phase 3.** Import the existing React/Vite frontend into `frontend/`, strip out hardcoded mock arrays from `ObjectiveList.tsx`, `Analytics.tsx`, `StatsCards.tsx`, `History.tsx`, `Settings.tsx`, and wire them to the Phase 2 API endpoints using React Query.
- **Phase 4.** Flask-SocketIO chat with regex DLP scrubber, plus the Celery outbox worker and HMAC signer for the dual-portal sync.

## Working style for Claude Code

- **Always use Plan Mode on the first pass of a new file** so I can review the approach before code is written.
- **Use Extended Thinking for scoring math and RBAC filters** — these are the parts where "looks right" and "is right" diverge.
- **Write tests in the same change as the code they test.** The services are the correctness-critical layer; untested services are incomplete deliverables.
- **Do not create mock data.** Every endpoint returns real data from the DB, or an empty list for a genuinely empty DB.
- **Stop and ask if the framework rules above would need to bend** to implement something. They are the source of truth, not suggestions.
- **Never modify `CLAUDE.md` or `models.py` without explicit instruction.** These are locked artifacts from the planning phase.

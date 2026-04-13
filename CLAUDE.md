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

**Internal role visibility model (as of Phase 2.4):**

- **ADMIN** — reads and modifies everything, no scoping.
- **Users with `is_c_suite = True`** (CEO, CFO, COO, CCO, Chairman, Board members, Compliance officers) — read everything regardless of their formal role. Write access follows their role rules (an `is_c_suite` EMPLOYEE still cannot modify another employee's objective). This flag is set by ADMIN only.
- **EXECUTIVE without `is_c_suite`** (department heads) — three-dimensional visibility:
  - (a) all Objectives whose `department_id` matches their own department;
  - (b) all Objectives on a `ProjectTeam` where their department appears in `ProjectTeamDepartment`;
  - (c) all Objectives owned by anyone in their transitive reporting chain (walked downward via `User.manager_id`).
  - Modify access: own objectives, dept objectives, and project objectives where their dept participates.
- **EMPLOYEE** — no automatic department-wide visibility. Sees only:
  - Objectives they personally own;
  - Objectives on a `ProjectTeam` where they have an explicit `ProjectTeamMember` row.
  - Can modify project objectives only if their `role_on_team = LEAD`. Regular `MEMBER` role grants read-only access to project objectives.
- **PARTNER** — see above. Zero-trust boundary is unchanged.

## Organizational model

The org chart is the structural backbone for RBAC scoping. Key concepts:

- **`User.manager_id`** — self-FK. Builds the reporting chain tree. The RBAC service walks it downward (BFS, cycle-safe) to compute transitive reports for EXECUTIVE scoping. NULL for top-level executives and users with no manager set.
- **`User.is_c_suite`** — boolean, default false. Set by ADMIN for users who need cross-silo read visibility for regulatory or governance reasons (Compliance, Legal, Board, C-suite officers). Does NOT grant elevated write privileges — those are still governed by role.
- **`Department`** — org unit, nestable via `parent_id`. Objectives, Users, and ProjectTeams all carry a `department_id`.
- **`ProjectTeam`** — the primary visibility grant mechanism for employees. Has a single `primary_department` (owner/governance) and zero or more `participating_departments` via the `ProjectTeamDepartment` join table. An employee's visibility expands only as far as the ProjectTeams they explicitly belong to.
- **`ProjectTeamMember`** — join table between User and ProjectTeam. Carries `role_on_team` (LEAD or MEMBER). LEAD grants modify access to project objectives; MEMBER grants read-only.
- **Chinese walls are the default.** Two department heads in the same division cannot see each other's objectives unless they share a ProjectTeam. This is by design — in an investment bank, information barriers between desks (e.g. M&A advisory and sales/trading) are a regulatory requirement, not a preference. The ProjectTeam mechanism is the explicit, auditable way to create controlled information flow across walls.
- **Adding someone to a ProjectTeam is the only way to grant cross-department visibility** to employees. There is no "share with a user" shortcut that bypasses this.

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

## Sanitization service (Phase 2.5)

Sanitization is a **gate**, not a transformer. The service does not rewrite or redact text — it blocks external sharing until the content is clean and has manager approval.

**Flow when an employee sets `Task.is_external = True`:**

1. The sanitization service scans `title` and `description` against a compliance-maintained pattern list stored in the database (not hardcoded YAML). Pattern categories include: client names, project codes, currency amounts, internal system IDs, percentages, unannounced event dates, internal URLs, and desk/strategy identifiers.
2. **If any pattern matches:** reject the external share. Return the matched *categories* to the employee (e.g. "possible client name, possible currency amount") without echoing the matched text back. Require the employee to rewrite and resubmit.
3. **If no patterns match:** queue the task for manager approval. Any EXECUTIVE in the same department as the task's KR, or any ADMIN, may approve.
4. **Only after approval** does the task become visible to the partner. `sanitized_title` and `sanitized_description` are written at this point (they may differ from `title`/`description` if the employee chose to use gentler partner-facing wording).

**What partners see:** sanitized title, sanitized description, status, due date, and a note "This task is contributing to [Team Name]'s progress." They never see OKR context, KR text, objective titles, financial data, or department names.

**Pattern list governance:** Compliance and Admin users maintain the pattern list via the admin UI (Phase 3). Patterns are stored as rows in a `CompliancePattern` table (to be added in Phase 2.5) with a category label, regex, and active flag. Changes write to `AuditLog`.

## Phased build plan

- **Phase 1 — DONE.** `backend/app/models.py` — full SQLAlchemy schema.
- **Phase 2.1 — DONE.** `backend/app/services/scoring.py` — scoring engine, stoplight bands, task-driven KR rollup (52 tests).
- **Phase 2.2 — DONE.** `backend/app/services/alignment.py` — cascade/ladder links, cycle detection, authority rules (46 tests).
- **Phase 2.3 — DONE.** `backend/app/services/rbac.py` — Zero Trust query scoping and permission predicates (61 tests at completion, revised in Phase 2.4).
- **Phase 2.4 — DONE.** Org chart + project-scoped RBAC. Added `User.manager_id`, `User.is_c_suite`, `ProjectTeam`, `ProjectTeamMember`, `ProjectTeamDepartment`, `Objective.project_team_id` to `models.py`; rewrote `rbac.py` with three-dimensional visibility model (75 tests).
- **Phase 2.5 — Next.** `backend/app/services/sanitization.py` — gate-based task sanitization, compliance pattern matching, manager approval flow. Requires `CompliancePattern` model addition.
- **Phase 2.6 — Pending.** `backend/app/routes.py` — Flask blueprints wiring all services to REST endpoints.
- **Phase 3 — Pending.** Import React/Vite frontend into `frontend/`, strip hardcoded mock arrays from `ObjectiveList.tsx`, `Analytics.tsx`, `StatsCards.tsx`, `History.tsx`, `Settings.tsx`, wire to Phase 2 API endpoints using React Query.
- **Phase 4 — Pending.** Flask-SocketIO chat with DLP scrubber, Celery outbox worker and HMAC signer for dual-portal sync.

## Deferred features (Phase 5+)

These are explicitly out of scope for the current build but should be kept in mind when making architectural decisions:

- **Visual org chart editor** — admin UI for managing `User.manager_id`, `Department` nesting, and `ProjectTeam` membership. Currently these are set via direct DB/API writes.
- **Information barriers as configurable rules** — currently the Chinese wall model is hardcoded: departments are isolated by default, broken only by shared `ProjectTeam` membership. A future admin UI could let Compliance define explicit barrier rules between named department pairs.
- **Formal "share project with manager" workflow** — the current mechanism for granting cross-department exec visibility is adding the manager's department to `ProjectTeamDepartment`. A structured request-and-approve UX would replace this manual step.
- **Pattern-matching search across projects** — surface similar past work to the requesting user with a controlled reveal: "5 relevant projects found — 3 are accessible to you now, 2 require access request."
- **Request-and-approval workflow for confidential access** — structured flow where a user requests access to an objective or project outside their current scope, routed to the owning department head and optionally Compliance, with full `AuditLog` trail.
- **Project templates library** — reusable `ProjectTeam` scaffolds (member roles, participating departments, standard objectives) for recurring cross-functional work patterns.

- ## Skills available in this repo

Claude Code should use the skills stored under `.claude/skills/` when their trigger conditions match.

### frontend-design (`.claude/skills/frontend-design/SKILL.md`)

**When to use:** Any time Phase 3 or later work touches React components, Tailwind styling, page layouts, dashboards, forms, or any visual/UI element. This includes rewriting the existing components (`ObjectiveList.tsx`, `Analytics.tsx`, `StatsCards.tsx`, `History.tsx`, `Settings.tsx`) and building any new UI.

**Why:** The existing frontend shell is generic. When wiring it to real data, we want the rebuild to produce a distinctive, production-grade interface rather than default AI-slop aesthetics. The skill enforces intentional typography, color, and layout choices.

**Important context for this project specifically:**
- This is an **investment bank** enterprise portal, not a consumer app. The aesthetic direction should lean toward refined, serious, data-dense, and trustworthy — not playful or maximalist.
- Think "Bloomberg terminal meets editorial magazine" rather than "startup landing page."
- Avoid: purple gradients, Inter, generic SaaS dashboard patterns, emoji icons, pastel color schemes.
- Favor: restrained color palette with one strong accent, characterful but legible typography, generous use of monospace for numeric data, dark-mode-first (the existing shell is already dark).
- Accessibility is non-negotiable. This will be used by regulated-industry staff; WCAG AA minimum.

**Do NOT use this skill during Phase 2** (backend services). It is only relevant once we start wiring the frontend in Phase 3.

## Working style for Claude Code

- **Always use Plan Mode on the first pass of a new file** so I can review the approach before code is written.
- **Use Extended Thinking for scoring math and RBAC filters** — these are the parts where "looks right" and "is right" diverge.
- **Write tests in the same change as the code they test.** The services are the correctness-critical layer; untested services are incomplete deliverables.
- **Do not create mock data.** Every endpoint returns real data from the DB, or an empty list for a genuinely empty DB.
- **Stop and ask if the framework rules above would need to bend** to implement something. They are the source of truth, not suggestions.
- **Never modify `CLAUDE.md` or `models.py` without explicit instruction.** These are locked artifacts from the planning phase.

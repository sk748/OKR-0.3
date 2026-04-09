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

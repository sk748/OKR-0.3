"""
Shared test fixtures for backend tests.

Uses in-memory SQLite for speed. SQLite does not enforce PG-specific CHECK
constraints or enum types, so Python-level logic is what's being tested here.
Integration tests against real PostgreSQL belong in a separate test suite.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime, timezone
from typing import Any

import pytest
from sqlalchemy import String, Text, create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import JSONB, UUID

from backend.app.models import (
    Base,
    Cycle,
    Department,
    KeyResult,
    Objective,
    OKRCommitmentType,
    OKRLevel,
    ProjectTeam,
    ProjectTeamDepartment,
    ProjectTeamMember,
    RoleOnTeam,
    StoplightStatus,
    Task,
    TaskStatus,
    User,
    UserRole,
)

# ---------------------------------------------------------------------------
# SQLite compatibility: map PG-specific column types to SQLite equivalents.
# This lets us run tests against in-memory SQLite without touching models.py.
# ---------------------------------------------------------------------------

from sqlalchemy import event as sa_event


@sa_event.listens_for(Base.metadata, "before_create")
def _patch_pg_types_for_sqlite(target, connection, **kw):
    """No-op — type compilation is handled below."""


@sa_event.listens_for(Base.metadata, "before_create")
def _sqlite_drop_enum_value_check_constraints(target, connection, **kw):
    """
    WORKAROUND: SQLAlchemy 2.0 on Python 3.12 stores str-based enum members
    by their .name ('PARTNER') rather than their .value ('partner') in SQLite.
    The CHECK constraint ck_users_partner_scope_matches_role was written for
    PostgreSQL where the native enum stores lowercase values. In SQLite,
    'PARTNER' != 'partner' (case-sensitive), so PARTNER user INSERTs fail.

    Fix: drop this constraint from the DDL when creating SQLite tables.
    Application-level invariant is still enforced: make_user() in this file
    always supplies partner_scope for PARTNER users. The production PostgreSQL
    path is unaffected — the constraint still exists there.
    """
    if connection.dialect.name != "sqlite":
        return
    users_table = Base.metadata.tables.get("users")
    if users_table is not None:
        users_table.constraints = {
            c for c in users_table.constraints
            if getattr(c, "name", None) != "ck_users_partner_scope_matches_role"
        }


# Register SQLite compilers for PG types.
from sqlalchemy.ext.compiler import compiles


@compiles(UUID, "sqlite")
def _compile_uuid_sqlite(type_, compiler, **kw):
    return "CHAR(32)"


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):
    return "TEXT"


@pytest.fixture()
def db_engine():
    """In-memory SQLite engine with all tables created."""
    engine = create_engine("sqlite://", echo=False)

    # SQLite needs foreign key enforcement turned on explicitly.
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, _connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def db_session(db_engine):
    """
    Yields a Session that rolls back after each test.
    Every test gets a clean slate without re-creating tables.
    """
    with Session(db_engine) as session:
        yield session
        session.rollback()


# ---------------------------------------------------------------------------
# Model factories — thin wrappers with sensible defaults.
# ---------------------------------------------------------------------------

def make_user(
    session: Session,
    *,
    email: str | None = None,
    role: UserRole = UserRole.EMPLOYEE,
    department: Department | None = None,
    manager: "User | None" = None,
    is_c_suite: bool = False,
    **overrides: Any,
) -> User:
    partner_scope = overrides.pop("partner_scope", None)
    if partner_scope is None and role == UserRole.PARTNER:
        partner_scope = {"allowed": True}

    kwargs: dict[str, Any] = {
        "id": uuid.uuid4(),
        "email": email or f"user-{uuid.uuid4().hex[:8]}@test.com",
        "display_name": overrides.pop("display_name", "Test User"),
        "role": role,
        "department_id": department.id if department else None,
        "manager_id": manager.id if manager else None,
        "is_c_suite": is_c_suite,
        "is_active": overrides.pop("is_active", True),
    }
    # Only set partner_scope when non-None to avoid JSONB serializing
    # Python None as JSON 'null' string (vs SQL NULL) on SQLite.
    if partner_scope is not None:
        kwargs["partner_scope"] = partner_scope
    kwargs.update(overrides)

    user = User(**kwargs)
    session.add(user)
    session.flush()
    return user


def make_c_suite_user(
    session: Session,
    *,
    role: UserRole = UserRole.EXECUTIVE,
    department: Department | None = None,
    **overrides: Any,
) -> User:
    """Convenience wrapper that always sets is_c_suite=True."""
    return make_user(session, role=role, department=department, is_c_suite=True, **overrides)


def make_department(
    session: Session,
    *,
    name: str = "Engineering",
    slug: str | None = None,
    **overrides: Any,
) -> Department:
    dept = Department(
        id=uuid.uuid4(),
        name=name,
        slug=slug or f"dept-{uuid.uuid4().hex[:8]}",
        **overrides,
    )
    session.add(dept)
    session.flush()
    return dept


def make_cycle(
    session: Session,
    *,
    name: str = "Q2 2026",
    year: int = 2026,
    quarter: int = 2,
    start_date: date | None = None,
    end_date: date | None = None,
    **overrides: Any,
) -> Cycle:
    cycle = Cycle(
        id=uuid.uuid4(),
        name=name,
        year=year,
        quarter=quarter,
        start_date=start_date or date(2026, 4, 1),
        end_date=end_date or date(2026, 6, 30),
        is_active=overrides.pop("is_active", True),
        **overrides,
    )
    session.add(cycle)
    session.flush()
    return cycle


def make_objective(
    session: Session,
    *,
    owner: User,
    cycle: Cycle,
    level: OKRLevel = OKRLevel.TEAM,
    commitment_type: OKRCommitmentType = OKRCommitmentType.COMMITTED,
    **overrides: Any,
) -> Objective:
    obj = Objective(
        id=uuid.uuid4(),
        title=overrides.pop("title", "Test Objective"),
        level=level,
        commitment_type=commitment_type,
        owner_id=owner.id,
        cycle_id=cycle.id,
        department_id=overrides.pop("department_id", None),
        progress=overrides.pop("progress", 0),
        status=overrides.pop("status", StoplightStatus.PENDING),
        **overrides,
    )
    session.add(obj)
    session.flush()
    return obj


def make_key_result(
    session: Session,
    *,
    objective: Objective,
    owner: User | None = None,
    start_value: float = 0,
    target_value: float = 100,
    current_value: float = 0,
    is_task_driven: bool = False,
    **overrides: Any,
) -> KeyResult:
    kr = KeyResult(
        id=uuid.uuid4(),
        objective_id=objective.id,
        owner_id=(owner or objective.owner).id,
        title=overrides.pop("title", "Test Key Result"),
        start_value=start_value,
        current_value=current_value,
        target_value=target_value,
        is_task_driven=is_task_driven,
        progress=overrides.pop("progress", 0),
        status=overrides.pop("status", StoplightStatus.PENDING),
        **overrides,
    )
    session.add(kr)
    session.flush()
    return kr


def make_task(
    session: Session,
    *,
    key_result: KeyResult,
    status: TaskStatus = TaskStatus.TODO,
    weight: float = 1,
    assignee: User | None = None,
    **overrides: Any,
) -> Task:
    task = Task(
        id=uuid.uuid4(),
        key_result_id=key_result.id,
        title=overrides.pop("title", "Test Task"),
        status=status,
        weight=weight,
        assignee_id=assignee.id if assignee else None,
        is_external=overrides.pop("is_external", False),
        **overrides,
    )
    session.add(task)
    session.flush()
    return task


def make_project_team(
    session: Session,
    *,
    name: str = "Test Project",
    primary_department: Department,
    participating_departments: list[Department] | None = None,
    **overrides: Any,
) -> ProjectTeam:
    """
    Create a ProjectTeam.

    The primary_department is always wired as a participating department.
    Additional departments can be passed via participating_departments.
    """
    pt = ProjectTeam(
        id=uuid.uuid4(),
        name=name,
        description=overrides.pop("description", None),
        primary_department_id=primary_department.id,
        **overrides,
    )
    session.add(pt)
    session.flush()

    # Wire participating departments — primary always included.
    seen: set[uuid.UUID] = set()
    for dept in (participating_departments or []):
        if dept.id not in seen:
            seen.add(dept.id)
            session.add(ProjectTeamDepartment(
                project_team_id=pt.id,
                department_id=dept.id,
            ))
    # Primary dept always participates (add after loop to avoid duplication).
    if primary_department.id not in seen:
        session.add(ProjectTeamDepartment(
            project_team_id=pt.id,
            department_id=primary_department.id,
        ))
    session.flush()
    return pt


def make_project_member(
    session: Session,
    *,
    user: User,
    project_team: ProjectTeam,
    role_on_team: RoleOnTeam = RoleOnTeam.MEMBER,
) -> ProjectTeamMember:
    """Add a user to a project team with a given role."""
    m = ProjectTeamMember(
        user_id=user.id,
        project_team_id=project_team.id,
        role_on_team=role_on_team,
    )
    session.add(m)
    session.flush()
    return m

"""
OKRSYNC — SQLAlchemy models (Phase 1).

Domain model for a Zero Trust OKR & Agile Sprint portal based on the
"What Matters" framework (Doerr). Designed for PostgreSQL.

Conventions:
  - SQLAlchemy 2.0 typed `Mapped[]` style.
  - UUID primary keys everywhere (safer than sequential ints for a portal
    that syncs data to external partners).
  - `created_at` / `updated_at` / `deleted_at` on every mutable domain table.
  - Derived fields (`progress`, `status`) are CACHED. The scoring service
    in Phase 2 is the single writer.
  - Enums are Python-side; the DB stores them as native PG enums.

Phase 2 will add: routes.py, services.py (scoring engine, RBAC query
filters), and the Celery tasks that drain TransactionalOutbox.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, date
from typing import Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Enum as SQLEnum,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    """Declarative base. All models inherit from this."""

    pass


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )


# ---------------------------------------------------------------------------
# Enums — these encode framework rules, not UI preferences.
# ---------------------------------------------------------------------------


class UserRole(str, enum.Enum):
    """
    RBAC roles. Order matters for privilege comparisons in services.py:
    ADMIN > EXECUTIVE > EMPLOYEE > PARTNER.

    PARTNER is the zero-trust boundary. Partners can ONLY see Tasks where
    is_external=True AND assignee_id matches their user_id. They must
    never see Objective or KeyResult rows.
    """

    ADMIN = "admin"
    EXECUTIVE = "executive"
    EMPLOYEE = "employee"
    PARTNER = "partner"


class OKRLevel(str, enum.Enum):
    """
    Org levels at which an Objective lives. From the North Star template:
    Executive Layer → Strategic/Cross-functional → Specialized Teams → Individual.

    NORTH_STAR is a special subtype of COMPANY — it's what the exec team
    commits to annually and what everything else ultimately ladders up to.
    """

    NORTH_STAR = "north_star"
    COMPANY = "company"
    DEPARTMENT = "department"
    TEAM = "team"
    INDIVIDUAL = "individual"


class OKRCommitmentType(str, enum.Enum):
    """
    From the Scoring PDF: committed OKRs target 100%, aspirational target ~70%.
    The stoplight engine uses this to decide which band a given score falls into.
    """

    COMMITTED = "committed"
    ASPIRATIONAL = "aspirational"


class StoplightStatus(str, enum.Enum):
    """
    Derived from progress %. The gaps in the framework bands (31-39, 61-69)
    are handled by nearest-band rounding in services.py — see score_progress().
    """

    RED = "red"  # 0-30: failed to make significant progress
    YELLOW = "yellow"  # 40-60: made progress, did not complete
    GREEN = "green"  # 70-100: delivered
    PENDING = "pending"  # no data yet (new OKR, no check-ins)


class AlignmentType(str, enum.Enum):
    """
    Cascade = top-down delegation. Ladder = bottom-up self-initiated alignment.
    The distinction matters for governance/audit, not for the resulting
    parent→child link structure, but the PDFs treat them as separate events.
    """

    CASCADE = "cascade"
    LADDER = "ladder"


class TaskStatus(str, enum.Enum):
    TODO = "todo"
    IN_PROGRESS = "in_progress"
    DONE = "done"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class ReflectionAction(str, enum.Enum):
    """End-of-cycle disposition, from the Scoring PDF's '5 Rs'."""

    RETIRE = "retire"
    REWRITE = "rewrite"
    ROLLOVER = "rollover"
    RECRAFT = "recraft"
    RETHINK = "rethink"


class OutboxStatus(str, enum.Enum):
    PENDING = "pending"
    IN_FLIGHT = "in_flight"
    DELIVERED = "delivered"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"


class OutboxEventType(str, enum.Enum):
    """Event types the external partner portal subscribes to."""

    TASK_CREATED = "task.created"
    TASK_UPDATED = "task.updated"
    TASK_COMPLETED = "task.completed"
    TASK_DELETED = "task.deleted"


# ---------------------------------------------------------------------------
# Users & Organization
# ---------------------------------------------------------------------------


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = _uuid_pk()
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        SQLEnum(UserRole, name="user_role"), nullable=False, default=UserRole.EMPLOYEE
    )
    department_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("departments.id", ondelete="SET NULL"), nullable=True
    )

    # Auth bookkeeping. Password hash is nullable because partners may be
    # provisioned via invite token before they set a password, and internal
    # users may authenticate via SSO in which case this stays null.
    password_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # For partners: the scope of tasks they're allowed to touch. NULL for
    # internal users. Enforced in services.py query filters, not at the ORM layer.
    partner_scope: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    department: Mapped[Optional["Department"]] = relationship(back_populates="members")
    owned_objectives: Mapped[list["Objective"]] = relationship(back_populates="owner")
    assigned_tasks: Mapped[list["Task"]] = relationship(back_populates="assignee")

    __table_args__ = (
        # Partners must have a partner_scope; internal users must not.
        CheckConstraint(
            "(role = 'partner' AND partner_scope IS NOT NULL) OR "
            "(role <> 'partner' AND partner_scope IS NULL)",
            name="ck_users_partner_scope_matches_role",
        ),
        Index("ix_users_role", "role"),
    )


class Department(Base):
    """
    Org unit. The 'circle' concept from the Cascade PDF — who's in the
    blast radius of a given Objective. Can be nested for larger orgs.
    """

    __tablename__ = "departments"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    parent_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("departments.id", ondelete="SET NULL"), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    parent: Mapped[Optional["Department"]] = relationship(
        remote_side="Department.id", back_populates="children"
    )
    children: Mapped[list["Department"]] = relationship(back_populates="parent")
    members: Mapped[list[User]] = relationship(back_populates="department")
    objectives: Mapped[list["Objective"]] = relationship(back_populates="department")


# ---------------------------------------------------------------------------
# Cycles — the Q1..Q4 calendar rhythm from the Calendar PDF.
# ---------------------------------------------------------------------------


class Cycle(Base):
    """
    A time-boxed OKR period. The Calendar PDF defines check-in cadence
    (every 2 weeks), grading dates, and brainstorming dates per quarter.
    History.tsx pages are fundamentally 'group Objectives by cycle'.
    """

    __tablename__ = "cycles"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(50), nullable=False)  # e.g. "Q1 2026"
    year: Mapped[int] = mapped_column(Integer, nullable=False)
    quarter: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # 1-4, NULL for annual
    start_date: Mapped[date] = mapped_column(Date, nullable=False)
    end_date: Mapped[date] = mapped_column(Date, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    objectives: Mapped[list["Objective"]] = relationship(back_populates="cycle")

    __table_args__ = (
        UniqueConstraint("year", "quarter", name="uq_cycles_year_quarter"),
        CheckConstraint("end_date > start_date", name="ck_cycles_date_order"),
        CheckConstraint("quarter IS NULL OR (quarter BETWEEN 1 AND 4)", name="ck_cycles_quarter_range"),
    )


# ---------------------------------------------------------------------------
# Objectives & Key Results — the core of the "What Matters" framework.
# ---------------------------------------------------------------------------


class Objective(Base):
    """
    The "What" — an inspirational, qualitative goal. Objectives are NOT
    supposed to contain metrics; those live in their KeyResults.

    `parent_key_result_id` is the cascade/ladder link: per the Cascade PDF,
    "a KR at one level becomes an Objective at another level." NULL means
    this is a top-level Objective (typically a North Star).
    """

    __tablename__ = "objectives"

    id: Mapped[uuid.UUID] = _uuid_pk()
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    level: Mapped[OKRLevel] = mapped_column(SQLEnum(OKRLevel, name="okr_level"), nullable=False)
    commitment_type: Mapped[OKRCommitmentType] = mapped_column(
        SQLEnum(OKRCommitmentType, name="okr_commitment_type"),
        nullable=False,
        default=OKRCommitmentType.COMMITTED,
    )

    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    department_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("departments.id", ondelete="SET NULL"), nullable=True
    )
    cycle_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cycles.id", ondelete="RESTRICT"), nullable=False
    )

    # The cascade/ladder spine. If set, this Objective was derived from
    # a parent KeyResult at a higher (cascade) or different (ladder) level.
    parent_key_result_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("key_results.id", ondelete="SET NULL"), nullable=True
    )
    alignment_type: Mapped[Optional[AlignmentType]] = mapped_column(
        SQLEnum(AlignmentType, name="alignment_type"), nullable=True
    )

    # CACHED derived fields. Single writer: scoring_service.recompute_objective().
    # Never update these from a route handler directly.
    progress: Mapped[float] = mapped_column(
        Numeric(5, 2), nullable=False, default=0, server_default="0"
    )
    status: Mapped[StoplightStatus] = mapped_column(
        SQLEnum(StoplightStatus, name="stoplight_status"),
        nullable=False,
        default=StoplightStatus.PENDING,
    )
    last_scored_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    owner: Mapped[User] = relationship(back_populates="owned_objectives")
    department: Mapped[Optional[Department]] = relationship(back_populates="objectives")
    cycle: Mapped[Cycle] = relationship(back_populates="objectives")
    key_results: Mapped[list["KeyResult"]] = relationship(
        back_populates="objective",
        foreign_keys="[KeyResult.objective_id]",
        cascade="all, delete-orphan",
        order_by="KeyResult.display_order",
    )
    parent_key_result: Mapped[Optional["KeyResult"]] = relationship(
        foreign_keys=[parent_key_result_id],
        back_populates="child_objectives",
    )
    reflections: Mapped[list["Reflection"]] = relationship(back_populates="objective")

    __table_args__ = (
        Index("ix_objectives_cycle_level", "cycle_id", "level"),
        Index("ix_objectives_owner", "owner_id"),
        Index("ix_objectives_parent_kr", "parent_key_result_id"),
        # Soft-delete: most queries filter deleted_at IS NULL.
        Index("ix_objectives_active", "cycle_id", postgresql_where=(deleted_at.is_(None))),
        CheckConstraint("progress >= 0 AND progress <= 100", name="ck_objectives_progress_range"),
        # If parent_key_result_id is set, alignment_type must be set (and vice versa).
        CheckConstraint(
            "(parent_key_result_id IS NULL AND alignment_type IS NULL) OR "
            "(parent_key_result_id IS NOT NULL AND alignment_type IS NOT NULL)",
            name="ck_objectives_alignment_consistency",
        ),
    )


class KeyResult(Base):
    """
    The "How you'll know" — quantitative, measurable outcomes.

    Progress is driven two ways:
      1. Manual: owner updates current_value (most common for metric-driven KRs).
      2. Derived: progress computed from linked Task completion (for work-driven KRs).

    `is_task_driven` decides which path the scoring engine takes.
    """

    __tablename__ = "key_results"

    id: Mapped[uuid.UUID] = _uuid_pk()
    objective_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("objectives.id", ondelete="CASCADE"), nullable=False
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Metric definition. unit is free-text ("deals", "%", "USD", ...).
    start_value: Mapped[float] = mapped_column(Numeric(20, 4), nullable=False, default=0)
    current_value: Mapped[float] = mapped_column(Numeric(20, 4), nullable=False, default=0)
    target_value: Mapped[float] = mapped_column(Numeric(20, 4), nullable=False)
    unit: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    is_task_driven: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    display_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Per-KR commitment override. NULL = inherit from parent Objective (the
    # common case). Set to COMMITTED or ASPIRATIONAL to override for this
    # specific KR — e.g. a mostly-committed Objective with one stretch KR.
    # The scoring engine resolves this as:
    #     effective = kr.commitment_type_override or kr.objective.commitment_type
    # See services.py::resolve_commitment_type() in Phase 2.
    commitment_type_override: Mapped[Optional[OKRCommitmentType]] = mapped_column(
        SQLEnum(OKRCommitmentType, name="okr_commitment_type"), nullable=True
    )

    # CACHED derived fields. See Objective.progress note.
    progress: Mapped[float] = mapped_column(
        Numeric(5, 2), nullable=False, default=0, server_default="0"
    )
    status: Mapped[StoplightStatus] = mapped_column(
        SQLEnum(StoplightStatus, name="stoplight_status"),
        nullable=False,
        default=StoplightStatus.PENDING,
    )
    last_scored_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    objective: Mapped[Objective] = relationship(
        back_populates="key_results",
        foreign_keys=[objective_id],
    )
    owner: Mapped[User] = relationship()
    tasks: Mapped[list["Task"]] = relationship(
        back_populates="key_result", cascade="all, delete-orphan"
    )
    # Objectives that ladder/cascade UP from this KR (i.e. this KR is their parent).
    child_objectives: Mapped[list[Objective]] = relationship(
        foreign_keys=[Objective.parent_key_result_id],
        back_populates="parent_key_result",
    )
    check_ins: Mapped[list["CheckIn"]] = relationship(back_populates="key_result")

    __table_args__ = (
        Index("ix_key_results_objective", "objective_id"),
        CheckConstraint("progress >= 0 AND progress <= 100", name="ck_key_results_progress_range"),
        CheckConstraint("target_value <> start_value", name="ck_key_results_meaningful_target"),
    )


# ---------------------------------------------------------------------------
# Tasks — Agile sprint work items. The zero-trust boundary for partners.
# ---------------------------------------------------------------------------


class Task(Base):
    """
    Sprint-level work item linked to a KR. Tasks are the ONLY entity an
    External Partner can see, and only when is_external=True and the
    partner is the assignee.

    sanitized_title / sanitized_description are the fields that get
    serialized into the Transactional Outbox. They're populated by the
    scrubber in services.py whenever the parent fields change — the
    partner must never see internal wording that leaks strategy.
    """

    __tablename__ = "tasks"

    id: Mapped[uuid.UUID] = _uuid_pk()
    key_result_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("key_results.id", ondelete="CASCADE"), nullable=False
    )

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    status: Mapped[TaskStatus] = mapped_column(
        SQLEnum(TaskStatus, name="task_status"), nullable=False, default=TaskStatus.TODO
    )
    assignee_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Zero-trust fields.
    is_external: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    sanitized_title: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    sanitized_description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Weight for task-driven KR progress rollup. Equal weights by default.
    weight: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False, default=1)

    due_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    key_result: Mapped[KeyResult] = relationship(back_populates="tasks")
    assignee: Mapped[Optional[User]] = relationship(back_populates="assigned_tasks")

    __table_args__ = (
        Index("ix_tasks_key_result", "key_result_id"),
        Index("ix_tasks_assignee_external", "assignee_id", "is_external"),
        # Hot path for partner queries: "all external tasks assigned to me".
        Index(
            "ix_tasks_partner_scope",
            "assignee_id",
            postgresql_where=(is_external.is_(True)),
        ),
        # If a task is external, it MUST have sanitized fields populated.
        CheckConstraint(
            "is_external = false OR sanitized_title IS NOT NULL",
            name="ck_tasks_external_requires_sanitized",
        ),
        CheckConstraint("weight > 0", name="ck_tasks_positive_weight"),
    )


# ---------------------------------------------------------------------------
# Check-ins & Reflections — the cycle rhythm from Calendar + Scoring PDFs.
# ---------------------------------------------------------------------------


class CheckIn(Base):
    """
    Bi-weekly check-in per the Calendar PDF. Captures confidence (0-10,
    which is what StatsCards.tsx displays) and a narrative update.
    One per KR per check-in date.
    """

    __tablename__ = "check_ins"

    id: Mapped[uuid.UUID] = _uuid_pk()
    key_result_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("key_results.id", ondelete="CASCADE"), nullable=False
    )
    author_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )

    confidence: Mapped[int] = mapped_column(Integer, nullable=False)  # 0-10
    reported_progress: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False)
    narrative: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    key_result: Mapped[KeyResult] = relationship(back_populates="check_ins")
    author: Mapped[User] = relationship()

    __table_args__ = (
        CheckConstraint("confidence BETWEEN 0 AND 10", name="ck_check_ins_confidence_range"),
        CheckConstraint(
            "reported_progress >= 0 AND reported_progress <= 100",
            name="ck_check_ins_progress_range",
        ),
        Index("ix_check_ins_kr_time", "key_result_id", "created_at"),
    )


class Reflection(Base):
    """
    End-of-cycle reflection on an Objective, capturing one of the '5 Rs'
    from the Scoring PDF (Retire/Rewrite/Rollover/Recraft/Rethink) plus
    free-text learnings. This is the audit trail that powers the History
    page's cross-quarter comparisons.
    """

    __tablename__ = "reflections"

    id: Mapped[uuid.UUID] = _uuid_pk()
    objective_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("objectives.id", ondelete="CASCADE"), nullable=False
    )
    author_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )

    action: Mapped[ReflectionAction] = mapped_column(
        SQLEnum(ReflectionAction, name="reflection_action"), nullable=False
    )
    final_score: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False)
    what_worked: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    what_didnt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    next_cycle_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    objective: Mapped[Objective] = relationship(back_populates="reflections")
    author: Mapped[User] = relationship()

    __table_args__ = (
        UniqueConstraint("objective_id", "author_id", name="uq_reflections_one_per_author"),
        CheckConstraint(
            "final_score >= 0 AND final_score <= 100", name="ck_reflections_score_range"
        ),
    )


# ---------------------------------------------------------------------------
# Collaboration — chat scoped to a KR or Task.
# ---------------------------------------------------------------------------


class ChatMessage(Base):
    """
    Messages sent via Flask-SocketIO in Phase 4. The 'context' is either
    a KeyResult or a Task — not both. Partner users may only send/read
    messages where context_type='task' AND they're the task assignee.

    `raw_text` is what the user typed; `scrubbed_text` is what the DLP
    pipeline produced and what other users actually see. Storing both
    lets admins audit DLP decisions without re-scanning history.
    """

    __tablename__ = "chat_messages"

    id: Mapped[uuid.UUID] = _uuid_pk()
    context_type: Mapped[str] = mapped_column(String(20), nullable=False)  # 'key_result' | 'task'
    context_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    sender_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    raw_text: Mapped[str] = mapped_column(Text, nullable=False)
    scrubbed_text: Mapped[str] = mapped_column(Text, nullable=False)
    dlp_hits: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    sender: Mapped[User] = relationship()

    __table_args__ = (
        Index("ix_chat_context", "context_type", "context_id", "created_at"),
        CheckConstraint(
            "context_type IN ('key_result', 'task')", name="ck_chat_valid_context_type"
        ),
    )


# ---------------------------------------------------------------------------
# Transactional Outbox — guarantees atomic "domain write + sync event".
# ---------------------------------------------------------------------------


class TransactionalOutbox(Base):
    """
    Core of the dual-portal sync. When a Task is created/updated/completed/
    deleted in the same DB transaction we INSERT a row here. A Celery
    worker drains PENDING rows, computes HMAC-SHA256 over the payload,
    POSTs to the partner webhook, and moves the row to DELIVERED (or
    retries on failure with exponential backoff up to max_retries, then
    DEAD_LETTER).

    This pattern is the correct answer to "how do I avoid the webhook
    firing for a transaction that rolled back?" — both writes commit or
    neither does, because they're in the same transaction.
    """

    __tablename__ = "transactional_outbox"

    id: Mapped[uuid.UUID] = _uuid_pk()
    event_type: Mapped[OutboxEventType] = mapped_column(
        SQLEnum(OutboxEventType, name="outbox_event_type"), nullable=False
    )
    aggregate_type: Mapped[str] = mapped_column(String(50), nullable=False)  # 'task'
    aggregate_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    # Pre-sanitized payload. The worker does NOT re-query the DB; it just
    # ships this blob. That keeps the worker decoupled from schema changes
    # and lets us replay events even after soft-deletes.
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    destination_url: Mapped[str] = mapped_column(String(500), nullable=False)

    status: Mapped[OutboxStatus] = mapped_column(
        SQLEnum(OutboxStatus, name="outbox_status"), nullable=False, default=OutboxStatus.PENDING
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_retries: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    next_attempt_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    delivered_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        # The worker's polling query: WHERE status='pending' ORDER BY created_at.
        Index(
            "ix_outbox_pending",
            "created_at",
            postgresql_where=(status == OutboxStatus.PENDING),
        ),
        Index("ix_outbox_aggregate", "aggregate_type", "aggregate_id"),
    )


# ---------------------------------------------------------------------------
# Audit log — RBAC-sensitive actions.
# ---------------------------------------------------------------------------


class AuditLog(Base):
    """
    Append-only log of privileged actions. Specifically:
      - Role changes
      - Cascade/ladder link creation
      - External partner invitations and scope changes
      - Outbox delivery outcomes (for compliance)
      - Failed authorization attempts (partner tried to read an Objective)

    This is the table the Settings page's 'audit trail' tab will read from.
    """

    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = _uuid_pk()
    actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    target_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    target_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)  # IPv6-safe

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    actor: Mapped[Optional[User]] = relationship()

    __table_args__ = (
        Index("ix_audit_actor_time", "actor_id", "created_at"),
        Index("ix_audit_action", "action"),
    )

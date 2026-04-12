"""
Alignment service for OKRSYNC.

This module manages the parent→child links in the OKR alignment tree.
It is the single writer for Objective.parent_key_result_id and
Objective.alignment_type. No other code may write to these fields.

CASCADE  = top-down delegation: a manager/exec cascades their KR down as a
           child Objective at a lower org level.
LADDER   = bottom-up self-alignment: an individual/team voluntarily aligns
           their own Objective upward to a higher-level KR.

TRANSACTION RULE: Functions in this module call session.flush() when they
need to make intermediate state visible, but they NEVER call session.commit().
The caller (route handler, Celery task, or test fixture) is responsible for
committing the transaction.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models import (
    AlignmentType,
    AuditLog,
    KeyResult,
    Objective,
    User,
    UserRole,
)


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Maximum number of levels to walk upward when checking for cycles.
# OKR hierarchies in practice are NORTH_STAR → COMPANY → DEPARTMENT → TEAM →
# INDIVIDUAL (5 levels), so 20 gives a large safety margin before we assume
# the data is corrupt rather than deeply nested.
_MAX_DEPTH: int = 20


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------


class AlignmentError(ValueError):
    """
    Raised for domain-level alignment violations:
      - cycle detected in the alignment graph
      - objective already aligned
      - objective not aligned (on remove)
      - soft-deleted entity
      - inconsistent schema state
    """


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _assert_not_soft_deleted(obj: Any, label: str) -> None:
    """Raise AlignmentError if obj.deleted_at is set."""
    if obj.deleted_at is not None:
        raise AlignmentError(f"{label} is soft-deleted")


def _assert_not_already_aligned(child_objective: Objective) -> None:
    """Raise AlignmentError if child_objective already has a parent KR."""
    if child_objective.parent_key_result_id is not None:
        raise AlignmentError("objective is already aligned to a key result")


def _assert_has_alignment(child_objective: Objective) -> None:
    """Raise AlignmentError if child_objective has no parent KR to remove."""
    if child_objective.parent_key_result_id is None:
        raise AlignmentError("objective has no alignment to remove")
    # Schema invariant: both fields must be set together.
    if child_objective.alignment_type is None:
        raise AlignmentError(
            "objective has inconsistent alignment state "
            "(parent_key_result_id is set but alignment_type is null)"
        )


def _would_create_cycle(
    parent_kr: KeyResult,
    child_objective: Objective,
    session: Session,
) -> bool:
    """
    Walk the ancestor chain of parent_kr upward through the alignment spine
    and return True if child_objective appears in that chain.

    If we're about to add child_objective.parent_key_result_id = parent_kr.id,
    a cycle exists iff child_objective is already an ancestor of parent_kr.

    Walk direction at each step:
        current_objective  →  its parent_key_result_id  →  that KR's objective_id  →  ...

    Uses targeted scalar queries (one column only) to avoid loading full rows.

    Raises AlignmentError if the chain exceeds _MAX_DEPTH, which would indicate
    corrupt data rather than a legitimate deep hierarchy.
    """
    # Start from the objective that owns parent_kr.
    current_obj_id = parent_kr.objective_id

    for _ in range(_MAX_DEPTH):
        if current_obj_id == child_objective.id:
            return True

        # Fetch only the parent_key_result_id column of the current objective.
        row = session.execute(
            select(Objective.parent_key_result_id).where(
                Objective.id == current_obj_id
            )
        ).first()

        if row is None:
            # Objective not found (orphan data) — safe to treat as no-cycle.
            return False

        parent_kr_id = row[0]
        if parent_kr_id is None:
            # Reached the top of the hierarchy (no parent KR) — no cycle.
            return False

        # Fetch only the objective_id column of the parent KR.
        current_obj_id = session.execute(
            select(KeyResult.objective_id).where(KeyResult.id == parent_kr_id)
        ).scalar_one_or_none()

        if current_obj_id is None:
            # KR not found (orphan data) — safe to treat as no-cycle.
            return False

    raise AlignmentError(
        f"Alignment chain exceeds maximum depth ({_MAX_DEPTH}). "
        "Data may be corrupt."
    )


def _write_audit_log(
    actor: User,
    action: str,
    child_objective: Objective,
    parent_kr_id: uuid.UUID | None,
    alignment_type: AlignmentType | None,
    session: Session,
) -> None:
    """
    Write an AuditLog row for an alignment change.

    The row captures pre-change values so it is meaningful on remove too:
    pass the original parent_kr_id / alignment_type before clearing them.

    Does NOT flush — caller flushes after the domain write.
    """
    log = AuditLog(
        id=uuid.uuid4(),
        actor_id=actor.id,
        action=action,
        target_type="objective",
        target_id=child_objective.id,
        details={
            "parent_kr_id": str(parent_kr_id) if parent_kr_id is not None else None,
            "child_objective_id": str(child_objective.id),
            "alignment_type": alignment_type.value if alignment_type is not None else None,
        },
    )
    session.add(log)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_cascade_link(
    parent_kr: KeyResult,
    child_objective: Objective,
    actor: User,
    session: Session,
) -> None:
    """
    Create a top-down CASCADE alignment: parent_kr's objective delegates its
    KR downward, and child_objective becomes the lower-level realisation.

    Sets child_objective.parent_key_result_id = parent_kr.id and
    child_objective.alignment_type = CASCADE atomically.

    Authority:
      actor.role in (ADMIN, EXECUTIVE)  OR  actor.id == parent_kr.owner_id

    Raises:
      AlignmentError   — pre-condition violation or cycle detected.
      PermissionError  — actor lacks authority.

    Calls session.flush(). Does NOT commit.
    """
    # Pre-conditions (checked before authority to avoid leaking privilege info
    # through differing error paths).
    _assert_not_soft_deleted(child_objective, "objective")
    _assert_not_soft_deleted(parent_kr, "key result")
    _assert_not_already_aligned(child_objective)

    # Authority check.
    if not (
        actor.role in (UserRole.ADMIN, UserRole.EXECUTIVE)
        or actor.id == parent_kr.owner_id
    ):
        raise PermissionError(
            "creating a cascade link requires ADMIN or EXECUTIVE role, "
            "or ownership of the parent key result"
        )

    # Cycle detection (after authority to avoid unnecessary DB round-trips).
    if _would_create_cycle(parent_kr, child_objective, session):
        raise AlignmentError(
            "creating this cascade link would produce a cycle in the alignment tree"
        )

    # Domain write — both fields set atomically.
    child_objective.parent_key_result_id = parent_kr.id
    child_objective.alignment_type = AlignmentType.CASCADE

    _write_audit_log(
        actor, "alignment.create_cascade",
        child_objective, parent_kr.id, AlignmentType.CASCADE,
        session,
    )

    session.flush()


def create_ladder_link(
    parent_kr: KeyResult,
    child_objective: Objective,
    actor: User,
    session: Session,
) -> None:
    """
    Create a bottom-up LADDER alignment: child_objective's owner volunteers to
    align their Objective upward to parent_kr at a higher org level.

    Sets child_objective.parent_key_result_id = parent_kr.id and
    child_objective.alignment_type = LADDER atomically.

    Authority:
      actor.id == child_objective.owner_id  OR  actor.role == ADMIN

    Note: EXECUTIVE role alone is NOT sufficient for laddering — this is
    explicitly a self-service, bottom-up action. Only the owner of the child
    objective (or an admin) may initiate it.

    Raises:
      AlignmentError   — pre-condition violation or cycle detected.
      PermissionError  — actor lacks authority.

    Calls session.flush(). Does NOT commit.
    """
    # Pre-conditions.
    _assert_not_soft_deleted(child_objective, "objective")
    _assert_not_soft_deleted(parent_kr, "key result")
    _assert_not_already_aligned(child_objective)

    # Authority check.
    if not (
        actor.role == UserRole.ADMIN
        or actor.id == child_objective.owner_id
    ):
        raise PermissionError(
            "creating a ladder link requires ADMIN role "
            "or ownership of the child objective"
        )

    # Cycle detection.
    if _would_create_cycle(parent_kr, child_objective, session):
        raise AlignmentError(
            "creating this ladder link would produce a cycle in the alignment tree"
        )

    # Domain write.
    child_objective.parent_key_result_id = parent_kr.id
    child_objective.alignment_type = AlignmentType.LADDER

    _write_audit_log(
        actor, "alignment.create_ladder",
        child_objective, parent_kr.id, AlignmentType.LADDER,
        session,
    )

    session.flush()


def remove_alignment(
    child_objective: Objective,
    actor: User,
    session: Session,
) -> None:
    """
    Remove the alignment link from child_objective to its parent KR.

    Clears child_objective.parent_key_result_id and child_objective.alignment_type
    atomically. Authority depends on the existing alignment_type:

      CASCADE link:
        actor.role in (ADMIN, EXECUTIVE)  OR  actor.id == parent_kr.owner_id
        (the delegatee/child_objective owner may NOT unilaterally abandon a
        cascaded delegation — the delegator or an admin must remove it)

      LADDER link:
        actor.role in (ADMIN, EXECUTIVE)  OR  actor.id == child_objective.owner_id

    Raises:
      AlignmentError   — objective has no alignment, or schema is inconsistent.
      PermissionError  — actor lacks authority.

    Calls session.flush(). Does NOT commit.
    """
    # Pre-condition: must have an existing alignment to remove.
    _assert_has_alignment(child_objective)

    # Capture pre-removal state — needed for authority check and audit.
    existing_parent_kr_id = child_objective.parent_key_result_id
    existing_alignment_type = child_objective.alignment_type

    # Authority depends on alignment_type.
    if existing_alignment_type == AlignmentType.CASCADE:
        # For CASCADE: only the delegator (parent_kr owner) or ADMIN/EXECUTIVE
        # may remove. The child's owner cannot unilaterally abandon a delegation.
        parent_kr_owner_id = session.execute(
            select(KeyResult.owner_id).where(KeyResult.id == existing_parent_kr_id)
        ).scalar_one_or_none()

        if not (
            actor.role in (UserRole.ADMIN, UserRole.EXECUTIVE)
            or (parent_kr_owner_id is not None and actor.id == parent_kr_owner_id)
        ):
            raise PermissionError(
                "removing a cascade link requires ADMIN or EXECUTIVE role, "
                "or ownership of the parent key result"
            )
    else:
        # For LADDER: the self-aligner (child objective owner) or ADMIN/EXECUTIVE.
        if not (
            actor.role in (UserRole.ADMIN, UserRole.EXECUTIVE)
            or actor.id == child_objective.owner_id
        ):
            raise PermissionError(
                "removing a ladder link requires ADMIN or EXECUTIVE role, "
                "or ownership of the child objective"
            )

    # Domain write — both fields cleared atomically.
    child_objective.parent_key_result_id = None
    child_objective.alignment_type = None

    _write_audit_log(
        actor, "alignment.remove",
        child_objective, existing_parent_kr_id, existing_alignment_type,
        session,
    )

    session.flush()

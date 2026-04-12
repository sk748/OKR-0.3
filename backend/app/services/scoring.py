"""
Scoring engine for OKRSYNC.

This module is the single writer for Objective.progress, Objective.status,
KeyResult.progress, KeyResult.status, and last_scored_at on both models.
No other code may write to these fields.

TRANSACTION RULE: Functions in this module call session.flush() when they
need to make intermediate state visible, but they NEVER call session.commit().
The caller (route handler, Celery task, or test fixture) is responsible for
committing the transaction.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models import (
    KeyResult,
    Objective,
    OKRCommitmentType,
    StoplightStatus,
    Task,
    TaskStatus,
)

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_ASSESSMENT_MAP: dict[tuple[OKRCommitmentType, StoplightStatus], str] = {
    (OKRCommitmentType.COMMITTED, StoplightStatus.GREEN): "on track for commitment",
    (OKRCommitmentType.COMMITTED, StoplightStatus.YELLOW): "behind on commitment",
    (OKRCommitmentType.COMMITTED, StoplightStatus.RED): "missed commitment",
    (OKRCommitmentType.COMMITTED, StoplightStatus.PENDING): "commitment not yet started",
    (OKRCommitmentType.ASPIRATIONAL, StoplightStatus.GREEN): "strong progress on stretch goal",
    (OKRCommitmentType.ASPIRATIONAL, StoplightStatus.YELLOW): "moderate progress on stretch goal",
    (OKRCommitmentType.ASPIRATIONAL, StoplightStatus.RED): "limited progress on stretch goal",
    (OKRCommitmentType.ASPIRATIONAL, StoplightStatus.PENDING): "stretch goal not yet started",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def _compute_metric_progress(
    start_value: float,
    current_value: float,
    target_value: float,
) -> float:
    """
    Direction-aware signed formula:
        raw = (current - start) / (target - start) * 100

    Works for both increasing targets (start < target) and decreasing
    targets (start > target) because the sign of the denominator flips
    with the direction of intent.

    Returns a float clamped to [0, 150].
    """
    denominator = float(target_value) - float(start_value)
    if denominator == 0:
        return 0.0
    raw = (float(current_value) - float(start_value)) / denominator * 100
    return _clamp(raw, 0.0, 150.0)


def _compute_task_progress(tasks: list[Task]) -> tuple[float, bool]:
    """
    Compute task-driven KR progress from a list of tasks.

    Returns (progress, has_eligible_tasks):
      - Eligible tasks: not CANCELLED and not soft-deleted (deleted_at is None).
      - BLOCKED tasks remain in the denominator (they're in scope, just stuck).
      - progress = sum(done_weight) / sum(eligible_weight) * 100
      - has_eligible_tasks = True if there are any eligible tasks.

    The boolean is needed to distinguish 0% done (RED) from no-data (PENDING).
    """
    eligible = [
        t for t in tasks
        if t.status != TaskStatus.CANCELLED and t.deleted_at is None
    ]
    if not eligible:
        return 0.0, False

    total_weight = sum(float(t.weight) for t in eligible)
    if total_weight == 0:
        return 0.0, False

    done_weight = sum(
        float(t.weight) for t in eligible if t.status == TaskStatus.DONE
    )
    raw = done_weight / total_weight * 100
    return _clamp(raw, 0.0, 150.0), True


# ---------------------------------------------------------------------------
# Pure public functions (no session, no DB writes)
# ---------------------------------------------------------------------------


def score_progress(raw_percent: float) -> StoplightStatus:
    """
    Map a progress percentage to a stoplight color.

    Bands with round-down gap handling:
      0-39   -> RED     (0-30 core, 31-39 gap rounds down)
      40-69  -> YELLOW  (40-60 core, 61-69 gap rounds down)
      70-100 -> GREEN

    The round-down behavior is implicit in the threshold checks:
    39.99 < 40 = RED, 69.99 < 70 = YELLOW.

    Input should be capped at 100 before calling for band purposes;
    values > 100 map to GREEN but the caller should cap explicitly.
    """
    capped = min(raw_percent, 100.0)
    if capped < 40.0:
        return StoplightStatus.RED
    if capped < 70.0:
        return StoplightStatus.YELLOW
    return StoplightStatus.GREEN


def resolve_commitment_type(kr: KeyResult) -> OKRCommitmentType:
    """
    Return the effective commitment type for a KR.
    Uses kr.commitment_type_override if set, else kr.objective.commitment_type.
    Caller must have eagerly loaded kr.objective.
    """
    return kr.commitment_type_override or kr.objective.commitment_type


def compute_kr_progress(kr: KeyResult) -> float:
    """
    Compute raw progress for a KR. Returns a float in [0.0, 150.0].

    Dispatches to metric-driven or task-driven path based on kr.is_task_driven.
    For task-driven KRs, uses kr.tasks (caller should eagerly load).
    For metric-driven KRs, uses kr.start_value/current_value/target_value.
    """
    if kr.is_task_driven:
        progress, _ = _compute_task_progress(list(kr.tasks))
        return progress
    return _compute_metric_progress(kr.start_value, kr.current_value, kr.target_value)


def get_scoring_context(kr: KeyResult) -> dict:
    """
    Build the scoring context dict for a single KR.

    Returns:
        {
            "progress": float,             # raw [0, 150] recomputed
            "status": StoplightStatus,     # stored kr.status
            "commitment_type": OKRCommitmentType,  # resolved
            "assessment": str,             # qualitative string
        }

    progress is recomputed from current values to show overshoot.
    status uses the stored value for consistency with what the frontend displays.
    Caller must have eagerly loaded kr.objective and kr.tasks.
    Does NOT write to the database.
    """
    raw_progress = compute_kr_progress(kr)
    commitment = resolve_commitment_type(kr)
    status = kr.status
    assessment = _ASSESSMENT_MAP.get(
        (commitment, status), "status unavailable"
    )
    return {
        "progress": raw_progress,
        "status": status,
        "commitment_type": commitment,
        "assessment": assessment,
    }


# ---------------------------------------------------------------------------
# Mutation functions (take session, flush but do NOT commit)
# ---------------------------------------------------------------------------


def recompute_key_result(kr: KeyResult, session: Session) -> None:
    """
    Recompute and write kr.progress, kr.status, kr.last_scored_at.

    For task-driven KRs, queries tasks fresh via session (not relationship
    cache) to ensure visibility of uncommitted changes in the current
    transaction.

    Stores min(raw_progress, 100.0) in kr.progress to satisfy the DB
    CHECK constraint (progress >= 0 AND progress <= 100).

    Calls session.flush(). Does NOT commit.
    """
    if kr.is_task_driven:
        stmt = select(Task).where(
            Task.key_result_id == kr.id,
            Task.deleted_at.is_(None),
        )
        tasks = list(session.execute(stmt).scalars())
        raw_progress, has_eligible = _compute_task_progress(tasks)

        if not has_eligible:
            kr.progress = 0.0
            kr.status = StoplightStatus.PENDING
        else:
            kr.progress = min(raw_progress, 100.0)
            kr.status = score_progress(min(raw_progress, 100.0))
    else:
        raw_progress = _compute_metric_progress(
            kr.start_value, kr.current_value, kr.target_value
        )
        stored = min(raw_progress, 100.0)
        kr.progress = stored
        kr.status = score_progress(stored)

    kr.last_scored_at = datetime.now(timezone.utc)
    session.flush()


def recompute_objective(objective: Objective, session: Session) -> None:
    """
    Recompute and write objective.progress, objective.status,
    objective.last_scored_at.

    Equal-weight arithmetic mean of non-deleted KRs' stored progress.
    Zero active KRs -> progress=0, status=PENDING.

    Queries KRs fresh via session for transaction consistency.
    Calls session.flush(). Does NOT commit.
    """
    stmt = select(KeyResult).where(
        KeyResult.objective_id == objective.id,
        KeyResult.deleted_at.is_(None),
    )
    active_krs = list(session.execute(stmt).scalars())

    if not active_krs:
        objective.progress = 0.0
        objective.status = StoplightStatus.PENDING
    else:
        avg = sum(float(kr.progress) for kr in active_krs) / len(active_krs)
        avg = round(avg, 2)
        objective.progress = avg
        objective.status = score_progress(avg)

    objective.last_scored_at = datetime.now(timezone.utc)
    session.flush()


def recompute_on_task_change(task: Task, session: Session) -> None:
    """
    Entry point called by task write handlers. Safe to call unconditionally.

    Behavior:
    1. If task.key_result.is_task_driven AND task.key_result.deleted_at is None:
       recompute the KR, then recompute the parent Objective.
    2. If task.key_result.is_task_driven is False: no-op.
    3. If task.key_result.deleted_at is not None: no-op.

    Idempotent: calling twice with no intervening state change produces
    identical results, because recompute_key_result and recompute_objective
    both recompute from the full current state (not incremental deltas).

    Calls session.flush(). Does NOT commit.
    """
    kr = task.key_result

    if not kr.is_task_driven:
        return
    if kr.deleted_at is not None:
        return

    recompute_key_result(kr, session)
    recompute_objective(kr.objective, session)

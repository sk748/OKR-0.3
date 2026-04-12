"""
Tests for backend.app.services.scoring.

All tests use real model instances against an in-memory SQLite session.
No mocks of models. Fixtures are defined in conftest.py.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from backend.app.models import (
    OKRCommitmentType,
    StoplightStatus,
    TaskStatus,
)
from backend.app.services.scoring import (
    compute_kr_progress,
    get_scoring_context,
    recompute_key_result,
    recompute_objective,
    recompute_on_task_change,
    resolve_commitment_type,
    score_progress,
)
from backend.tests.conftest import (
    make_cycle,
    make_department,
    make_key_result,
    make_objective,
    make_task,
    make_user,
)


# ---------------------------------------------------------------------------
# Helpers to build common fixtures inline
# ---------------------------------------------------------------------------


def _setup_basics(session):
    """Create the minimum shared entities needed for most tests."""
    user = make_user(session)
    cycle = make_cycle(session)
    return user, cycle


# ═══════════════════════════════════════════════════════════════════════════
# score_progress — stoplight band math
# ═══════════════════════════════════════════════════════════════════════════


class TestScoreProgress:
    def test_zero_is_red(self):
        assert score_progress(0) == StoplightStatus.RED

    def test_30_is_red(self):
        assert score_progress(30) == StoplightStatus.RED

    def test_31_rounds_down_to_red(self):
        assert score_progress(31) == StoplightStatus.RED

    def test_39_rounds_down_to_red(self):
        assert score_progress(39) == StoplightStatus.RED

    def test_39_point_99_rounds_down_to_red(self):
        assert score_progress(39.99) == StoplightStatus.RED

    def test_40_is_yellow(self):
        assert score_progress(40) == StoplightStatus.YELLOW

    def test_60_is_yellow(self):
        assert score_progress(60) == StoplightStatus.YELLOW

    def test_61_rounds_down_to_yellow(self):
        assert score_progress(61) == StoplightStatus.YELLOW

    def test_69_rounds_down_to_yellow(self):
        assert score_progress(69) == StoplightStatus.YELLOW

    def test_69_point_99_rounds_down_to_yellow(self):
        assert score_progress(69.99) == StoplightStatus.YELLOW

    def test_70_is_green(self):
        assert score_progress(70) == StoplightStatus.GREEN

    def test_100_is_green(self):
        assert score_progress(100) == StoplightStatus.GREEN


# ═══════════════════════════════════════════════════════════════════════════
# compute_kr_progress — metric-driven
# ═══════════════════════════════════════════════════════════════════════════


class TestComputeKrProgressMetric:
    def test_increasing_target_midpoint(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(
            db_session, objective=obj,
            start_value=0, target_value=100, current_value=50,
        )
        assert compute_kr_progress(kr) == pytest.approx(50.0)

    def test_increasing_target_complete(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(
            db_session, objective=obj,
            start_value=0, target_value=100, current_value=100,
        )
        assert compute_kr_progress(kr) == pytest.approx(100.0)

    def test_decreasing_target_midpoint(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(
            db_session, objective=obj,
            start_value=10, target_value=5, current_value=7.5,
        )
        assert compute_kr_progress(kr) == pytest.approx(50.0)

    def test_decreasing_target_complete(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(
            db_session, objective=obj,
            start_value=10, target_value=5, current_value=5,
        )
        assert compute_kr_progress(kr) == pytest.approx(100.0)

    def test_overshoot_clamped_at_150(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(
            db_session, objective=obj,
            start_value=0, target_value=100, current_value=260,
        )
        assert compute_kr_progress(kr) == pytest.approx(150.0)

    def test_regression_below_start_clamped_at_0(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(
            db_session, objective=obj,
            start_value=0, target_value=100, current_value=-20,
        )
        assert compute_kr_progress(kr) == pytest.approx(0.0)

    def test_no_progress_returns_zero(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(
            db_session, objective=obj,
            start_value=0, target_value=100, current_value=0,
        )
        assert compute_kr_progress(kr) == pytest.approx(0.0)


# ═══════════════════════════════════════════════════════════════════════════
# compute_kr_progress — task-driven
# ═══════════════════════════════════════════════════════════════════════════


class TestComputeKrProgressTaskDriven:
    def test_all_done_is_100(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(db_session, objective=obj, is_task_driven=True)
        make_task(db_session, key_result=kr, status=TaskStatus.DONE)
        make_task(db_session, key_result=kr, status=TaskStatus.DONE)
        db_session.expire(kr, ["tasks"])
        assert compute_kr_progress(kr) == pytest.approx(100.0)

    def test_none_done_is_zero(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(db_session, objective=obj, is_task_driven=True)
        make_task(db_session, key_result=kr, status=TaskStatus.TODO)
        make_task(db_session, key_result=kr, status=TaskStatus.TODO)
        db_session.expire(kr, ["tasks"])
        assert compute_kr_progress(kr) == pytest.approx(0.0)

    def test_partial_with_equal_weights(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(db_session, objective=obj, is_task_driven=True)
        make_task(db_session, key_result=kr, status=TaskStatus.DONE)
        make_task(db_session, key_result=kr, status=TaskStatus.DONE)
        make_task(db_session, key_result=kr, status=TaskStatus.TODO)
        make_task(db_session, key_result=kr, status=TaskStatus.TODO)
        db_session.expire(kr, ["tasks"])
        assert compute_kr_progress(kr) == pytest.approx(50.0)

    def test_cancelled_excluded_from_denominator(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(db_session, objective=obj, is_task_driven=True)
        make_task(db_session, key_result=kr, status=TaskStatus.DONE)
        make_task(db_session, key_result=kr, status=TaskStatus.TODO)
        make_task(db_session, key_result=kr, status=TaskStatus.CANCELLED)
        db_session.expire(kr, ["tasks"])
        # 1 done / 2 eligible (CANCELLED excluded) = 50%
        assert compute_kr_progress(kr) == pytest.approx(50.0)

    def test_soft_deleted_excluded(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(db_session, objective=obj, is_task_driven=True)
        make_task(db_session, key_result=kr, status=TaskStatus.DONE)
        deleted_task = make_task(db_session, key_result=kr, status=TaskStatus.TODO)
        deleted_task.deleted_at = datetime.now(timezone.utc)
        db_session.flush()
        db_session.expire(kr, ["tasks"])
        # 1 done / 1 eligible (deleted excluded) = 100%
        assert compute_kr_progress(kr) == pytest.approx(100.0)

    def test_blocked_stays_in_denominator(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(db_session, objective=obj, is_task_driven=True)
        make_task(db_session, key_result=kr, status=TaskStatus.DONE)
        make_task(db_session, key_result=kr, status=TaskStatus.BLOCKED)
        db_session.expire(kr, ["tasks"])
        # 1 done / 2 eligible = 50%
        assert compute_kr_progress(kr) == pytest.approx(50.0)

    def test_no_eligible_tasks_returns_zero(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(db_session, objective=obj, is_task_driven=True)
        make_task(db_session, key_result=kr, status=TaskStatus.CANCELLED)
        db_session.expire(kr, ["tasks"])
        assert compute_kr_progress(kr) == pytest.approx(0.0)

    def test_mixed_weights(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(db_session, objective=obj, is_task_driven=True)
        make_task(db_session, key_result=kr, status=TaskStatus.DONE, weight=3)
        make_task(db_session, key_result=kr, status=TaskStatus.TODO, weight=1)
        db_session.expire(kr, ["tasks"])
        # 3 / 4 = 75%
        assert compute_kr_progress(kr) == pytest.approx(75.0)


# ═══════════════════════════════════════════════════════════════════════════
# resolve_commitment_type
# ═══════════════════════════════════════════════════════════════════════════


class TestResolveCommitmentType:
    def test_inherits_from_objective_when_no_override(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(
            db_session, owner=user, cycle=cycle,
            commitment_type=OKRCommitmentType.ASPIRATIONAL,
        )
        kr = make_key_result(db_session, objective=obj)
        db_session.expire(kr, ["objective"])
        assert resolve_commitment_type(kr) == OKRCommitmentType.ASPIRATIONAL

    def test_uses_override_when_set(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(
            db_session, owner=user, cycle=cycle,
            commitment_type=OKRCommitmentType.COMMITTED,
        )
        kr = make_key_result(
            db_session, objective=obj,
            commitment_type_override=OKRCommitmentType.ASPIRATIONAL,
        )
        db_session.expire(kr, ["objective"])
        assert resolve_commitment_type(kr) == OKRCommitmentType.ASPIRATIONAL


# ═══════════════════════════════════════════════════════════════════════════
# recompute_key_result — integration with DB session
# ═══════════════════════════════════════════════════════════════════════════


class TestRecomputeKeyResult:
    def test_metric_driven_writes_progress_and_status(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(
            db_session, objective=obj,
            start_value=0, target_value=100, current_value=50,
        )
        recompute_key_result(kr, db_session)
        assert float(kr.progress) == pytest.approx(50.0)
        assert kr.status == StoplightStatus.YELLOW

    def test_metric_driven_caps_at_100_in_db(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(
            db_session, objective=obj,
            start_value=0, target_value=100, current_value=130,
        )
        recompute_key_result(kr, db_session)
        assert float(kr.progress) == pytest.approx(100.0)
        assert kr.status == StoplightStatus.GREEN

    def test_task_driven_writes_progress(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(db_session, objective=obj, is_task_driven=True)
        make_task(db_session, key_result=kr, status=TaskStatus.DONE)
        make_task(db_session, key_result=kr, status=TaskStatus.TODO)
        recompute_key_result(kr, db_session)
        assert float(kr.progress) == pytest.approx(50.0)
        assert kr.status == StoplightStatus.YELLOW

    def test_task_driven_no_eligible_tasks_is_pending(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(db_session, objective=obj, is_task_driven=True)
        make_task(db_session, key_result=kr, status=TaskStatus.CANCELLED)
        recompute_key_result(kr, db_session)
        assert float(kr.progress) == pytest.approx(0.0)
        assert kr.status == StoplightStatus.PENDING

    def test_sets_last_scored_at(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(
            db_session, objective=obj,
            start_value=0, target_value=100, current_value=50,
        )
        assert kr.last_scored_at is None
        recompute_key_result(kr, db_session)
        assert kr.last_scored_at is not None
        assert isinstance(kr.last_scored_at, datetime)


# ═══════════════════════════════════════════════════════════════════════════
# recompute_objective — integration
# ═══════════════════════════════════════════════════════════════════════════


class TestRecomputeObjective:
    def test_averages_kr_progress(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr1 = make_key_result(
            db_session, objective=obj,
            start_value=0, target_value=100, current_value=40,
        )
        kr2 = make_key_result(
            db_session, objective=obj,
            start_value=0, target_value=100, current_value=60,
        )
        kr3 = make_key_result(
            db_session, objective=obj,
            start_value=0, target_value=100, current_value=80,
        )
        recompute_key_result(kr1, db_session)
        recompute_key_result(kr2, db_session)
        recompute_key_result(kr3, db_session)
        recompute_objective(obj, db_session)
        assert float(obj.progress) == pytest.approx(60.0)
        assert obj.status == StoplightStatus.YELLOW

    def test_ignores_deleted_krs(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr1 = make_key_result(
            db_session, objective=obj,
            start_value=0, target_value=100, current_value=80,
        )
        kr2 = make_key_result(
            db_session, objective=obj,
            start_value=0, target_value=100, current_value=20,
        )
        recompute_key_result(kr1, db_session)
        recompute_key_result(kr2, db_session)
        # Soft-delete kr2
        kr2.deleted_at = datetime.now(timezone.utc)
        db_session.flush()
        recompute_objective(obj, db_session)
        # Only kr1 at 80% remains
        assert float(obj.progress) == pytest.approx(80.0)
        assert obj.status == StoplightStatus.GREEN

    def test_zero_active_krs_is_pending(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        recompute_objective(obj, db_session)
        assert float(obj.progress) == pytest.approx(0.0)
        assert obj.status == StoplightStatus.PENDING

    def test_sets_last_scored_at(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        assert obj.last_scored_at is None
        recompute_objective(obj, db_session)
        assert obj.last_scored_at is not None

    def test_status_from_average(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr1 = make_key_result(
            db_session, objective=obj,
            start_value=0, target_value=100, current_value=30,
        )
        kr2 = make_key_result(
            db_session, objective=obj,
            start_value=0, target_value=100, current_value=50,
        )
        recompute_key_result(kr1, db_session)
        recompute_key_result(kr2, db_session)
        recompute_objective(obj, db_session)
        # avg = (30 + 50) / 2 = 40 → YELLOW
        assert float(obj.progress) == pytest.approx(40.0)
        assert obj.status == StoplightStatus.YELLOW


# ═══════════════════════════════════════════════════════════════════════════
# get_scoring_context — assessment strings and overshoot
# ═══════════════════════════════════════════════════════════════════════════


class TestGetScoringContext:
    def _make_kr_with_status(
        self, db_session, commitment_type, status, current_value=50,
    ):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(
            db_session, owner=user, cycle=cycle,
            commitment_type=commitment_type,
        )
        kr = make_key_result(
            db_session, objective=obj,
            start_value=0, target_value=100, current_value=current_value,
            status=status,
        )
        return kr

    def test_committed_green(self, db_session):
        kr = self._make_kr_with_status(
            db_session, OKRCommitmentType.COMMITTED, StoplightStatus.GREEN, 80,
        )
        ctx = get_scoring_context(kr)
        assert ctx["assessment"] == "on track for commitment"
        assert ctx["commitment_type"] == OKRCommitmentType.COMMITTED

    def test_committed_yellow(self, db_session):
        kr = self._make_kr_with_status(
            db_session, OKRCommitmentType.COMMITTED, StoplightStatus.YELLOW, 50,
        )
        ctx = get_scoring_context(kr)
        assert ctx["assessment"] == "behind on commitment"

    def test_committed_red(self, db_session):
        kr = self._make_kr_with_status(
            db_session, OKRCommitmentType.COMMITTED, StoplightStatus.RED, 10,
        )
        ctx = get_scoring_context(kr)
        assert ctx["assessment"] == "missed commitment"

    def test_committed_pending(self, db_session):
        kr = self._make_kr_with_status(
            db_session, OKRCommitmentType.COMMITTED, StoplightStatus.PENDING, 0,
        )
        ctx = get_scoring_context(kr)
        assert ctx["assessment"] == "commitment not yet started"

    def test_aspirational_green(self, db_session):
        kr = self._make_kr_with_status(
            db_session, OKRCommitmentType.ASPIRATIONAL, StoplightStatus.GREEN, 80,
        )
        ctx = get_scoring_context(kr)
        assert ctx["assessment"] == "strong progress on stretch goal"

    def test_aspirational_yellow(self, db_session):
        kr = self._make_kr_with_status(
            db_session, OKRCommitmentType.ASPIRATIONAL, StoplightStatus.YELLOW, 50,
        )
        ctx = get_scoring_context(kr)
        assert ctx["assessment"] == "moderate progress on stretch goal"

    def test_aspirational_red(self, db_session):
        kr = self._make_kr_with_status(
            db_session, OKRCommitmentType.ASPIRATIONAL, StoplightStatus.RED, 10,
        )
        ctx = get_scoring_context(kr)
        assert ctx["assessment"] == "limited progress on stretch goal"

    def test_aspirational_pending(self, db_session):
        kr = self._make_kr_with_status(
            db_session, OKRCommitmentType.ASPIRATIONAL, StoplightStatus.PENDING, 0,
        )
        ctx = get_scoring_context(kr)
        assert ctx["assessment"] == "stretch goal not yet started"

    def test_raw_progress_above_100_for_overshoot(self, db_session):
        kr = self._make_kr_with_status(
            db_session, OKRCommitmentType.COMMITTED, StoplightStatus.GREEN, 130,
        )
        ctx = get_scoring_context(kr)
        assert ctx["progress"] == pytest.approx(130.0)
        assert ctx["status"] == StoplightStatus.GREEN


# ═══════════════════════════════════════════════════════════════════════════
# recompute_on_task_change — chain + edge cases
# ═══════════════════════════════════════════════════════════════════════════


class TestRecomputeOnTaskChange:
    def test_updates_kr_and_objective(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(db_session, objective=obj, is_task_driven=True)
        t1 = make_task(db_session, key_result=kr, status=TaskStatus.DONE)
        make_task(db_session, key_result=kr, status=TaskStatus.TODO)
        recompute_on_task_change(t1, db_session)
        assert float(kr.progress) == pytest.approx(50.0)
        assert kr.status == StoplightStatus.YELLOW
        assert float(obj.progress) == pytest.approx(50.0)
        assert obj.status == StoplightStatus.YELLOW

    def test_noop_for_metric_driven_kr(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(
            db_session, objective=obj, is_task_driven=False,
            start_value=0, target_value=100, current_value=50,
        )
        task = make_task(db_session, key_result=kr, status=TaskStatus.DONE)
        original_progress = float(kr.progress)
        original_status = kr.status
        recompute_on_task_change(task, db_session)
        # No change — metric-driven KR ignores task changes
        assert float(kr.progress) == pytest.approx(original_progress)
        assert kr.status == original_status

    def test_noop_for_soft_deleted_kr(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(db_session, objective=obj, is_task_driven=True)
        task = make_task(db_session, key_result=kr, status=TaskStatus.DONE)
        kr.deleted_at = datetime.now(timezone.utc)
        db_session.flush()
        original_progress = float(kr.progress)
        recompute_on_task_change(task, db_session)
        assert float(kr.progress) == pytest.approx(original_progress)

    def test_idempotent(self, db_session):
        user, cycle = _setup_basics(db_session)
        obj = make_objective(db_session, owner=user, cycle=cycle)
        kr = make_key_result(db_session, objective=obj, is_task_driven=True)
        t1 = make_task(db_session, key_result=kr, status=TaskStatus.DONE)
        make_task(db_session, key_result=kr, status=TaskStatus.TODO)

        recompute_on_task_change(t1, db_session)
        progress_1 = float(kr.progress)
        status_1 = kr.status
        obj_progress_1 = float(obj.progress)
        obj_status_1 = obj.status

        recompute_on_task_change(t1, db_session)
        assert float(kr.progress) == pytest.approx(progress_1)
        assert kr.status == status_1
        assert float(obj.progress) == pytest.approx(obj_progress_1)
        assert obj.status == obj_status_1

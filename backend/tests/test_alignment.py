"""
Tests for backend.app.services.alignment.

All tests use real model instances against an in-memory SQLite session.
No mocks of models. Fixtures from conftest.py.

Setup for remove_alignment tests: alignment fields are written directly
on the Objective (bypassing the service) so that audit rows from setup
don't interfere with the single audit row being verified.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from backend.app.models import (
    AlignmentType,
    AuditLog,
    KeyResult,
    OKRLevel,
    UserRole,
)
from backend.app.services.alignment import (
    AlignmentError,
    create_cascade_link,
    create_ladder_link,
    remove_alignment,
)
from backend.tests.conftest import (
    make_cycle,
    make_key_result,
    make_objective,
    make_user,
)


# ---------------------------------------------------------------------------
# Shared setup helpers
# ---------------------------------------------------------------------------


def _basics(session):
    """Return (user, cycle) — the minimum shared entities."""
    user = make_user(session)
    cycle = make_cycle(session)
    return user, cycle


def _admin(session, cycle=None):
    return make_user(session, role=UserRole.ADMIN)


def _executive(session):
    return make_user(session, role=UserRole.EXECUTIVE)


def _employee(session):
    return make_user(session, role=UserRole.EMPLOYEE)


# ═══════════════════════════════════════════════════════════════════════════
# TestCreateCascadeLink
# ═══════════════════════════════════════════════════════════════════════════


class TestCreateCascadeLink:
    def _setup(self, session):
        """Create owner, cycle, parent objective + KR, unlinked child objective."""
        owner = make_user(session, role=UserRole.EMPLOYEE)
        cycle = make_cycle(session)
        parent_obj = make_objective(session, owner=owner, cycle=cycle, level=OKRLevel.COMPANY)
        parent_kr = make_key_result(session, objective=parent_obj, owner=owner)
        child_obj = make_objective(session, owner=owner, cycle=cycle, level=OKRLevel.TEAM)
        return owner, cycle, parent_obj, parent_kr, child_obj

    def test_cascade_creates_link_fields_correctly(self, db_session):
        owner, _, _, parent_kr, child_obj = self._setup(db_session)
        admin = _admin(db_session)
        create_cascade_link(parent_kr, child_obj, admin, db_session)
        assert child_obj.parent_key_result_id == parent_kr.id

    def test_cascade_alignment_type_is_cascade(self, db_session):
        owner, _, _, parent_kr, child_obj = self._setup(db_session)
        admin = _admin(db_session)
        create_cascade_link(parent_kr, child_obj, admin, db_session)
        assert child_obj.alignment_type == AlignmentType.CASCADE

    def test_cascade_writes_audit_log_with_correct_fields(self, db_session):
        owner, _, _, parent_kr, child_obj = self._setup(db_session)
        admin = _admin(db_session)
        create_cascade_link(parent_kr, child_obj, admin, db_session)
        logs = list(db_session.execute(select(AuditLog)).scalars())
        assert len(logs) == 1
        log = logs[0]
        assert log.actor_id == admin.id
        assert log.target_type == "objective"
        assert log.target_id == child_obj.id
        assert log.details["parent_kr_id"] == str(parent_kr.id)
        assert log.details["child_objective_id"] == str(child_obj.id)
        assert log.details["alignment_type"] == "cascade"

    def test_cascade_audit_action_is_create_cascade(self, db_session):
        owner, _, _, parent_kr, child_obj = self._setup(db_session)
        admin = _admin(db_session)
        create_cascade_link(parent_kr, child_obj, admin, db_session)
        log = db_session.execute(select(AuditLog)).scalar_one()
        assert log.action == "alignment.create_cascade"

    def test_cascade_allows_admin(self, db_session):
        _, _, _, parent_kr, child_obj = self._setup(db_session)
        admin = make_user(db_session, role=UserRole.ADMIN)
        create_cascade_link(parent_kr, child_obj, admin, db_session)  # must not raise
        assert child_obj.alignment_type == AlignmentType.CASCADE

    def test_cascade_allows_executive(self, db_session):
        _, _, _, parent_kr, child_obj = self._setup(db_session)
        exec_user = make_user(db_session, role=UserRole.EXECUTIVE)
        create_cascade_link(parent_kr, child_obj, exec_user, db_session)
        assert child_obj.alignment_type == AlignmentType.CASCADE

    def test_cascade_allows_parent_kr_owner(self, db_session):
        owner, _, _, parent_kr, child_obj = self._setup(db_session)
        # owner is an EMPLOYEE but owns the parent KR
        create_cascade_link(parent_kr, child_obj, owner, db_session)
        assert child_obj.alignment_type == AlignmentType.CASCADE

    def test_cascade_denies_non_owner_employee(self, db_session):
        _, _, _, parent_kr, child_obj = self._setup(db_session)
        other_employee = make_user(db_session, role=UserRole.EMPLOYEE)
        with pytest.raises(PermissionError):
            create_cascade_link(parent_kr, child_obj, other_employee, db_session)

    def test_cascade_denies_partner(self, db_session):
        _, _, _, parent_kr, child_obj = self._setup(db_session)
        partner = make_user(db_session, role=UserRole.PARTNER)
        with pytest.raises(PermissionError):
            create_cascade_link(parent_kr, child_obj, partner, db_session)

    def test_cascade_fails_if_already_aligned(self, db_session):
        owner, _, parent_obj, parent_kr, child_obj = self._setup(db_session)
        # Pre-align child_obj to some other KR
        other_kr = make_key_result(db_session, objective=parent_obj, owner=owner)
        child_obj.parent_key_result_id = other_kr.id
        child_obj.alignment_type = AlignmentType.CASCADE
        db_session.flush()
        admin = _admin(db_session)
        with pytest.raises(AlignmentError, match="already aligned"):
            create_cascade_link(parent_kr, child_obj, admin, db_session)

    def test_cascade_fails_if_child_soft_deleted(self, db_session):
        _, _, _, parent_kr, child_obj = self._setup(db_session)
        child_obj.deleted_at = datetime.now(timezone.utc)
        db_session.flush()
        admin = _admin(db_session)
        with pytest.raises(AlignmentError, match="soft-deleted"):
            create_cascade_link(parent_kr, child_obj, admin, db_session)

    def test_cascade_fails_if_parent_kr_soft_deleted(self, db_session):
        _, _, _, parent_kr, child_obj = self._setup(db_session)
        parent_kr.deleted_at = datetime.now(timezone.utc)
        db_session.flush()
        admin = _admin(db_session)
        with pytest.raises(AlignmentError, match="soft-deleted"):
            create_cascade_link(parent_kr, child_obj, admin, db_session)


# ═══════════════════════════════════════════════════════════════════════════
# TestCreateLadderLink
# ═══════════════════════════════════════════════════════════════════════════


class TestCreateLadderLink:
    def _setup(self, session):
        owner = make_user(session, role=UserRole.EMPLOYEE)
        cycle = make_cycle(session)
        parent_obj = make_objective(session, owner=owner, cycle=cycle, level=OKRLevel.COMPANY)
        parent_kr = make_key_result(session, objective=parent_obj, owner=owner)
        child_obj = make_objective(session, owner=owner, cycle=cycle, level=OKRLevel.TEAM)
        return owner, cycle, parent_obj, parent_kr, child_obj

    def test_ladder_creates_link_fields_correctly(self, db_session):
        owner, _, _, parent_kr, child_obj = self._setup(db_session)
        create_ladder_link(parent_kr, child_obj, owner, db_session)
        assert child_obj.parent_key_result_id == parent_kr.id

    def test_ladder_alignment_type_is_ladder(self, db_session):
        owner, _, _, parent_kr, child_obj = self._setup(db_session)
        create_ladder_link(parent_kr, child_obj, owner, db_session)
        assert child_obj.alignment_type == AlignmentType.LADDER

    def test_ladder_writes_audit_log_with_correct_fields(self, db_session):
        owner, _, _, parent_kr, child_obj = self._setup(db_session)
        create_ladder_link(parent_kr, child_obj, owner, db_session)
        logs = list(db_session.execute(select(AuditLog)).scalars())
        assert len(logs) == 1
        log = logs[0]
        assert log.actor_id == owner.id
        assert log.target_id == child_obj.id
        assert log.details["alignment_type"] == "ladder"

    def test_ladder_audit_action_is_create_ladder(self, db_session):
        owner, _, _, parent_kr, child_obj = self._setup(db_session)
        create_ladder_link(parent_kr, child_obj, owner, db_session)
        log = db_session.execute(select(AuditLog)).scalar_one()
        assert log.action == "alignment.create_ladder"

    def test_ladder_allows_child_objective_owner(self, db_session):
        owner, _, _, parent_kr, child_obj = self._setup(db_session)
        create_ladder_link(parent_kr, child_obj, owner, db_session)
        assert child_obj.alignment_type == AlignmentType.LADDER

    def test_ladder_allows_admin(self, db_session):
        _, _, _, parent_kr, child_obj = self._setup(db_session)
        admin = make_user(db_session, role=UserRole.ADMIN)
        create_ladder_link(parent_kr, child_obj, admin, db_session)
        assert child_obj.alignment_type == AlignmentType.LADDER

    def test_ladder_denies_executive(self, db_session):
        """EXECUTIVE may cascade but may NOT ladder — that is self-service only."""
        _, _, _, parent_kr, child_obj = self._setup(db_session)
        exec_user = make_user(db_session, role=UserRole.EXECUTIVE)
        with pytest.raises(PermissionError):
            create_ladder_link(parent_kr, child_obj, exec_user, db_session)

    def test_ladder_denies_non_owner_employee(self, db_session):
        _, _, _, parent_kr, child_obj = self._setup(db_session)
        other = make_user(db_session, role=UserRole.EMPLOYEE)
        with pytest.raises(PermissionError):
            create_ladder_link(parent_kr, child_obj, other, db_session)

    def test_ladder_fails_if_already_aligned(self, db_session):
        owner, _, parent_obj, parent_kr, child_obj = self._setup(db_session)
        other_kr = make_key_result(db_session, objective=parent_obj, owner=owner)
        child_obj.parent_key_result_id = other_kr.id
        child_obj.alignment_type = AlignmentType.LADDER
        db_session.flush()
        with pytest.raises(AlignmentError, match="already aligned"):
            create_ladder_link(parent_kr, child_obj, owner, db_session)

    def test_ladder_fails_if_child_soft_deleted(self, db_session):
        owner, _, _, parent_kr, child_obj = self._setup(db_session)
        child_obj.deleted_at = datetime.now(timezone.utc)
        db_session.flush()
        with pytest.raises(AlignmentError, match="soft-deleted"):
            create_ladder_link(parent_kr, child_obj, owner, db_session)

    def test_ladder_fails_if_parent_kr_soft_deleted(self, db_session):
        owner, _, _, parent_kr, child_obj = self._setup(db_session)
        parent_kr.deleted_at = datetime.now(timezone.utc)
        db_session.flush()
        with pytest.raises(AlignmentError, match="soft-deleted"):
            create_ladder_link(parent_kr, child_obj, owner, db_session)


# ═══════════════════════════════════════════════════════════════════════════
# TestRemoveAlignment
# ═══════════════════════════════════════════════════════════════════════════


class TestRemoveAlignment:
    """
    Setup uses direct field writes (bypassing the service) so that audit rows
    created during setup don't pollute the assertion on the single remove audit row.
    """

    def _setup_cascade(self, session):
        """Return (kr_owner, kr, child_obj, other_employee)."""
        kr_owner = make_user(session, role=UserRole.EMPLOYEE)
        cycle = make_cycle(session)
        parent_obj = make_objective(session, owner=kr_owner, cycle=cycle, level=OKRLevel.COMPANY)
        parent_kr = make_key_result(session, objective=parent_obj, owner=kr_owner)
        child_owner = make_user(session, role=UserRole.EMPLOYEE)
        child_obj = make_objective(session, owner=child_owner, cycle=cycle, level=OKRLevel.TEAM)
        # Direct write to set up the alignment without using the service.
        child_obj.parent_key_result_id = parent_kr.id
        child_obj.alignment_type = AlignmentType.CASCADE
        session.flush()
        return kr_owner, parent_kr, child_owner, child_obj

    def _setup_ladder(self, session):
        """Return (parent_kr_owner, parent_kr, child_owner, child_obj)."""
        parent_kr_owner = make_user(session, role=UserRole.EMPLOYEE)
        cycle = make_cycle(session)
        parent_obj = make_objective(session, owner=parent_kr_owner, cycle=cycle, level=OKRLevel.COMPANY)
        parent_kr = make_key_result(session, objective=parent_obj, owner=parent_kr_owner)
        child_owner = make_user(session, role=UserRole.EMPLOYEE)
        child_obj = make_objective(session, owner=child_owner, cycle=cycle, level=OKRLevel.TEAM)
        child_obj.parent_key_result_id = parent_kr.id
        child_obj.alignment_type = AlignmentType.LADDER
        session.flush()
        return parent_kr_owner, parent_kr, child_owner, child_obj

    def test_remove_cascade_clears_parent_key_result_id(self, db_session):
        kr_owner, parent_kr, _, child_obj = self._setup_cascade(db_session)
        remove_alignment(child_obj, kr_owner, db_session)
        assert child_obj.parent_key_result_id is None

    def test_remove_cascade_clears_alignment_type(self, db_session):
        kr_owner, parent_kr, _, child_obj = self._setup_cascade(db_session)
        remove_alignment(child_obj, kr_owner, db_session)
        assert child_obj.alignment_type is None

    def test_remove_cascade_writes_audit_log(self, db_session):
        kr_owner, parent_kr, _, child_obj = self._setup_cascade(db_session)
        original_parent_kr_id = parent_kr.id
        remove_alignment(child_obj, kr_owner, db_session)
        logs = list(db_session.execute(select(AuditLog)).scalars())
        assert len(logs) == 1
        log = logs[0]
        assert log.action == "alignment.remove"
        assert log.actor_id == kr_owner.id
        assert log.target_id == child_obj.id
        assert log.details["alignment_type"] == "cascade"
        assert log.details["parent_kr_id"] == str(original_parent_kr_id)

    def test_remove_cascade_allows_admin(self, db_session):
        _, _, _, child_obj = self._setup_cascade(db_session)
        admin = make_user(db_session, role=UserRole.ADMIN)
        remove_alignment(child_obj, admin, db_session)
        assert child_obj.parent_key_result_id is None

    def test_remove_cascade_allows_executive(self, db_session):
        _, _, _, child_obj = self._setup_cascade(db_session)
        exec_user = make_user(db_session, role=UserRole.EXECUTIVE)
        remove_alignment(child_obj, exec_user, db_session)
        assert child_obj.parent_key_result_id is None

    def test_remove_cascade_allows_parent_kr_owner(self, db_session):
        kr_owner, _, _, child_obj = self._setup_cascade(db_session)
        remove_alignment(child_obj, kr_owner, db_session)
        assert child_obj.parent_key_result_id is None

    def test_remove_cascade_denies_child_objective_owner(self, db_session):
        """The delegatee cannot unilaterally abandon a cascaded objective."""
        _, _, child_owner, child_obj = self._setup_cascade(db_session)
        with pytest.raises(PermissionError):
            remove_alignment(child_obj, child_owner, db_session)

    def test_remove_ladder_clears_both_fields(self, db_session):
        _, _, child_owner, child_obj = self._setup_ladder(db_session)
        remove_alignment(child_obj, child_owner, db_session)
        assert child_obj.parent_key_result_id is None
        assert child_obj.alignment_type is None

    def test_remove_ladder_writes_audit_log(self, db_session):
        _, parent_kr, child_owner, child_obj = self._setup_ladder(db_session)
        remove_alignment(child_obj, child_owner, db_session)
        log = db_session.execute(select(AuditLog)).scalar_one()
        assert log.action == "alignment.remove"
        assert log.details["alignment_type"] == "ladder"

    def test_remove_ladder_allows_admin(self, db_session):
        _, _, _, child_obj = self._setup_ladder(db_session)
        admin = make_user(db_session, role=UserRole.ADMIN)
        remove_alignment(child_obj, admin, db_session)
        assert child_obj.parent_key_result_id is None

    def test_remove_ladder_allows_executive(self, db_session):
        _, _, _, child_obj = self._setup_ladder(db_session)
        exec_user = make_user(db_session, role=UserRole.EXECUTIVE)
        remove_alignment(child_obj, exec_user, db_session)
        assert child_obj.parent_key_result_id is None

    def test_remove_ladder_allows_child_objective_owner(self, db_session):
        _, _, child_owner, child_obj = self._setup_ladder(db_session)
        remove_alignment(child_obj, child_owner, db_session)
        assert child_obj.parent_key_result_id is None

    def test_remove_ladder_denies_parent_kr_owner_alone(self, db_session):
        """The KR owner who was laddered-up-to cannot unilaterally remove a ladder."""
        parent_kr_owner, _, _, child_obj = self._setup_ladder(db_session)
        with pytest.raises(PermissionError):
            remove_alignment(child_obj, parent_kr_owner, db_session)

    def test_remove_fails_if_no_alignment_exists(self, db_session):
        user = make_user(db_session)
        cycle = make_cycle(db_session)
        unaligned_obj = make_objective(db_session, owner=user, cycle=cycle)
        admin = make_user(db_session, role=UserRole.ADMIN)
        with pytest.raises(AlignmentError, match="no alignment"):
            remove_alignment(unaligned_obj, admin, db_session)


# ═══════════════════════════════════════════════════════════════════════════
# TestCycleDetection
# ═══════════════════════════════════════════════════════════════════════════


class TestCycleDetection:
    """
    Chains are assembled by direct field writes to avoid service call overhead
    in setup. The cycle-detection logic is exercised by calling the service.
    """

    def _make_chain(self, session, depth: int):
        """
        Build a linear alignment chain of `depth` objectives.
        Returns (objectives_list, krs_list) each of length `depth`.

        Chain: obj[0] -> kr[0] -> obj[1] -> kr[1] -> ... -> obj[depth-1]
        Each obj[i+1].parent_key_result_id = kr[i].id
        """
        user = make_user(session, role=UserRole.ADMIN)
        cycle = make_cycle(session)
        objs = []
        krs = []
        for i in range(depth):
            level = OKRLevel.COMPANY if i == 0 else OKRLevel.TEAM
            obj = make_objective(session, owner=user, cycle=cycle, level=level)
            kr = make_key_result(session, objective=obj, owner=user)
            if i > 0:
                obj.parent_key_result_id = krs[i - 1].id
                obj.alignment_type = AlignmentType.CASCADE
            objs.append(obj)
            krs.append(kr)
        session.flush()
        return objs, krs

    def test_direct_cycle_prevented(self, db_session):
        """KR on objective A cannot become the parent of objective A itself."""
        objs, krs = self._make_chain(db_session, depth=1)
        obj_a, kr_a = objs[0], krs[0]
        admin = make_user(db_session, role=UserRole.ADMIN)
        with pytest.raises(AlignmentError, match="cycle"):
            create_cascade_link(kr_a, obj_a, admin, db_session)

    def test_two_hop_cycle_prevented(self, db_session):
        """Chain: A→kr_a→B→kr_b. kr_b cannot become parent of A."""
        objs, krs = self._make_chain(db_session, depth=2)
        obj_a, obj_b = objs[0], objs[1]
        kr_b = krs[1]
        admin = make_user(db_session, role=UserRole.ADMIN)
        with pytest.raises(AlignmentError, match="cycle"):
            create_cascade_link(kr_b, obj_a, admin, db_session)

    def test_three_hop_cycle_prevented(self, db_session):
        """Chain: A→B→C→D. kr_d cannot become parent of A."""
        objs, krs = self._make_chain(db_session, depth=4)
        obj_a = objs[0]
        kr_d = krs[3]
        admin = make_user(db_session, role=UserRole.ADMIN)
        with pytest.raises(AlignmentError, match="cycle"):
            create_cascade_link(kr_d, obj_a, admin, db_session)

    def test_no_false_positive_independent_chains(self, db_session):
        """
        Chain 1: obj_a → kr_a → obj_b
        Chain 2: obj_c → kr_c (top-level, unlinked)
        Linking kr_c → obj_a (top of chain 1) should succeed — no cycle.
        """
        user = make_user(db_session, role=UserRole.ADMIN)
        cycle = make_cycle(db_session)
        # Chain 1
        obj_a = make_objective(db_session, owner=user, cycle=cycle, level=OKRLevel.COMPANY)
        kr_a = make_key_result(db_session, objective=obj_a, owner=user)
        obj_b = make_objective(db_session, owner=user, cycle=cycle, level=OKRLevel.TEAM)
        obj_b.parent_key_result_id = kr_a.id
        obj_b.alignment_type = AlignmentType.CASCADE
        # Chain 2 (independent)
        obj_c = make_objective(db_session, owner=user, cycle=cycle, level=OKRLevel.DEPARTMENT)
        kr_c = make_key_result(db_session, objective=obj_c, owner=user)
        db_session.flush()
        # obj_a is unaligned (top-level) — linking kr_c → obj_a is valid.
        create_cascade_link(kr_c, obj_a, user, db_session)
        assert obj_a.parent_key_result_id == kr_c.id

    def test_no_false_positive_sibling_krs_on_same_objective(self, db_session):
        """
        obj_a has kr_a1 and kr_a2. obj_b is already a child of kr_a1.
        Linking kr_a2 → a new unlinked obj_c should succeed.
        """
        user = make_user(db_session, role=UserRole.ADMIN)
        cycle = make_cycle(db_session)
        obj_a = make_objective(db_session, owner=user, cycle=cycle, level=OKRLevel.COMPANY)
        kr_a1 = make_key_result(db_session, objective=obj_a, owner=user)
        kr_a2 = make_key_result(db_session, objective=obj_a, owner=user)
        obj_b = make_objective(db_session, owner=user, cycle=cycle, level=OKRLevel.TEAM)
        obj_b.parent_key_result_id = kr_a1.id
        obj_b.alignment_type = AlignmentType.CASCADE
        obj_c = make_objective(db_session, owner=user, cycle=cycle, level=OKRLevel.TEAM)
        db_session.flush()
        # Linking kr_a2 → obj_c: walk above kr_a2 is obj_a (no parent) → no cycle.
        create_cascade_link(kr_a2, obj_c, user, db_session)
        assert obj_c.parent_key_result_id == kr_a2.id

    def test_exceeding_max_depth_raises_alignment_error(self, db_session, monkeypatch):
        """
        With _MAX_DEPTH patched to 3, a 4-level chain exhausts the loop and
        raises AlignmentError instead of returning a result.
        """
        import backend.app.services.alignment as alignment_module
        monkeypatch.setattr(alignment_module, "_MAX_DEPTH", 3)

        user = make_user(db_session, role=UserRole.ADMIN)
        cycle = make_cycle(db_session)

        # Build: obj_a → kr_a → obj_b → kr_b → obj_c → kr_c → obj_d → kr_d
        # Chain depth from kr_d upward: obj_d, obj_c, obj_b, obj_a = 4 levels
        obj_a = make_objective(db_session, owner=user, cycle=cycle, level=OKRLevel.COMPANY)
        kr_a = make_key_result(db_session, objective=obj_a, owner=user)
        obj_b = make_objective(db_session, owner=user, cycle=cycle, level=OKRLevel.DEPARTMENT)
        obj_b.parent_key_result_id = kr_a.id
        obj_b.alignment_type = AlignmentType.CASCADE
        db_session.flush()
        kr_b = make_key_result(db_session, objective=obj_b, owner=user)
        obj_c = make_objective(db_session, owner=user, cycle=cycle, level=OKRLevel.TEAM)
        obj_c.parent_key_result_id = kr_b.id
        obj_c.alignment_type = AlignmentType.CASCADE
        db_session.flush()
        kr_c = make_key_result(db_session, objective=obj_c, owner=user)
        obj_d = make_objective(db_session, owner=user, cycle=cycle, level=OKRLevel.INDIVIDUAL)
        obj_d.parent_key_result_id = kr_c.id
        obj_d.alignment_type = AlignmentType.CASCADE
        db_session.flush()
        kr_d = make_key_result(db_session, objective=obj_d, owner=user)

        # A fresh unaligned objective — no cycle would exist if depth weren't an issue.
        obj_e = make_objective(db_session, owner=user, cycle=cycle, level=OKRLevel.INDIVIDUAL)
        db_session.flush()

        # Walking above kr_d: obj_d → obj_c → obj_b → (would reach obj_a but loop ends)
        with pytest.raises(AlignmentError, match="maximum depth"):
            create_cascade_link(kr_d, obj_e, user, db_session)


# ═══════════════════════════════════════════════════════════════════════════
# TestSchemaInvariants
# ═══════════════════════════════════════════════════════════════════════════


class TestSchemaInvariants:
    def test_create_sets_both_fields_atomically(self, db_session):
        """After create_cascade_link, both fields are non-null together."""
        user = make_user(db_session)
        cycle = make_cycle(db_session)
        parent_obj = make_objective(db_session, owner=user, cycle=cycle)
        parent_kr = make_key_result(db_session, objective=parent_obj)
        child_obj = make_objective(db_session, owner=user, cycle=cycle)
        admin = make_user(db_session, role=UserRole.ADMIN)
        create_cascade_link(parent_kr, child_obj, admin, db_session)
        # Both must be non-null.
        assert child_obj.parent_key_result_id is not None
        assert child_obj.alignment_type is not None
        # And they must be consistent with each other.
        assert child_obj.parent_key_result_id == parent_kr.id
        assert child_obj.alignment_type == AlignmentType.CASCADE

    def test_remove_clears_both_fields_atomically(self, db_session):
        """After remove_alignment, both fields are null together."""
        user = make_user(db_session)
        cycle = make_cycle(db_session)
        parent_obj = make_objective(db_session, owner=user, cycle=cycle)
        parent_kr = make_key_result(db_session, objective=parent_obj)
        child_obj = make_objective(db_session, owner=user, cycle=cycle)
        child_obj.parent_key_result_id = parent_kr.id
        child_obj.alignment_type = AlignmentType.CASCADE
        db_session.flush()
        admin = make_user(db_session, role=UserRole.ADMIN)
        remove_alignment(child_obj, admin, db_session)
        assert child_obj.parent_key_result_id is None
        assert child_obj.alignment_type is None

    def test_remove_stores_audit_with_pre_removal_values(self, db_session):
        """
        The audit row written by remove_alignment must capture the values that
        existed BEFORE the fields were cleared — not the post-clear nulls.
        """
        user = make_user(db_session)
        cycle = make_cycle(db_session)
        parent_obj = make_objective(db_session, owner=user, cycle=cycle)
        parent_kr = make_key_result(db_session, objective=parent_obj)
        child_obj = make_objective(db_session, owner=user, cycle=cycle)
        child_obj.parent_key_result_id = parent_kr.id
        child_obj.alignment_type = AlignmentType.LADDER
        db_session.flush()
        admin = make_user(db_session, role=UserRole.ADMIN)
        remove_alignment(child_obj, admin, db_session)
        log = db_session.execute(select(AuditLog)).scalar_one()
        # Audit captured the pre-clear values.
        assert log.details["parent_kr_id"] == str(parent_kr.id)
        assert log.details["alignment_type"] == "ladder"
        # Object fields are now null.
        assert child_obj.parent_key_result_id is None
        assert child_obj.alignment_type is None

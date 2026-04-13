"""
Tests for backend.app.services.rbac.

All tests use real model instances against an in-memory SQLite session.
No mocks. Fixtures from conftest.py.

Structure:
  TestScopedObjectivesQuery   — 14 tests
  TestScopedKeyResultsQuery   — 6 tests
  TestScopedTasksQuery        — 9 tests
  TestScopedChatQuery         — 9 tests (includes TIGHTENING 2 partner tests)
  TestCanViewPredicates       — 14 tests
  TestCanModifyPredicates     — 16 tests (includes TIGHTENING 1 KR tests)
  TestRequireRole             — 5 tests
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from backend.app.models import (
    AuditLog,
    ChatMessage,
    OKRLevel,
    RoleOnTeam,
    Task,
    TaskStatus,
    UserRole,
)
from backend.app.services.rbac import (
    can_modify_key_result,
    can_modify_objective,
    can_modify_task,
    can_view_key_result,
    can_view_objective,
    can_view_task,
    require_role,
    scoped_chat_query,
    scoped_key_results_query,
    scoped_objectives_query,
    scoped_tasks_query,
)
from backend.tests.conftest import (
    make_c_suite_user,
    make_cycle,
    make_department,
    make_key_result,
    make_objective,
    make_project_member,
    make_project_team,
    make_task,
    make_user,
)


# ---------------------------------------------------------------------------
# Local factory helpers
# ---------------------------------------------------------------------------


def make_chat_message(
    session,
    *,
    context_type: str,
    context_id: uuid.UUID,
    sender,
    raw_text: str = "hello",
) -> ChatMessage:
    """Create and flush a ChatMessage for the given context."""
    msg = ChatMessage(
        id=uuid.uuid4(),
        context_type=context_type,
        context_id=context_id,
        sender_id=sender.id,
        raw_text=raw_text,
        scrubbed_text=raw_text,
    )
    session.add(msg)
    session.flush()
    return msg


def make_external_task(session, *, key_result, assignee=None, **overrides):
    """Create an external task with a required sanitized_title."""
    return make_task(
        session,
        key_result=key_result,
        assignee=assignee,
        is_external=True,
        sanitized_title=overrides.pop("sanitized_title", "External Task"),
        **overrides,
    )


# ═══════════════════════════════════════════════════════════════════════════
# TestScopedObjectivesQuery
# ═══════════════════════════════════════════════════════════════════════════


class TestScopedObjectivesQuery:
    def _setup(self, session):
        dept = make_department(session)
        owner = make_user(session, department=dept)
        cycle = make_cycle(session)
        obj = make_objective(
            session, owner=owner, cycle=cycle, department_id=dept.id
        )
        return owner, cycle, dept, obj

    def test_admin_sees_all_objectives(self, db_session):
        owner, _, _, obj = self._setup(db_session)
        admin = make_user(db_session, role=UserRole.ADMIN)
        q = scoped_objectives_query(admin, db_session)
        results = list(db_session.execute(q).scalars())
        assert obj in results

    def test_c_suite_executive_sees_all_objectives(self, db_session):
        """is_c_suite executive sees all objectives regardless of dept."""
        owner, _, _, obj = self._setup(db_session)
        exec_user = make_c_suite_user(db_session, role=UserRole.EXECUTIVE)
        q = scoped_objectives_query(exec_user, db_session)
        results = list(db_session.execute(q).scalars())
        assert obj in results

    def test_c_suite_compliance_sees_all(self, db_session):
        """is_c_suite=True with EMPLOYEE role still sees everything."""
        owner, _, _, obj = self._setup(db_session)
        compliance = make_c_suite_user(db_session, role=UserRole.EMPLOYEE)
        q = scoped_objectives_query(compliance, db_session)
        results = list(db_session.execute(q).scalars())
        assert obj in results

    def test_employee_sees_own_objectives(self, db_session):
        owner, _, _, obj = self._setup(db_session)
        q = scoped_objectives_query(owner, db_session)
        results = list(db_session.execute(q).scalars())
        assert obj in results

    def test_employee_excludes_other_dept_objectives(self, db_session):
        """Employee in dept B cannot see objective in dept A (no project link)."""
        owner, _, dept, obj = self._setup(db_session)
        other_dept = make_department(db_session, name="Other Dept", slug="other-dept")
        outsider = make_user(db_session, department=other_dept)
        q = scoped_objectives_query(outsider, db_session)
        results = list(db_session.execute(q).scalars())
        assert obj not in results

    def test_employee_no_dept_sees_only_owned(self, db_session):
        owner, _, dept, obj = self._setup(db_session)
        no_dept_user = make_user(db_session)  # no department
        q = scoped_objectives_query(no_dept_user, db_session)
        results = list(db_session.execute(q).scalars())
        assert obj not in results

    def test_partner_raises_permission_error(self, db_session):
        partner = make_user(db_session, role=UserRole.PARTNER)
        with pytest.raises(PermissionError):
            scoped_objectives_query(partner, db_session)

    def test_partner_writes_audit_log_on_objectives_query(self, db_session):
        partner = make_user(db_session, role=UserRole.PARTNER)
        with pytest.raises(PermissionError):
            scoped_objectives_query(partner, db_session)
        logs = list(db_session.execute(select(AuditLog)).scalars())
        assert len(logs) == 1
        assert logs[0].action == "rbac.denied.objectives_query"
        assert logs[0].actor_id == partner.id

    # --- Phase 2.4 new tests ---

    def test_department_head_sees_dept_objectives(self, db_session):
        """Non-c_suite EXECUTIVE with dept_id sees objectives in their dept."""
        owner, cycle, dept, obj = self._setup(db_session)
        exec_user = make_user(db_session, role=UserRole.EXECUTIVE, department=dept)
        q = scoped_objectives_query(exec_user, db_session)
        results = list(db_session.execute(q).scalars())
        assert obj in results

    def test_department_head_cannot_see_other_dept_objectives(self, db_session):
        """Non-c_suite EXECUTIVE cannot see objectives from a different dept."""
        owner, cycle, dept, obj = self._setup(db_session)
        other_dept = make_department(db_session, name="Other", slug="exec-other")
        exec_user = make_user(db_session, role=UserRole.EXECUTIVE, department=other_dept)
        q = scoped_objectives_query(exec_user, db_session)
        results = list(db_session.execute(q).scalars())
        assert obj not in results

    def test_department_head_sees_participating_project_objectives(self, db_session):
        """EXECUTIVE sees objective on project where their dept is a participant."""
        exec_dept = make_department(db_session, name="Exec Dept", slug="exec-pt")
        other_dept = make_department(db_session, name="Other Dept", slug="other-pt")
        exec_user = make_user(db_session, role=UserRole.EXECUTIVE, department=exec_dept)
        owner = make_user(db_session, department=other_dept)
        cycle = make_cycle(db_session)
        pt = make_project_team(
            db_session,
            primary_department=other_dept,
            participating_departments=[exec_dept],
        )
        obj = make_objective(
            db_session, owner=owner, cycle=cycle, project_team_id=pt.id
        )
        q = scoped_objectives_query(exec_user, db_session)
        results = list(db_session.execute(q).scalars())
        assert obj in results

    def test_department_head_sees_report_objectives(self, db_session):
        """EXECUTIVE sees objective owned by their direct report."""
        exec_dept = make_department(db_session, name="Exec Dept", slug="exec-rpt")
        exec_user = make_user(db_session, role=UserRole.EXECUTIVE, department=exec_dept)
        report = make_user(db_session, department=exec_dept, manager=exec_user)
        cycle = make_cycle(db_session)
        # Objective owned by report, in a different dept — visible via reporting chain
        other_dept = make_department(db_session, name="Report Dept", slug="rpt-dept")
        obj = make_objective(
            db_session, owner=report, cycle=cycle, department_id=other_dept.id
        )
        q = scoped_objectives_query(exec_user, db_session)
        results = list(db_session.execute(q).scalars())
        assert obj in results

    def test_employee_on_project_sees_project_objectives(self, db_session):
        """EMPLOYEE added to project team sees all objectives scoped to that team."""
        dept_a = make_department(db_session, name="Dept A", slug="dept-a")
        dept_b = make_department(db_session, name="Dept B", slug="dept-b")
        employee = make_user(db_session, department=dept_a)
        owner = make_user(db_session, department=dept_b)
        cycle = make_cycle(db_session)
        pt = make_project_team(db_session, primary_department=dept_b)
        make_project_member(db_session, user=employee, project_team=pt)
        obj = make_objective(db_session, owner=owner, cycle=cycle, project_team_id=pt.id)
        q = scoped_objectives_query(employee, db_session)
        results = list(db_session.execute(q).scalars())
        assert obj in results

    def test_employee_not_on_project_cannot_see_project_objectives(self, db_session):
        """EMPLOYEE not on team cannot see project-scoped objectives."""
        dept_a = make_department(db_session, name="Dept A2", slug="dept-a2")
        dept_b = make_department(db_session, name="Dept B2", slug="dept-b2")
        outsider = make_user(db_session, department=dept_a)
        owner = make_user(db_session, department=dept_b)
        cycle = make_cycle(db_session)
        pt = make_project_team(db_session, primary_department=dept_b)
        obj = make_objective(db_session, owner=owner, cycle=cycle, project_team_id=pt.id)
        q = scoped_objectives_query(outsider, db_session)
        results = list(db_session.execute(q).scalars())
        assert obj not in results

    def test_employee_on_multiple_projects_sees_all(self, db_session):
        """EMPLOYEE on two teams sees objectives from both."""
        dept = make_department(db_session, name="Main Dept", slug="main-dept")
        employee = make_user(db_session, department=dept)
        owner = make_user(db_session, department=dept)
        cycle = make_cycle(db_session)
        pt1 = make_project_team(db_session, name="Team Alpha", primary_department=dept)
        pt2 = make_project_team(db_session, name="Team Beta", primary_department=dept)
        make_project_member(db_session, user=employee, project_team=pt1)
        make_project_member(db_session, user=employee, project_team=pt2)
        obj1 = make_objective(db_session, owner=owner, cycle=cycle, project_team_id=pt1.id)
        obj2 = make_objective(db_session, owner=owner, cycle=cycle, project_team_id=pt2.id)
        q = scoped_objectives_query(employee, db_session)
        results = list(db_session.execute(q).scalars())
        assert obj1 in results
        assert obj2 in results


# ═══════════════════════════════════════════════════════════════════════════
# TestScopedKeyResultsQuery
# ═══════════════════════════════════════════════════════════════════════════


class TestScopedKeyResultsQuery:
    def _setup(self, session):
        dept = make_department(session)
        owner = make_user(session, department=dept)
        cycle = make_cycle(session)
        obj = make_objective(
            session, owner=owner, cycle=cycle, department_id=dept.id
        )
        kr = make_key_result(session, objective=obj, owner=owner)
        return owner, cycle, dept, obj, kr

    def test_admin_sees_all_krs(self, db_session):
        owner, _, _, _, kr = self._setup(db_session)
        admin = make_user(db_session, role=UserRole.ADMIN)
        q = scoped_key_results_query(admin, db_session)
        results = list(db_session.execute(q).scalars())
        assert kr in results

    def test_c_suite_executive_sees_all_krs(self, db_session):
        owner, _, _, _, kr = self._setup(db_session)
        exec_user = make_c_suite_user(db_session, role=UserRole.EXECUTIVE)
        q = scoped_key_results_query(exec_user, db_session)
        results = list(db_session.execute(q).scalars())
        assert kr in results

    def test_employee_sees_krs_on_accessible_objectives(self, db_session):
        """Employee sees KRs on objectives they own."""
        owner, _, _, _, kr = self._setup(db_session)
        q = scoped_key_results_query(owner, db_session)
        results = list(db_session.execute(q).scalars())
        assert kr in results

    def test_employee_on_project_sees_krs(self, db_session):
        """Employee on a project team sees KRs on project-scoped objectives."""
        dept_a = make_department(db_session, name="KR Dept A", slug="kr-dept-a")
        dept_b = make_department(db_session, name="KR Dept B", slug="kr-dept-b")
        employee = make_user(db_session, department=dept_a)
        owner = make_user(db_session, department=dept_b)
        cycle = make_cycle(db_session)
        pt = make_project_team(db_session, primary_department=dept_b)
        make_project_member(db_session, user=employee, project_team=pt)
        obj = make_objective(db_session, owner=owner, cycle=cycle, project_team_id=pt.id)
        kr = make_key_result(db_session, objective=obj, owner=owner)
        q = scoped_key_results_query(employee, db_session)
        results = list(db_session.execute(q).scalars())
        assert kr in results

    def test_employee_excludes_krs_on_inaccessible_objectives(self, db_session):
        """Employee with no project membership cannot see KRs on others' objectives."""
        owner, _, dept, _, kr = self._setup(db_session)
        other_dept = make_department(db_session, name="Other", slug="other-kr")
        outsider = make_user(db_session, department=other_dept)
        q = scoped_key_results_query(outsider, db_session)
        results = list(db_session.execute(q).scalars())
        assert kr not in results

    def test_partner_raises_permission_error(self, db_session):
        partner = make_user(db_session, role=UserRole.PARTNER)
        with pytest.raises(PermissionError):
            scoped_key_results_query(partner, db_session)

    def test_partner_writes_audit_log_on_kr_query(self, db_session):
        partner = make_user(db_session, role=UserRole.PARTNER)
        with pytest.raises(PermissionError):
            scoped_key_results_query(partner, db_session)
        logs = list(db_session.execute(select(AuditLog)).scalars())
        assert len(logs) == 1
        assert logs[0].action == "rbac.denied.key_results_query"
        assert logs[0].actor_id == partner.id


# ═══════════════════════════════════════════════════════════════════════════
# TestScopedTasksQuery
# ═══════════════════════════════════════════════════════════════════════════


class TestScopedTasksQuery:
    def _setup(self, session):
        dept = make_department(session)
        owner = make_user(session, department=dept)
        cycle = make_cycle(session)
        obj = make_objective(
            session, owner=owner, cycle=cycle, department_id=dept.id
        )
        kr = make_key_result(session, objective=obj, owner=owner)
        task = make_task(session, key_result=kr, assignee=owner)
        return owner, cycle, dept, obj, kr, task

    def test_admin_sees_all_tasks(self, db_session):
        owner, _, _, _, _, task = self._setup(db_session)
        admin = make_user(db_session, role=UserRole.ADMIN)
        q = scoped_tasks_query(admin, db_session)
        results = list(db_session.execute(q).scalars())
        assert task in results

    def test_c_suite_executive_sees_all_tasks(self, db_session):
        owner, _, _, _, _, task = self._setup(db_session)
        exec_user = make_c_suite_user(db_session, role=UserRole.EXECUTIVE)
        q = scoped_tasks_query(exec_user, db_session)
        results = list(db_session.execute(q).scalars())
        assert task in results

    def test_employee_sees_assigned_tasks(self, db_session):
        owner, _, _, _, _, task = self._setup(db_session)
        q = scoped_tasks_query(owner, db_session)
        results = list(db_session.execute(q).scalars())
        assert task in results

    def test_employee_sees_tasks_on_accessible_kr(self, db_session):
        """Employee on a project team sees unassigned tasks on KRs of that project."""
        dept_a = make_department(db_session, name="Task Dept A", slug="task-dept-a")
        dept_b = make_department(db_session, name="Task Dept B", slug="task-dept-b")
        employee = make_user(db_session, department=dept_a)
        owner = make_user(db_session, department=dept_b)
        cycle = make_cycle(db_session)
        pt = make_project_team(db_session, primary_department=dept_b)
        make_project_member(db_session, user=employee, project_team=pt)
        obj = make_objective(db_session, owner=owner, cycle=cycle, project_team_id=pt.id)
        kr = make_key_result(db_session, objective=obj, owner=owner)
        unassigned_task = make_task(db_session, key_result=kr)
        q = scoped_tasks_query(employee, db_session)
        results = list(db_session.execute(q).scalars())
        assert unassigned_task in results

    def test_employee_excludes_tasks_on_inaccessible_kr(self, db_session):
        owner, _, _, _, _, task = self._setup(db_session)
        outsider = make_user(db_session)  # no dept, doesn't own anything
        q = scoped_tasks_query(outsider, db_session)
        results = list(db_session.execute(q).scalars())
        assert task not in results

    def test_partner_sees_external_assigned_tasks(self, db_session):
        owner, _, _, _, kr, _ = self._setup(db_session)
        partner = make_user(db_session, role=UserRole.PARTNER)
        ext_task = make_external_task(db_session, key_result=kr, assignee=partner)
        q = scoped_tasks_query(partner, db_session)
        results = list(db_session.execute(q).scalars())
        assert ext_task in results

    def test_partner_excludes_internal_tasks_even_if_assignee(self, db_session):
        owner, _, _, _, kr, _ = self._setup(db_session)
        partner = make_user(db_session, role=UserRole.PARTNER)
        internal_task = make_task(db_session, key_result=kr, assignee=partner)
        q = scoped_tasks_query(partner, db_session)
        results = list(db_session.execute(q).scalars())
        assert internal_task not in results

    def test_partner_excludes_external_tasks_assigned_to_others(self, db_session):
        owner, _, _, _, kr, _ = self._setup(db_session)
        partner = make_user(db_session, role=UserRole.PARTNER)
        other_partner = make_user(db_session, role=UserRole.PARTNER)
        ext_task = make_external_task(db_session, key_result=kr, assignee=other_partner)
        q = scoped_tasks_query(partner, db_session)
        results = list(db_session.execute(q).scalars())
        assert ext_task not in results

    def test_partner_excludes_soft_deleted_external_tasks(self, db_session):
        owner, _, _, _, kr, _ = self._setup(db_session)
        partner = make_user(db_session, role=UserRole.PARTNER)
        ext_task = make_external_task(db_session, key_result=kr, assignee=partner)
        ext_task.deleted_at = datetime.now(timezone.utc)
        db_session.flush()
        q = scoped_tasks_query(partner, db_session)
        results = list(db_session.execute(q).scalars())
        assert ext_task not in results


# ═══════════════════════════════════════════════════════════════════════════
# TestScopedChatQuery
# ═══════════════════════════════════════════════════════════════════════════


class TestScopedChatQuery:
    def _setup(self, session):
        dept = make_department(session)
        owner = make_user(session, department=dept)
        cycle = make_cycle(session)
        obj = make_objective(
            session, owner=owner, cycle=cycle, department_id=dept.id
        )
        kr = make_key_result(session, objective=obj, owner=owner)
        task = make_task(session, key_result=kr, assignee=owner)
        kr_msg = make_chat_message(
            session, context_type="key_result", context_id=kr.id, sender=owner
        )
        task_msg = make_chat_message(
            session, context_type="task", context_id=task.id, sender=owner
        )
        return owner, dept, cycle, obj, kr, task, kr_msg, task_msg

    def test_admin_sees_task_chat(self, db_session):
        owner, _, _, _, _, task, _, task_msg = self._setup(db_session)
        admin = make_user(db_session, role=UserRole.ADMIN)
        q = scoped_chat_query(admin, "task", task.id, db_session)
        results = list(db_session.execute(q).scalars())
        assert task_msg in results

    def test_admin_sees_kr_chat(self, db_session):
        owner, _, _, _, kr, _, kr_msg, _ = self._setup(db_session)
        admin = make_user(db_session, role=UserRole.ADMIN)
        q = scoped_chat_query(admin, "key_result", kr.id, db_session)
        results = list(db_session.execute(q).scalars())
        assert kr_msg in results

    def test_employee_sees_task_chat_on_accessible_task(self, db_session):
        owner, _, _, _, _, task, _, task_msg = self._setup(db_session)
        q = scoped_chat_query(owner, "task", task.id, db_session)
        results = list(db_session.execute(q).scalars())
        assert task_msg in results

    def test_employee_cannot_see_task_chat_on_inaccessible_task(self, db_session):
        owner, _, _, _, _, task, _, task_msg = self._setup(db_session)
        outsider = make_user(db_session)  # no dept, not assignee
        q = scoped_chat_query(outsider, "task", task.id, db_session)
        results = list(db_session.execute(q).scalars())
        assert task_msg not in results

    def test_partner_sees_task_chat_on_external_assigned_task(self, db_session):
        owner, _, _, _, kr, _, _, _ = self._setup(db_session)
        partner = make_user(db_session, role=UserRole.PARTNER)
        ext_task = make_external_task(db_session, key_result=kr, assignee=partner)
        msg = make_chat_message(
            db_session, context_type="task", context_id=ext_task.id, sender=owner
        )
        q = scoped_chat_query(partner, "task", ext_task.id, db_session)
        results = list(db_session.execute(q).scalars())
        assert msg in results

    def test_partner_cannot_see_task_chat_on_internal_task(self, db_session):
        """TIGHTENING 2: Internal task → partner raises PermissionError (not empty result)."""
        owner, _, _, _, kr, _, _, _ = self._setup(db_session)
        partner = make_user(db_session, role=UserRole.PARTNER)
        internal_task = make_task(db_session, key_result=kr, assignee=partner)
        with pytest.raises(PermissionError):
            scoped_chat_query(partner, "task", internal_task.id, db_session)

    def test_partner_raises_on_kr_chat(self, db_session):
        owner, _, _, _, kr, _, _, _ = self._setup(db_session)
        partner = make_user(db_session, role=UserRole.PARTNER)
        with pytest.raises(PermissionError):
            scoped_chat_query(partner, "key_result", kr.id, db_session)

    def test_partner_kr_chat_writes_audit_log(self, db_session):
        owner, _, _, _, kr, _, _, _ = self._setup(db_session)
        partner = make_user(db_session, role=UserRole.PARTNER)
        with pytest.raises(PermissionError):
            scoped_chat_query(partner, "key_result", kr.id, db_session)
        logs = list(db_session.execute(select(AuditLog)).scalars())
        assert len(logs) == 1
        assert logs[0].action == "rbac.denied.kr_chat_query"
        assert logs[0].actor_id == partner.id

    def test_partner_raises_on_task_chat_for_task_not_assigned_to_them(self, db_session):
        """TIGHTENING 2: External task assigned to another partner → raises + audit log."""
        owner, _, _, _, kr, _, _, _ = self._setup(db_session)
        partner = make_user(db_session, role=UserRole.PARTNER)
        other_partner = make_user(db_session, role=UserRole.PARTNER)
        ext_task = make_external_task(
            db_session, key_result=kr, assignee=other_partner
        )
        with pytest.raises(PermissionError):
            scoped_chat_query(partner, "task", ext_task.id, db_session)
        logs = list(db_session.execute(select(AuditLog)).scalars())
        assert any(log.action == "rbac.denied.task_chat_query" for log in logs)


# ═══════════════════════════════════════════════════════════════════════════
# TestCanViewPredicates
# ═══════════════════════════════════════════════════════════════════════════


class TestCanViewPredicates:
    def _setup(self, session):
        dept = make_department(session)
        owner = make_user(session, department=dept)
        cycle = make_cycle(session)
        obj = make_objective(
            session, owner=owner, cycle=cycle, department_id=dept.id
        )
        kr = make_key_result(session, objective=obj, owner=owner)
        task = make_task(session, key_result=kr, assignee=owner)
        return owner, dept, cycle, obj, kr, task

    def test_admin_can_view_any_objective(self, db_session):
        _, _, _, obj, _, _ = self._setup(db_session)
        admin = make_user(db_session, role=UserRole.ADMIN)
        assert can_view_objective(admin, obj) is True

    def test_c_suite_can_view_any_objective(self, db_session):
        """is_c_suite executive can view any objective."""
        _, _, _, obj, _, _ = self._setup(db_session)
        exec_user = make_c_suite_user(db_session, role=UserRole.EXECUTIVE)
        assert can_view_objective(exec_user, obj) is True

    def test_employee_can_view_own_objective(self, db_session):
        owner, _, _, obj, _, _ = self._setup(db_session)
        assert can_view_objective(owner, obj) is True

    def test_employee_cannot_view_other_dept_objective(self, db_session):
        """Employee with no project membership cannot view objective not owned by them."""
        _, _, _, obj, _, _ = self._setup(db_session)
        outsider = make_user(db_session)  # no dept, no project
        assert can_view_objective(outsider, obj) is False

    def test_partner_cannot_view_objective(self, db_session):
        _, _, _, obj, _, _ = self._setup(db_session)
        partner = make_user(db_session, role=UserRole.PARTNER)
        assert can_view_objective(partner, obj) is False

    def test_partner_can_view_external_assigned_task(self, db_session):
        _, _, _, _, kr, _ = self._setup(db_session)
        partner = make_user(db_session, role=UserRole.PARTNER)
        ext_task = make_external_task(db_session, key_result=kr, assignee=partner)
        assert can_view_task(partner, ext_task) is True

    def test_partner_cannot_view_internal_assigned_task(self, db_session):
        owner, _, _, _, kr, _ = self._setup(db_session)
        partner = make_user(db_session, role=UserRole.PARTNER)
        internal_task = make_task(db_session, key_result=kr, assignee=partner)
        assert can_view_task(partner, internal_task) is False

    def test_partner_cannot_view_task_assigned_to_other(self, db_session):
        _, _, _, _, kr, _ = self._setup(db_session)
        partner = make_user(db_session, role=UserRole.PARTNER)
        other_partner = make_user(db_session, role=UserRole.PARTNER)
        ext_task = make_external_task(db_session, key_result=kr, assignee=other_partner)
        assert can_view_task(partner, ext_task) is False

    def test_partner_cannot_view_kr(self, db_session):
        _, _, _, _, kr, _ = self._setup(db_session)
        partner = make_user(db_session, role=UserRole.PARTNER)
        assert can_view_key_result(partner, kr) is False

    # --- Phase 2.4 new tests ---

    def test_department_head_can_view_dept_objective(self, db_session):
        """Non-c_suite EXECUTIVE can view objective in their dept."""
        owner, dept, _, obj, _, _ = self._setup(db_session)
        exec_user = make_user(db_session, role=UserRole.EXECUTIVE, department=dept)
        assert can_view_objective(exec_user, obj) is True

    def test_department_head_cannot_view_other_dept_objective(self, db_session):
        """Non-c_suite EXECUTIVE cannot view objective from a different dept."""
        _, _, _, obj, _, _ = self._setup(db_session)
        other_dept = make_department(db_session, name="Other", slug="cvp-other")
        exec_user = make_user(db_session, role=UserRole.EXECUTIVE, department=other_dept)
        assert can_view_objective(exec_user, obj) is False

    def test_employee_on_project_can_view_project_objective(self, db_session):
        """Employee who is a member of a project team can view objectives on that team."""
        dept_a = make_department(db_session, name="View Dept A", slug="view-a")
        dept_b = make_department(db_session, name="View Dept B", slug="view-b")
        employee = make_user(db_session, department=dept_a)
        owner = make_user(db_session, department=dept_b)
        cycle = make_cycle(db_session)
        pt = make_project_team(db_session, primary_department=dept_b)
        make_project_member(db_session, user=employee, project_team=pt)
        obj = make_objective(db_session, owner=owner, cycle=cycle, project_team_id=pt.id)
        # Need to reload to populate project_team relationship
        db_session.refresh(obj)
        assert can_view_objective(employee, obj) is True

    def test_employee_not_on_project_cannot_view_project_objective(self, db_session):
        """Employee not on a project team cannot view objectives scoped to it."""
        dept_a = make_department(db_session, name="No-View Dept A", slug="nv-a")
        dept_b = make_department(db_session, name="No-View Dept B", slug="nv-b")
        outsider = make_user(db_session, department=dept_a)
        owner = make_user(db_session, department=dept_b)
        cycle = make_cycle(db_session)
        pt = make_project_team(db_session, primary_department=dept_b)
        obj = make_objective(db_session, owner=owner, cycle=cycle, project_team_id=pt.id)
        db_session.refresh(obj)
        assert can_view_objective(outsider, obj) is False


# ═══════════════════════════════════════════════════════════════════════════
# TestCanModifyPredicates
# ═══════════════════════════════════════════════════════════════════════════


class TestCanModifyPredicates:
    def _setup(self, session):
        dept = make_department(session)
        owner = make_user(session, department=dept)
        cycle = make_cycle(session)
        obj = make_objective(
            session, owner=owner, cycle=cycle, department_id=dept.id
        )
        kr = make_key_result(session, objective=obj, owner=owner)
        task = make_task(session, key_result=kr, assignee=owner)
        return owner, dept, cycle, obj, kr, task

    def test_admin_can_modify_any_objective(self, db_session):
        _, _, _, obj, _, _ = self._setup(db_session)
        admin = make_user(db_session, role=UserRole.ADMIN)
        assert can_modify_objective(admin, obj) is True

    def test_executive_can_modify_own_objective(self, db_session):
        _, _, cycle, _, _, _ = self._setup(db_session)
        exec_user = make_user(db_session, role=UserRole.EXECUTIVE)
        cycle2 = make_cycle(db_session, name="Q3 2026", year=2026, quarter=3)
        exec_obj = make_objective(db_session, owner=exec_user, cycle=cycle2)
        assert can_modify_objective(exec_user, exec_obj) is True

    def test_executive_can_modify_dept_objective(self, db_session):
        _, dept, _, obj, _, _ = self._setup(db_session)
        exec_user = make_user(db_session, role=UserRole.EXECUTIVE, department=dept)
        assert can_modify_objective(exec_user, obj) is True

    def test_executive_cannot_modify_other_dept_objective(self, db_session):
        _, _, _, obj, _, _ = self._setup(db_session)
        other_dept = make_department(db_session, name="Other", slug="other-mod")
        exec_user = make_user(db_session, role=UserRole.EXECUTIVE, department=other_dept)
        assert can_modify_objective(exec_user, obj) is False

    def test_employee_can_modify_own_objective(self, db_session):
        owner, _, _, obj, _, _ = self._setup(db_session)
        assert can_modify_objective(owner, obj) is True

    def test_employee_cannot_modify_others_objective(self, db_session):
        _, dept, _, obj, _, _ = self._setup(db_session)
        colleague = make_user(db_session, department=dept)
        assert can_modify_objective(colleague, obj) is False

    def test_partner_cannot_modify_objective(self, db_session):
        _, _, _, obj, _, _ = self._setup(db_session)
        partner = make_user(db_session, role=UserRole.PARTNER)
        assert can_modify_objective(partner, obj) is False

    def test_admin_can_modify_any_task(self, db_session):
        _, _, _, _, _, task = self._setup(db_session)
        admin = make_user(db_session, role=UserRole.ADMIN)
        assert can_modify_task(admin, task) is True

    def test_employee_can_modify_assigned_task(self, db_session):
        owner, _, _, _, _, task = self._setup(db_session)
        assert can_modify_task(owner, task) is True

    def test_employee_can_modify_task_as_kr_owner(self, db_session):
        """KR owner (not assignee) may also modify tasks on that KR."""
        owner, _, _, obj, kr, _ = self._setup(db_session)
        kr_owner = make_user(db_session)
        cycle2 = make_cycle(db_session, name="Q3 2026", year=2026, quarter=3)
        kr2 = make_key_result(db_session, objective=obj, owner=kr_owner)
        task2 = make_task(db_session, key_result=kr2, assignee=owner)  # assigned to owner, not kr_owner
        assert can_modify_task(kr_owner, task2) is True

    def test_employee_cannot_modify_unassigned_unowned_task(self, db_session):
        owner, dept, _, _, kr, _ = self._setup(db_session)
        other = make_user(db_session, department=dept)
        other_task = make_task(db_session, key_result=kr, assignee=owner)
        # other is neither assignee (owner is) nor kr owner (owner is)
        assert can_modify_task(other, other_task) is False

    def test_partner_cannot_modify_task(self, db_session):
        _, _, _, _, kr, _ = self._setup(db_session)
        partner = make_user(db_session, role=UserRole.PARTNER)
        ext_task = make_external_task(db_session, key_result=kr, assignee=partner)
        assert can_modify_task(partner, ext_task) is False

    def test_employee_can_modify_kr_on_owned_objective(self, db_session):
        """TIGHTENING 1: Objective owner may modify any KR on that objective."""
        owner, _, _, obj, _, _ = self._setup(db_session)
        other = make_user(db_session)
        # KR owned by other, but objective owned by owner
        kr2 = make_key_result(db_session, objective=obj, owner=other)
        assert can_modify_key_result(owner, kr2) is True

    def test_employee_cannot_modify_kr_on_unowned_objective(self, db_session):
        """TIGHTENING 1: Employee who owns neither KR nor parent obj cannot modify."""
        owner, dept, _, obj, kr, _ = self._setup(db_session)
        colleague = make_user(db_session, department=dept)
        # colleague doesn't own kr (owner_id=owner) nor obj (owner_id=owner)
        assert can_modify_key_result(colleague, kr) is False

    # --- Phase 2.4 new tests ---

    def test_project_lead_can_modify_project_objective(self, db_session):
        """Employee who is LEAD on the project team can modify project objectives."""
        dept = make_department(db_session, name="Lead Dept", slug="lead-dept")
        lead = make_user(db_session, department=dept)
        owner = make_user(db_session, department=dept)
        cycle = make_cycle(db_session)
        pt = make_project_team(db_session, primary_department=dept)
        make_project_member(db_session, user=lead, project_team=pt, role_on_team=RoleOnTeam.LEAD)
        obj = make_objective(db_session, owner=owner, cycle=cycle, project_team_id=pt.id)
        db_session.refresh(obj)
        assert can_modify_objective(lead, obj) is True

    def test_project_member_cannot_modify_project_objective(self, db_session):
        """Employee who is a regular MEMBER on the project team cannot modify project objectives."""
        dept = make_department(db_session, name="Mbr Dept", slug="mbr-dept")
        member = make_user(db_session, department=dept)
        owner = make_user(db_session, department=dept)
        cycle = make_cycle(db_session)
        pt = make_project_team(db_session, primary_department=dept)
        make_project_member(db_session, user=member, project_team=pt, role_on_team=RoleOnTeam.MEMBER)
        obj = make_objective(db_session, owner=owner, cycle=cycle, project_team_id=pt.id)
        db_session.refresh(obj)
        assert can_modify_objective(member, obj) is False

    def test_c_suite_employee_can_modify_anything(self, db_session):
        """is_c_suite with EMPLOYEE role can still modify any objective."""
        _, _, _, obj, _, _ = self._setup(db_session)
        compliance = make_c_suite_user(db_session, role=UserRole.EMPLOYEE)
        assert can_modify_objective(compliance, obj) is True


# ═══════════════════════════════════════════════════════════════════════════
# TestRequireRole
# ═══════════════════════════════════════════════════════════════════════════


class TestRequireRole:
    def test_allows_sufficient_role(self, db_session):
        emp = make_user(db_session, role=UserRole.EMPLOYEE)
        called = []

        @require_role(UserRole.EMPLOYEE, get_user=lambda: emp)
        def fn():
            called.append(True)

        fn()
        assert called == [True]

    def test_denies_insufficient_role(self, db_session):
        partner = make_user(db_session, role=UserRole.PARTNER)

        @require_role(UserRole.EMPLOYEE, get_user=lambda: partner)
        def fn():
            pass  # pragma: no cover

        with pytest.raises(PermissionError, match="employee"):
            fn()

    def test_admin_passes_all_minimums(self, db_session):
        admin = make_user(db_session, role=UserRole.ADMIN)

        for minimum in (
            UserRole.PARTNER,
            UserRole.EMPLOYEE,
            UserRole.EXECUTIVE,
            UserRole.ADMIN,
        ):
            def make_fn(min_role):
                @require_role(min_role, get_user=lambda: admin)
                def fn():
                    return min_role
                return fn

            assert make_fn(minimum)() is minimum

    def test_partner_denied_employee_minimum(self, db_session):
        partner = make_user(db_session, role=UserRole.PARTNER)

        @require_role(UserRole.EMPLOYEE, get_user=lambda: partner)
        def fn():
            return True  # pragma: no cover

        with pytest.raises(PermissionError):
            fn()

    def test_decorated_fn_called_with_args_when_permitted(self, db_session):
        admin = make_user(db_session, role=UserRole.ADMIN)

        @require_role(UserRole.EMPLOYEE, get_user=lambda: admin)
        def add(x, y):
            return x + y

        assert add(3, 4) == 7

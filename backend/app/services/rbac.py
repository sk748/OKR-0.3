"""
RBAC query scoping and permission predicates for OKRSYNC.

This module enforces the Zero Trust RBAC model. It is the single place
where "can this user see/touch this entity" is decided.

PARTNER is the zero-trust boundary. Every code path that might expose
Objective, KeyResult, CheckIn, Reflection, or ChatMessage(key_result) to a
PARTNER user must pass through this module first.

Authority rules summary (Phase 2.4):
  ADMIN          — full read/write on everything.
  is_c_suite     — full read visibility regardless of role; write follows role rules.
                   C-suite flag overrides EXECUTIVE dept-scoping and EMPLOYEE
                   project-team scoping for read paths.
  EXECUTIVE      — reads objectives in their dept + dept-participating projects +
                   their reporting chain; modifies same; may cascade links.
  EMPLOYEE       — reads/modifies own objectives + objectives on project teams
                   they belong to; reads/modifies own KRs + KRs on accessible
                   objectives; sees assigned tasks or tasks on accessible KRs.
  PARTNER        — zero-trust: only external tasks assigned to them. No access
                   to Objective, KeyResult, CheckIn, Reflection, KR-chat, or
                   AuditLog. Any such attempt writes an AuditLog denial row.

TRANSACTION RULE: scoped_*_query functions may call session.flush() after
writing an AuditLog row (for PARTNER denial), but they NEVER call
session.commit(). All other functions in this module are pure (no session).
"""

from __future__ import annotations

import functools
import uuid
from typing import Callable

from sqlalchemy import and_, false, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql import Select

from backend.app.models import (
    AuditLog,
    ChatMessage,
    KeyResult,
    Objective,
    ProjectTeamDepartment,
    ProjectTeamMember,
    RoleOnTeam,
    Task,
    User,
    UserRole,
)


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_PRIVILEGE_ORDER: dict[UserRole, int] = {
    UserRole.PARTNER: 0,
    UserRole.EMPLOYEE: 1,
    UserRole.EXECUTIVE: 2,
    UserRole.ADMIN: 3,
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _write_denied_audit(actor: User, action: str, session: Session) -> None:
    """
    Write an AuditLog row recording a denied access attempt by *actor*.
    Does NOT flush — caller flushes before raising PermissionError.
    """
    log = AuditLog(
        id=uuid.uuid4(),
        actor_id=actor.id,
        action=action,
        target_type=None,
        target_id=None,
        details={"role": actor.role.value},
    )
    session.add(log)


def _has_full_visibility(user: User) -> bool:
    """Return True for ADMIN or any is_c_suite user (compliance, CEO, Board, etc.)."""
    return user.role == UserRole.ADMIN or user.is_c_suite


def _user_project_team_ids(user: User) -> Select:
    """Subquery returning project_team_ids where *user* is a direct member."""
    return select(ProjectTeamMember.project_team_id).where(
        ProjectTeamMember.user_id == user.id
    )


def _user_department_project_team_ids(user: User) -> Select:
    """
    Subquery returning project_team_ids where *user*'s department participates.
    If the user has no department, returns an always-empty subquery.
    """
    q = select(ProjectTeamDepartment.project_team_id)
    if user.department_id is not None:
        return q.where(ProjectTeamDepartment.department_id == user.department_id)
    return q.where(false())


def _reporting_chain_user_ids(user: User, session: Session) -> list[uuid.UUID]:
    """
    Walk the manager_id tree DOWNWARD from *user* to collect all transitive
    direct-reports, including the user themselves (so their own untagged
    objectives are covered by the owner_id IN filter).

    Uses BFS to avoid stack overflow on deep orgs. The visited set guards
    against infinite loops in corrupt data (cycles in manager_id graph).
    """
    visited: set[uuid.UUID] = set()
    queue: list[uuid.UUID] = [user.id]
    result: list[uuid.UUID] = []
    while queue:
        current = queue.pop()
        if current in visited:
            continue
        visited.add(current)
        result.append(current)
        rows = list(
            session.execute(
                select(User.id).where(User.manager_id == current)
            ).scalars()
        )
        queue.extend(r for r in rows if r not in visited)
    return result


# ---------------------------------------------------------------------------
# Query scoping — return Select objects; callers add ordering / pagination
# ---------------------------------------------------------------------------


def scoped_objectives_query(user: User, session: Session) -> Select:
    """
    Return a SELECT statement for Objectives visible to *user*.

    ADMIN / is_c_suite:    all non-deleted objectives.
    EXECUTIVE (dept head): objectives in their dept, OR on a project where
                           their dept participates, OR owned by anyone in
                           their reporting chain (including themselves).
    EMPLOYEE:              objectives they own, OR on a project team they
                           are an explicit member of.
    PARTNER:               raises PermissionError (writes audit row first).
    """
    if _has_full_visibility(user):
        return select(Objective).where(Objective.deleted_at.is_(None))

    if user.role == UserRole.PARTNER:
        _write_denied_audit(user, "rbac.denied.objectives_query", session)
        session.flush()
        raise PermissionError("partners may not access objectives")

    base = Objective.deleted_at.is_(None)

    if user.role == UserRole.EXECUTIVE:
        chain_ids = _reporting_chain_user_ids(user, session)
        conditions = [Objective.owner_id.in_(chain_ids)]
        if user.department_id is not None:
            conditions.append(Objective.department_id == user.department_id)
            conditions.append(
                Objective.project_team_id.in_(
                    _user_department_project_team_ids(user)
                )
            )
        return select(Objective).where(and_(base, or_(*conditions)))

    # EMPLOYEE
    return select(Objective).where(
        and_(
            base,
            or_(
                Objective.owner_id == user.id,
                Objective.project_team_id.in_(_user_project_team_ids(user)),
            ),
        )
    )


def scoped_key_results_query(user: User, session: Session) -> Select:
    """
    Return a SELECT statement for KeyResults visible to *user*.

    ADMIN / is_c_suite:    all non-deleted key results.
    EXECUTIVE / EMPLOYEE:  key results on objectives accessible to them
                           (delegates to scoped_objectives_query logic).
    PARTNER:               raises PermissionError (writes audit row first).
    """
    if _has_full_visibility(user):
        return select(KeyResult).where(KeyResult.deleted_at.is_(None))

    if user.role == UserRole.PARTNER:
        _write_denied_audit(user, "rbac.denied.key_results_query", session)
        session.flush()
        raise PermissionError("partners may not access key results")

    # Build the objective visibility subquery inline (avoids calling the
    # full scoped_objectives_query which returns a full SELECT — we just
    # need the id-set subquery here).
    obj_ids_subq = _visible_objective_ids_subq(user, session)
    return select(KeyResult).where(
        and_(
            KeyResult.deleted_at.is_(None),
            KeyResult.objective_id.in_(obj_ids_subq),
        )
    )


def scoped_tasks_query(user: User, session: Session) -> Select:
    """
    Return a SELECT statement for Tasks visible to *user*.

    ADMIN / is_c_suite:    all non-deleted tasks.
    EXECUTIVE:             all tasks on key results whose objective is visible.
                           (Executives may need to monitor sprint progress.)
    EMPLOYEE:              tasks assigned to them OR on accessible key results.
    PARTNER:               direct indexed lookup — is_external=True AND
                           assignee_id only. Never joins through KR/Objective.
                           Uses ix_tasks_partner_scope partial index on PG.
    """
    if _has_full_visibility(user):
        return select(Task).where(Task.deleted_at.is_(None))

    if user.role == UserRole.PARTNER:
        # Hot path: satisfies ix_tasks_partner_scope (assignee_id WHERE is_external=True).
        return select(Task).where(
            and_(
                Task.assignee_id == user.id,
                Task.is_external.is_(True),
                Task.deleted_at.is_(None),
            )
        )

    obj_ids_subq = _visible_objective_ids_subq(user, session)
    kr_ids_subq = select(KeyResult.id).where(
        and_(
            KeyResult.deleted_at.is_(None),
            KeyResult.objective_id.in_(obj_ids_subq),
        )
    )

    if user.role == UserRole.EXECUTIVE:
        # Executive sees all tasks on their visible KRs.
        return select(Task).where(
            and_(
                Task.deleted_at.is_(None),
                Task.key_result_id.in_(kr_ids_subq),
            )
        )

    # EMPLOYEE
    return select(Task).where(
        and_(
            Task.deleted_at.is_(None),
            or_(
                Task.assignee_id == user.id,
                Task.key_result_id.in_(kr_ids_subq),
            ),
        )
    )


def scoped_chat_query(
    user: User,
    context_type: str,
    context_id: uuid.UUID,
    session: Session,
) -> Select:
    """
    Return a SELECT statement for ChatMessages in the given context.

    ADMIN / is_c_suite:    all messages in the context.

    EMPLOYEE (task):    messages if the task is accessible to them (assignee or
                        KR on a visible objective).
    EMPLOYEE (kr):      messages if the KR's objective is visible to them.

    PARTNER (task):     first verifies the task is visible to this partner via
                        the same direct indexed lookup as scoped_tasks_query.
                        Raises PermissionError + writes audit row if not visible.
    PARTNER (kr):       always raises PermissionError (writes audit row first).
    """
    if _has_full_visibility(user):
        return select(ChatMessage).where(
            and_(
                ChatMessage.context_type == context_type,
                ChatMessage.context_id == context_id,
            )
        )

    if user.role == UserRole.PARTNER:
        if context_type == "key_result":
            _write_denied_audit(user, "rbac.denied.kr_chat_query", session)
            session.flush()
            raise PermissionError("partners may not access key result chat")

        # context_type == "task": verify visibility before returning chat.
        # Same indexed lookup as scoped_tasks_query — no join through hierarchy.
        task_row = session.execute(
            select(Task.id).where(
                and_(
                    Task.id == context_id,
                    Task.assignee_id == user.id,
                    Task.is_external.is_(True),
                    Task.deleted_at.is_(None),
                )
            )
        ).first()

        if task_row is None:
            _write_denied_audit(user, "rbac.denied.task_chat_query", session)
            session.flush()
            raise PermissionError(
                "partners may not access chat for tasks not assigned to them"
            )

        return select(ChatMessage).where(
            and_(
                ChatMessage.context_type == "task",
                ChatMessage.context_id == context_id,
            )
        )

    # EMPLOYEE / EXECUTIVE (non-c_suite)
    obj_ids_subq = _visible_objective_ids_subq(user, session)

    if context_type == "task":
        kr_ids_subq = select(KeyResult.id).where(
            and_(
                KeyResult.deleted_at.is_(None),
                KeyResult.objective_id.in_(obj_ids_subq),
            )
        )
        accessible_task_ids = select(Task.id).where(
            and_(
                Task.deleted_at.is_(None),
                or_(
                    Task.assignee_id == user.id,
                    Task.key_result_id.in_(kr_ids_subq),
                ),
            )
        )
        return select(ChatMessage).where(
            and_(
                ChatMessage.context_type == "task",
                ChatMessage.context_id == context_id,
                ChatMessage.context_id.in_(accessible_task_ids),
            )
        )

    # context_type == "key_result"
    accessible_kr_ids = select(KeyResult.id).where(
        and_(
            KeyResult.deleted_at.is_(None),
            KeyResult.objective_id.in_(obj_ids_subq),
        )
    )
    return select(ChatMessage).where(
        and_(
            ChatMessage.context_type == "key_result",
            ChatMessage.context_id == context_id,
            ChatMessage.context_id.in_(accessible_kr_ids),
        )
    )


# ---------------------------------------------------------------------------
# Internal subquery helper shared by KR / Task / Chat query functions
# ---------------------------------------------------------------------------


def _visible_objective_ids_subq(user: User, session: Session) -> Select:
    """
    Return a subquery of Objective.id values visible to *user*.
    Caller must have already excluded ADMIN/is_c_suite/PARTNER before calling.
    """
    base = Objective.deleted_at.is_(None)

    if user.role == UserRole.EXECUTIVE:
        chain_ids = _reporting_chain_user_ids(user, session)
        conditions = [Objective.owner_id.in_(chain_ids)]
        if user.department_id is not None:
            conditions.append(Objective.department_id == user.department_id)
            conditions.append(
                Objective.project_team_id.in_(
                    _user_department_project_team_ids(user)
                )
            )
        return select(Objective.id).where(and_(base, or_(*conditions)))

    # EMPLOYEE
    return select(Objective.id).where(
        and_(
            base,
            or_(
                Objective.owner_id == user.id,
                Objective.project_team_id.in_(_user_project_team_ids(user)),
            ),
        )
    )


# ---------------------------------------------------------------------------
# Permission predicates — pure functions (no session, no DB round-trips)
# ---------------------------------------------------------------------------


def can_view_objective(user: User, objective: Objective) -> bool:
    """
    Return True if *user* may read *objective*.

    PARTNER:            never.
    ADMIN / is_c_suite: always.
    EXECUTIVE:          owns it, OR it is in their dept, OR it is on a project
                        team where their dept participates (requires
                        objective.project_team.participating_departments loaded).
    EMPLOYEE:           owns it, OR is an explicit member of its project team
                        (requires objective.project_team.members loaded).
    """
    if user.role == UserRole.PARTNER:
        return False
    if _has_full_visibility(user):
        return True
    if user.role == UserRole.EXECUTIVE:
        if objective.owner_id == user.id:
            return True
        if user.department_id and objective.department_id == user.department_id:
            return True
        if objective.project_team_id and objective.project_team:
            for ptd in objective.project_team.participating_departments:
                if ptd.department_id == user.department_id:
                    return True
        return False
    # EMPLOYEE
    if objective.owner_id == user.id:
        return True
    if objective.project_team_id and objective.project_team:
        for m in objective.project_team.members:
            if m.user_id == user.id:
                return True
    return False


def can_view_key_result(user: User, kr: KeyResult) -> bool:
    """
    Return True if *user* may read *kr*.
    Requires kr.objective to be loaded (lazy load is fine within a session).

    PARTNER: never.
    ADMIN / is_c_suite: always.
    EXECUTIVE / EMPLOYEE: if they can view the parent objective.
    """
    if user.role == UserRole.PARTNER:
        return False
    if _has_full_visibility(user):
        return True
    return can_view_objective(user, kr.objective)


def can_view_task(user: User, task: Task) -> bool:
    """
    Return True if *user* may read *task*.
    Requires task.key_result (and task.key_result.objective) to be loaded
    for the EMPLOYEE branch.

    PARTNER: only if is_external=True AND they are the assignee.
    ADMIN / is_c_suite: always.
    EMPLOYEE / EXECUTIVE: if they are the assignee OR if they can view the KR.
    """
    if user.role == UserRole.PARTNER:
        return task.is_external and task.assignee_id == user.id
    if _has_full_visibility(user):
        return True
    # EMPLOYEE / EXECUTIVE
    if task.assignee_id == user.id:
        return True
    return can_view_key_result(user, task.key_result)


def can_modify_objective(user: User, objective: Objective) -> bool:
    """
    Return True if *user* may write to *objective*.

    PARTNER:            never.
    ADMIN / is_c_suite: always.
    EXECUTIVE:          owns it, in their dept, OR dept participates in its
                        project team (requires participating_departments loaded).
    EMPLOYEE:           owns it, OR is a LEAD on its project team.
    """
    if user.role == UserRole.PARTNER:
        return False
    if _has_full_visibility(user):
        return True
    if user.role == UserRole.EXECUTIVE:
        if objective.owner_id == user.id:
            return True
        if user.department_id and objective.department_id == user.department_id:
            return True
        if objective.project_team_id and objective.project_team:
            for ptd in objective.project_team.participating_departments:
                if ptd.department_id == user.department_id:
                    return True
        return False
    # EMPLOYEE: owns it or is a project team LEAD
    if objective.owner_id == user.id:
        return True
    if objective.project_team_id and objective.project_team:
        for m in objective.project_team.members:
            if m.user_id == user.id and m.role_on_team == RoleOnTeam.LEAD:
                return True
    return False


def can_modify_key_result(user: User, kr: KeyResult) -> bool:
    """
    Return True if *user* may write to *kr*.
    Requires kr.objective to be loaded (lazy load is fine within a session).

    PARTNER:            never.
    ADMIN / is_c_suite: always.
    EXECUTIVE:          same authority as can_modify_objective on the parent
                        objective.
    EMPLOYEE:           if they own the KR OR if they own the parent objective.
                        (Rationale: an Objective owner reasonably controls its
                        KRs even when a separate person is formally the KR owner.)
    """
    if user.role == UserRole.PARTNER:
        return False
    if _has_full_visibility(user):
        return True
    if user.role == UserRole.EXECUTIVE:
        return can_modify_objective(user, kr.objective)
    # EMPLOYEE: KR owner OR parent objective owner
    return kr.owner_id == user.id or kr.objective.owner_id == user.id


def can_modify_task(user: User, task: Task) -> bool:
    """
    Return True if *user* may write to *task*.
    Requires task.key_result to be loaded for the EMPLOYEE branch.

    PARTNER:            never.
    ADMIN / is_c_suite: always.
    EXECUTIVE:          always (mirrors their broad read access to tasks).
    EMPLOYEE:           if they are the assignee OR if they own the KR.
    """
    if user.role == UserRole.PARTNER:
        return False
    if _has_full_visibility(user):
        return True
    if user.role == UserRole.EXECUTIVE:
        return True
    # EMPLOYEE: assignee or KR owner
    return task.assignee_id == user.id or task.key_result.owner_id == user.id


# ---------------------------------------------------------------------------
# Decorator factory
# ---------------------------------------------------------------------------


def require_role(minimum: UserRole, get_user: Callable[[], User]) -> Callable:
    """
    Decorator factory that gates a function behind a minimum role requirement.

    minimum:  the lowest UserRole permitted to call the decorated function.
              Privilege order: PARTNER < EMPLOYEE < EXECUTIVE < ADMIN.
    get_user: callable that returns the current User — will be wired to
              Flask's g.current_user in Phase 2.5.

    Raises PermissionError if the resolved user's role is below *minimum*.

    Usage:
        @require_role(UserRole.EMPLOYEE, get_user=lambda: g.current_user)
        def my_route():
            ...
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            user = get_user()
            if _PRIVILEGE_ORDER[user.role] < _PRIVILEGE_ORDER[minimum]:
                raise PermissionError(
                    f"requires {minimum.value} role or higher"
                )
            return fn(*args, **kwargs)
        return wrapper
    return decorator

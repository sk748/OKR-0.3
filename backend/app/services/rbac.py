"""
RBAC query scoping and permission predicates for OKRSYNC.

This module enforces the Zero Trust RBAC model. It is the single place
where "can this user see/touch this entity" is decided.

PARTNER is the zero-trust boundary. Every code path that might expose
Objective, KeyResult, CheckIn, Reflection, or ChatMessage(key_result) to a
PARTNER user must pass through this module first.

Authority rules summary:
  ADMIN       — full read/write on everything.
  EXECUTIVE   — reads everything; modifies objectives/KRs in their dept or
                owned by them; may cascade links.
  EMPLOYEE    — reads/modifies own objectives + dept objectives; reads/modifies
                own KRs + KRs on objectives they own; sees assigned tasks or
                tasks on accessible KRs.
  PARTNER     — zero-trust: only external tasks assigned to them. No access
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

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql import Select

from backend.app.models import (
    AuditLog,
    ChatMessage,
    KeyResult,
    Objective,
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


def _employee_obj_ids_subq(user: User) -> Select:
    """
    Return a SELECT of Objective.id values visible to an EMPLOYEE user.

    Includes objectives the user owns, plus objectives whose department_id
    matches the user's department (if they have one). Always excludes
    soft-deleted rows.
    """
    base = Objective.deleted_at.is_(None)
    if user.department_id is not None:
        ownership = or_(
            Objective.owner_id == user.id,
            Objective.department_id == user.department_id,
        )
    else:
        ownership = Objective.owner_id == user.id
    return select(Objective.id).where(and_(base, ownership))


# ---------------------------------------------------------------------------
# Query scoping — return Select objects; callers add ordering / pagination
# ---------------------------------------------------------------------------


def scoped_objectives_query(user: User, session: Session) -> Select:
    """
    Return a SELECT statement for Objectives visible to *user*.

    ADMIN / EXECUTIVE: all non-deleted objectives.
    EMPLOYEE:          objectives they own + objectives in their department.
    PARTNER:           raises PermissionError (writes audit row first).
    """
    if user.role in (UserRole.ADMIN, UserRole.EXECUTIVE):
        return select(Objective).where(Objective.deleted_at.is_(None))

    if user.role == UserRole.PARTNER:
        _write_denied_audit(user, "rbac.denied.objectives_query", session)
        session.flush()
        raise PermissionError("partners may not access objectives")

    # EMPLOYEE
    base = Objective.deleted_at.is_(None)
    if user.department_id is not None:
        ownership = or_(
            Objective.owner_id == user.id,
            Objective.department_id == user.department_id,
        )
    else:
        ownership = Objective.owner_id == user.id
    return select(Objective).where(and_(base, ownership))


def scoped_key_results_query(user: User, session: Session) -> Select:
    """
    Return a SELECT statement for KeyResults visible to *user*.

    ADMIN / EXECUTIVE: all non-deleted key results.
    EMPLOYEE:          key results on objectives accessible to them.
    PARTNER:           raises PermissionError (writes audit row first).
    """
    if user.role in (UserRole.ADMIN, UserRole.EXECUTIVE):
        return select(KeyResult).where(KeyResult.deleted_at.is_(None))

    if user.role == UserRole.PARTNER:
        _write_denied_audit(user, "rbac.denied.key_results_query", session)
        session.flush()
        raise PermissionError("partners may not access key results")

    # EMPLOYEE
    return select(KeyResult).where(
        and_(
            KeyResult.deleted_at.is_(None),
            KeyResult.objective_id.in_(_employee_obj_ids_subq(user)),
        )
    )


def scoped_tasks_query(user: User, session: Session) -> Select:
    """
    Return a SELECT statement for Tasks visible to *user*.

    ADMIN / EXECUTIVE: all non-deleted tasks.
    EMPLOYEE:          tasks assigned to them OR on accessible key results.
    PARTNER:           direct indexed lookup — is_external=True AND assignee_id
                       only. Never joins through KR/Objective hierarchy.
                       Uses ix_tasks_partner_scope partial index on PostgreSQL.
    """
    if user.role in (UserRole.ADMIN, UserRole.EXECUTIVE):
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

    # EMPLOYEE
    kr_ids_subq = select(KeyResult.id).where(
        and_(
            KeyResult.deleted_at.is_(None),
            KeyResult.objective_id.in_(_employee_obj_ids_subq(user)),
        )
    )
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

    ADMIN / EXECUTIVE: all messages in the context regardless of visibility.

    EMPLOYEE (task):   messages if the task is accessible to them (assignee or
                       KR on an accessible objective).
    EMPLOYEE (kr):     messages if the KR's objective is accessible to them.

    PARTNER (task):    first verifies the task is visible to this partner via the
                       same direct indexed lookup as scoped_tasks_query. If the
                       task is not visible (not assigned, not external, soft-deleted,
                       or wrong assignee), writes audit row + raises PermissionError.
                       Returns message rows only if the task IS visible.
    PARTNER (kr):      always raises PermissionError (writes audit row first).
    """
    if user.role in (UserRole.ADMIN, UserRole.EXECUTIVE):
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

    # EMPLOYEE
    if context_type == "task":
        kr_ids_subq = select(KeyResult.id).where(
            and_(
                KeyResult.deleted_at.is_(None),
                KeyResult.objective_id.in_(_employee_obj_ids_subq(user)),
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

    # EMPLOYEE, context_type == "key_result"
    accessible_kr_ids = select(KeyResult.id).where(
        and_(
            KeyResult.deleted_at.is_(None),
            KeyResult.objective_id.in_(_employee_obj_ids_subq(user)),
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
# Permission predicates — pure functions (no session, no DB round-trips)
# ---------------------------------------------------------------------------


def can_view_objective(user: User, objective: Objective) -> bool:
    """
    Return True if *user* may read *objective*.

    PARTNER: never.
    ADMIN / EXECUTIVE: always.
    EMPLOYEE: if they own it OR if it belongs to their department.
    """
    if user.role == UserRole.PARTNER:
        return False
    if user.role in (UserRole.ADMIN, UserRole.EXECUTIVE):
        return True
    # EMPLOYEE
    if objective.owner_id == user.id:
        return True
    return (
        user.department_id is not None
        and objective.department_id == user.department_id
    )


def can_view_key_result(user: User, kr: KeyResult) -> bool:
    """
    Return True if *user* may read *kr*.
    Requires kr.objective to be loaded (lazy load is fine within a session).

    PARTNER: never.
    ADMIN / EXECUTIVE: always.
    EMPLOYEE: if they can view the parent objective.
    """
    if user.role == UserRole.PARTNER:
        return False
    if user.role in (UserRole.ADMIN, UserRole.EXECUTIVE):
        return True
    return can_view_objective(user, kr.objective)


def can_view_task(user: User, task: Task) -> bool:
    """
    Return True if *user* may read *task*.
    Requires task.key_result (and task.key_result.objective) to be loaded
    for the EMPLOYEE branch.

    PARTNER: only if is_external=True AND they are the assignee.
    ADMIN / EXECUTIVE: always.
    EMPLOYEE: if they are the assignee OR if they can view the KR.
    """
    if user.role == UserRole.PARTNER:
        return task.is_external and task.assignee_id == user.id
    if user.role in (UserRole.ADMIN, UserRole.EXECUTIVE):
        return True
    # EMPLOYEE
    if task.assignee_id == user.id:
        return True
    return can_view_key_result(user, task.key_result)


def can_modify_objective(user: User, objective: Objective) -> bool:
    """
    Return True if *user* may write to *objective*.

    PARTNER: never.
    ADMIN: always.
    EXECUTIVE: if they own it OR if it belongs to their department.
    EMPLOYEE: only if they own it.
    """
    if user.role == UserRole.PARTNER:
        return False
    if user.role == UserRole.ADMIN:
        return True
    if user.role == UserRole.EXECUTIVE:
        if objective.owner_id == user.id:
            return True
        return (
            user.department_id is not None
            and objective.department_id == user.department_id
        )
    # EMPLOYEE
    return objective.owner_id == user.id


def can_modify_key_result(user: User, kr: KeyResult) -> bool:
    """
    Return True if *user* may write to *kr*.
    Requires kr.objective to be loaded (lazy load is fine within a session).

    PARTNER: never.
    ADMIN: always.
    EXECUTIVE: same authority as can_modify_objective on the parent objective.
    EMPLOYEE: if they own the KR OR if they own the parent objective.
              (Rationale: an Objective owner reasonably controls its KRs even
              when a separate person is formally listed as the KR owner.)
    """
    if user.role == UserRole.PARTNER:
        return False
    if user.role == UserRole.ADMIN:
        return True
    if user.role == UserRole.EXECUTIVE:
        return can_modify_objective(user, kr.objective)
    # EMPLOYEE: KR owner OR parent objective owner
    return kr.owner_id == user.id or kr.objective.owner_id == user.id


def can_modify_task(user: User, task: Task) -> bool:
    """
    Return True if *user* may write to *task*.
    Requires task.key_result to be loaded for the EMPLOYEE branch.

    PARTNER: never.
    ADMIN / EXECUTIVE: always.
    EMPLOYEE: if they are the assignee OR if they own the KR.
    """
    if user.role == UserRole.PARTNER:
        return False
    if user.role in (UserRole.ADMIN, UserRole.EXECUTIVE):
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

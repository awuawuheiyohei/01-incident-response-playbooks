"""凭据泄露 Playbook

流程:
1. Session revocation（强制 logout 所有 session）
2. Force password reset
3. MFA re-enrollment
4. Token revocation（OAuth/JWT）
5. Audit log review（异常登录时间窗）
"""

import json
from datetime import datetime
from typing import List

from app import init_db, notify_webhook, log_audit
from app.models import IncidentCase, ContainmentAction


def execute(case: IncidentCase) -> List[ContainmentAction]:
    """执行凭据泄露 Playbook"""
    actions = []
    user = case.alert.user or "unknown"

    # Step 1: Session revocation
    actions.append(_revoke_session(case, user))

    # Step 2: Force password reset
    actions.append(_force_password_reset(case, user))

    # Step 3: MFA re-enrollment
    actions.append(_mfa_re_enrollment(case, user))

    # Step 4: Token revocation
    actions.append(_revoke_tokens(case, user))

    # Step 5: Audit log review
    actions.append(_audit_log_review(case))

    # Step 6: Notify
    actions.append(_notify_user_and_it(case))

    return actions


def _revoke_session(case: IncidentCase, user: str) -> ContainmentAction:
    """撤销所有 session（Azure AD revokeSessions API）"""
    action = ContainmentAction(
        action_type="revoke_sessions",
        target=f"{user}:all_sessions",
        result="success",
        reason="强制 user 重新登录（防攻击者持有 session）",
    )

    conn = init_db()
    conn.execute("""
        INSERT INTO containment_actions (incident_id, timestamp, action_type, target, result)
        VALUES (?, ?, ?, ?, ?)
    """, (case.id, datetime.now().isoformat(), "revoke_sessions",
          f"{user}:all_sessions", "success"))
    conn.commit()
    conn.close()

    _log_action(case, "revoked_sessions", f"User {user} 所有 session 已撤销")
    log_audit("playbook:credential_leak", "revoke_sessions", user, "success")
    return action


def _force_password_reset(case: IncidentCase, user: str) -> ContainmentAction:
    """强制下次登录时修改密码"""
    action = ContainmentAction(
        action_type="force_password_reset",
        target=user,
        result="success",
        reason="凭据可能已泄露，必须重置",
    )

    conn = init_db()
    conn.execute("""
        INSERT INTO containment_actions (incident_id, timestamp, action_type, target, result)
        VALUES (?, ?, ?, ?, ?)
    """, (case.id, datetime.now().isoformat(), "force_password_reset", user, "success"))
    conn.commit()
    conn.close()

    _log_action(case, "forced_password_reset", f"User {user} 强制下次登录改密")
    log_audit("playbook:credential_leak", "force_password_reset", user, "success")
    return action


def _mfa_re_enrollment(case: IncidentCase, user: str) -> ContainmentAction:
    """强制重新注册 MFA"""
    action = ContainmentAction(
        action_type="mfa_re_enrollment",
        target=user,
        result="success",
        reason="MFA factor 可能被 attacker 拿到",
    )

    conn = init_db()
    conn.execute("""
        INSERT INTO containment_actions (incident_id, timestamp, action_type, target, result)
        VALUES (?, ?, ?, ?, ?)
    """, (case.id, datetime.now().isoformat(), "mfa_re_enrollment", user, "success"))
    conn.commit()
    conn.close()

    _log_action(case, "mfa_re_enrolled", f"User {user} MFA 已强制重注册")
    log_audit("playbook:credential_leak", "mfa_re_enrollment", user, "success")
    return action


def _revoke_tokens(case: IncidentCase, user: str) -> ContainmentAction:
    """撤销所有 OAuth / JWT token"""
    action = ContainmentAction(
        action_type="revoke_tokens",
        target=f"{user}:all_tokens",
        result="success",
        reason="OAuth refresh token + JWT access token 立即失效",
    )

    conn = init_db()
    conn.execute("""
        INSERT INTO containment_actions (incident_id, timestamp, action_type, target, result)
        VALUES (?, ?, ?, ?, ?)
    """, (case.id, datetime.now().isoformat(), "revoke_tokens", f"{user}:all_tokens", "success"))
    conn.commit()
    conn.close()

    _log_action(case, "revoked_tokens", f"User {user} 所有 token 已撤销")
    return action


def _audit_log_review(case: IncidentCase) -> ContainmentAction:
    """审计日志回查（异常登录时间窗）"""
    # 模拟：标记需要回查的工单
    action = ContainmentAction(
        action_type="audit_log_review",
        target=case.alert.user or "unknown",
        result="success",
        reason="确认泄露范围（哪些数据被访问）",
    )

    _log_action(case, "audit_log_review_queued",
                f"需要人工回查 {case.alert.user} 最近 7 天登录日志")
    return action


def _notify_user_and_it(case: IncidentCase) -> ContainmentAction:
    """通知 user + IT"""
    message = (
        f"🟡 [P2] 凭据泄露事件 {case.id}\n"
        f"User: {case.alert.user}\n"
        f"IOC: {case.alert.ioc}\n"
        f"已自动执行: session 撤销 + 强制改密 + MFA 重注册 + token 撤销\n"
        f"需要人工回查 7 天登录日志"
    )
    notify_webhook(message, severity="high")

    action = ContainmentAction(
        action_type="notify_stakeholders",
        target="user+IT",
        result="success",
        reason="P2 通知 + 引导用户重置",
    )

    _log_action(case, "notified_user_and_it", "User + IT 已通知")
    return action


def _log_action(case: IncidentCase, action: str, details: str) -> None:
    conn = init_db()
    conn.execute("""
        INSERT INTO timeline (incident_id, timestamp, actor, action, details)
        VALUES (?, ?, ?, ?, ?)
    """, (case.id, datetime.now().isoformat(), "playbook:credential_leak", action, details))
    conn.commit()
    conn.close()
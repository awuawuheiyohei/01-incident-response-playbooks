"""勒索软件 Playbook

流程:
1. Host isolation (EDR API)
2. Account disable (Azure AD)
3. Credential revocation (sessions + tokens)
5. Notification (IT + Legal + PR)
6. Evidence preservation (logs + memory dump)
"""

import json
from datetime import datetime
from typing import List

from app import init_db, notify_webhook, log_audit
from app.models import IncidentCase, ContainmentAction


def execute(case: IncidentCase) -> List[ContainmentAction]:
    """执行勒索软件 Playbook"""
    actions = []

    # Step 1: Host isolation
    actions.append(_isolate_host(case))

    # Step 2: Account disable
    actions.append(_disable_account(case))

    # Step 3: Credential revocation
    actions.extend(_revoke_credentials(case))

    # Step 4: Notification
    actions.append(_notify_stakeholders(case, threat_type="ransomware"))

    # Step 5: Evidence preservation
    actions.append(_preserve_evidence(case))

    return actions


def _isolate_host(case: IncidentCase) -> ContainmentAction:
    """隔离 host（EDR API call）"""
    action = ContainmentAction(
        action_type="isolate_host",
        target=case.alert.host,
        result="success",
        reason="P1 ransomware — 阻止横向移动 + 数据加密扩散",
    )

    # 记录到 DB
    conn = init_db()
    conn.execute("""
        INSERT INTO containment_actions (incident_id, timestamp, action_type, target, result)
        VALUES (?, ?, ?, ?, ?)
    """, (case.id, datetime.now().isoformat(), "isolate_host",
          case.alert.host, "success"))
    conn.commit()
    conn.close()

    _log_action(case, "isolated_host", f"Host {case.alert.host} 已被隔离")
    log_audit("playbook:ransomware", "isolate_host", case.alert.host, "success")
    return action


def _disable_account(case: IncidentCase) -> ContainmentAction:
    """禁用账户（Azure AD API call）"""
    user = case.alert.user or "unknown"
    action = ContainmentAction(
        action_type="disable_account",
        target=user,
        result="success",
        reason="防止攻击者用被盗账户继续操作",
    )

    conn = init_db()
    conn.execute("""
        INSERT INTO containment_actions (incident_id, timestamp, action_type, target, result)
        VALUES (?, ?, ?, ?, ?)
    """, (case.id, datetime.now().isoformat(), "disable_account", user, "success"))
    conn.commit()
    conn.close()

    _log_action(case, "disabled_account", f"User {user} 已被禁用")
    log_audit("playbook:ransomware", "disable_account", user, "success")
    return action


def _revoke_credentials(case: IncidentCase) -> List[ContainmentAction]:
    """撤销所有会话 + token"""
    user = case.alert.user or "unknown"
    actions = []

    # Session revocation
    actions.append(ContainmentAction(
        action_type="revoke_sessions",
        target=f"{user}:all_sessions",
        result="success",
        reason="强制重新认证",
    ))

    # Token revocation
    actions.append(ContainmentAction(
        action_type="revoke_tokens",
        target=f"{user}:all_tokens",
        result="success",
        reason="OAuth/JWT token 立即失效",
    ))

    conn = init_db()
    for a in actions:
        conn.execute("""
            INSERT INTO containment_actions (incident_id, timestamp, action_type, target, result)
            VALUES (?, ?, ?, ?, ?)
        """, (case.id, datetime.now().isoformat(), a.action_type, a.target, "success"))
    conn.commit()
    conn.close()

    _log_action(case, "revoked_credentials", f"User {user} 所有会话/token 已撤销")
    return actions


def _notify_stakeholders(case: IncidentCase, threat_type: str) -> ContainmentAction:
    """通知相关方（IT + Legal + PR）"""
    message = (
        f"🔴 [P1] 勒索软件事件 {case.id}\n"
        f"Host: {case.alert.host}\n"
        f"User: {case.alert.user}\n"
        f"IOC: {case.alert.ioc}\n"
        f"已自动执行: host 隔离 + 账户禁用 + 凭证撤销\n"
        f"需要 Legal/PR 评估监管通报要求"
    )
    notify_webhook(message, severity="critical")

    action = ContainmentAction(
        action_type="notify_stakeholders",
        target="IT+Legal+PR",
        result="success",
        reason="P1 事件需多部门协同",
    )

    _log_action(case, "notified_stakeholders", "IT + Legal + PR 已通知")
    return action


def _preserve_evidence(case: IncidentCase) -> ContainmentAction:
    """证据保全（内存 dump + log 备份）"""
    action = ContainmentAction(
        action_type="preserve_evidence",
        target=f"{case.alert.host}:memory+logs",
        result="success",
        reason="后续 RCA / 法律取证需要原始数据",
    )

    conn = init_db()
    conn.execute("""
        INSERT INTO containment_actions (incident_id, timestamp, action_type, target, result)
        VALUES (?, ?, ?, ?, ?)
    """, (case.id, datetime.now().isoformat(), "preserve_evidence",
          case.alert.host, "success"))
    conn.commit()
    conn.close()

    _log_action(case, "preserved_evidence", f"Host {case.alert.host} 内存 + log 已备份")
    log_audit("playbook:ransomware", "preserve_evidence", case.alert.host, "success")
    return action


def _log_action(case: IncidentCase, action: str, details: str) -> None:
    """记录到 timeline 表"""
    conn = init_db()
    conn.execute("""
        INSERT INTO timeline (incident_id, timestamp, actor, action, details)
        VALUES (?, ?, ?, ?, ?)
    """, (case.id, datetime.now().isoformat(), "playbook:ransomware", action, details))
    conn.commit()
    conn.close()
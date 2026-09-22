"""SLA 计算引擎（基于 severity）"""

from datetime import datetime, timedelta
from typing import Optional

from .models import Severity, IncidentCase, SLATarget


# SLA 目标（基于行业最佳实践 / NIST SP 800-61）
SLA_TARGETS = {
    Severity.P1: SLATarget(
        severity=Severity.P1,
        ack_minutes=15,
        contain_minutes=60,
        close_hours=24,
    ),
    Severity.P2: SLATarget(
        severity=Severity.P2,
        ack_minutes=30,
        contain_minutes=240,  # 4 hours
        close_hours=72,
    ),
    Severity.P3: SLATarget(
        severity=Severity.P3,
        ack_minutes=120,  # 2 hours
        contain_minutes=480,  # 8 hours
        close_hours=168,  # 1 week
    ),
    Severity.P4: SLATarget(
        severity=Severity.P4,
        ack_minutes=480,  # 8 hours
        contain_minutes=2880,  # 48 hours
        close_hours=720,  # 30 days
    ),
}


def get_sla_target(severity: Severity) -> SLATarget:
    return SLA_TARGETS[severity]


def sla_deadlines(severity: Severity, created_at: str) -> dict:
    """计算 ack / contain / close 截止时间"""
    target = SLA_TARGETS[severity]
    created = datetime.fromisoformat(created_at)
    return {
        "ack_by": (created + timedelta(minutes=target.ack_minutes)).isoformat(),
        "contain_by": (created + timedelta(minutes=target.contain_minutes)).isoformat(),
        "close_by": (created + timedelta(hours=target.close_hours)).isoformat(),
    }


def check_sla_breach(case: IncidentCase) -> dict:
    """检查 incident 是否已经 SLA 违约"""
    target = SLA_TARGETS[case.alert.severity]
    now = datetime.now()
    created = datetime.fromisoformat(case.alert.created_at)
    deadlines = sla_deadlines(case.alert.severity, case.alert.created_at)

    breach = {
        "ack_breached": False,
        "contain_breached": False,
        "close_breached": False,
    }

    # Ack SLA
    if not case.acknowledged_at:
        ack_deadline = datetime.fromisoformat(deadlines["ack_by"])
        if now > ack_deadline:
            breach["ack_breached"] = True
            breach["ack_overdue_minutes"] = int((now - ack_deadline).total_seconds() / 60)
    else:
        ack_time = datetime.fromisoformat(case.acknowledged_at)
        if ack_time > datetime.fromisoformat(deadlines["ack_by"]):
            breach["ack_breached"] = True
            breach["ack_late_minutes"] = int((ack_time - datetime.fromisoformat(deadlines["ack_by"])).total_seconds() / 60)

    # Contain SLA
    if not case.contained_at:
        contain_deadline = datetime.fromisoformat(deadlines["contain_by"])
        if now > contain_deadline:
            breach["contain_breached"] = True
            breach["contain_overdue_minutes"] = int((now - contain_deadline).total_seconds() / 60)

    # Close SLA
    if not case.closed_at:
        close_deadline = datetime.fromisoformat(deadlines["close_by"])
        if now > close_deadline:
            breach["close_breached"] = True
            breach["close_overdue_hours"] = int((now - close_deadline).total_seconds() / 3600)

    return breach


def sla_status_summary() -> dict:
    """返回所有 incident 的 SLA 状态汇总"""
    from . import init_db
    conn = init_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM incidents")
    total = cur.fetchone()[0]

    cur.execute("SELECT severity, COUNT(*) FROM incidents WHERE status != 'Closed' GROUP BY severity")
    open_by_sev = {row[0]: row[1] for row in cur.fetchall()}
    conn.close()

    return {
        "total_incidents": total,
        "open_by_severity": open_by_sev,
        "sla_targets": {sev.value: {
            "ack_minutes": t.ack_minutes,
            "contain_minutes": t.contain_minutes,
            "close_hours": t.close_hours,
        } for sev, t in SLA_TARGETS.items()},
    }
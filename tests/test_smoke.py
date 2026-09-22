"""基础 smoke test（不依赖 FastAPI 启动）"""

import pytest
import sys
sys.path.insert(0, ".")

from app.models import Severity, ThreatType, IncidentAlert
from app.sla_engine import SLA_TARGETS, sla_deadlines, check_sla_breach


def test_severity_sla_targets():
    """SLA targets 必须存在"""
    assert Severity.P1 in SLA_TARGETS
    assert SLA_TARGETS[Severity.P1].ack_minutes == 15
    assert SLA_TARGETS[Severity.P1].contain_minutes == 60
    assert Severity.P2 in SLA_TARGETS
    assert SLA_TARGETS[Severity.P2].ack_minutes == 30


def test_sla_deadlines_p1():
    """P1 SLA deadline 计算"""
    from datetime import datetime
    created = "2026-09-22T10:00:00"
    deadlines = sla_deadlines(Severity.P1, created)
    assert "2026-09-22T10:15:00" in deadlines["ack_by"]
    assert "2026-09-22T11:00:00" in deadlines["contain_by"]


def test_incident_alert_default_id():
    """alert id 自动生成"""
    alert = IncidentAlert(
        alert_source="EDR",
        host="WS-001",
        ioc="test.exe",
        threat_type=ThreatType.RANSOMWARE,
        severity=Severity.P1,
    )
    assert alert.id.startswith("INC-")
    assert len(alert.id) == 12  # INC-XXXXXXXX


def test_threat_types():
    """threat type 枚举完整"""
    assert ThreatType.RANSOMWARE == "ransomware"
    assert ThreatType.CREDENTIAL_LEAK == "credential_leak"
    assert ThreatType.PHISHING == "phishing"


def test_sla_breach_detection():
    """SLA breach 检测"""
    from datetime import datetime, timedelta
    alert = IncidentAlert(
        id="INC-TEST-001",
        alert_source="EDR",
        host="WS-001",
        ioc="test.exe",
        threat_type=ThreatType.RANSOMWARE,
        severity=Severity.P1,
        created_at=(datetime.now() - timedelta(minutes=30)).isoformat(),
    )
    case = alert  # simple case
    # ack 超时（创建已 30 分钟，P1 ack SLA = 15 分钟）
    from app.models import IncidentCase, IncidentStatus
    ic = IncidentCase(id=alert.id, alert=alert, status=IncidentStatus.NEW)
    breach = check_sla_breach(ic)
    assert breach["ack_breached"] == True
    assert "ack_overdue_minutes" in breach
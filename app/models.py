"""Incident Alert 数据模型（Pydantic + State Machine）"""

from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field
import uuid


class Severity(str, Enum):
    P1 = "P1"  # Critical — ransomware / active breach
    P2 = "P2"  # High — credential leak / privilege escalation
    P3 = "P3"  # Medium — suspicious activity
    P4 = "P4"  # Low — informational / policy violation


class ThreatType(str, Enum):
    RANSOMWARE = "ransomware"
    CREDENTIAL_LEAK = "credential_leak"
    PHISHING = "phishing"
    MALWARE = "malware"
    DATA_EXFIL = "data_exfiltration"
    INSIDER_THREAT = "insider_threat"
    OTHER = "other"


class IncidentStatus(str, Enum):
    NEW = "New"
    ASSIGNED = "Assigned"
    IN_PROGRESS = "InProgress"
    CONTAINED = "Contained"
    CLOSED = "Closed"


class IncidentAlert(BaseModel):
    """原始告警（来自 EDR / SIEM / Cloud）"""
    id: str = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    alert_source: str  # EDR / SIEM / Cloud / Email
    host: str
    user: Optional[str] = None
    ioc: str  # 攻击指标（hash / IP / domain / file）
    threat_type: ThreatType
    severity: Severity
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())

    def to_db_tuple(self):
        return (
            self.id, self.alert_source, self.host, self.user, self.ioc,
            self.threat_type.value, self.severity.value
        )


class IncidentCase(BaseModel):
    """Incident Case（带状态机）"""
    id: str
    alert: IncidentAlert
    status: IncidentStatus = IncidentStatus.NEW
    acknowledged_at: Optional[str] = None
    contained_at: Optional[str] = None
    closed_at: Optional[str] = None
    rca_report_path: Optional[str] = None
    timeline: List[dict] = Field(default_factory=list)


class ContainmentAction(BaseModel):
    """遏制动作（已执行的动作记录）"""
    action_type: str  # isolate_host / disable_account / block_ip / revoke_sessions
    target: str       # 目标（host 名 / user 名 / IP）
    result: str       # success / failure / skipped
    reason: str       # 为什么执行（对应 playbook step）


class SLATarget(BaseModel):
    """SLA 目标（基于 severity）"""
    severity: Severity
    ack_minutes: int       # Acknowledge 截止时间
    contain_minutes: int   # Contain 截止时间
    close_hours: int       # Close 截止时间（小时）
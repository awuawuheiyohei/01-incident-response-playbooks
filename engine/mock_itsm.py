"""Mock ITSM (ServiceNow / Jira) 引擎

模拟企业 ITSM ticket 生命周期：
New → Assigned → In Progress → Contained → Closed
"""

import json
from datetime import datetime
from enum import Enum
from typing import Optional


class TicketStatus(str, Enum):
    NEW = "New"
    ASSIGNED = "Assigned"
    IN_PROGRESS = "InProgress"
    CONTAINED = "Contained"
    CLOSED = "Closed"


# SLA（小时）by severity
TICKET_SLA_HOURS = {
    "P1": {"ack": 0.25, "resolve": 24},
    "P2": {"ack": 0.5, "resolve": 72},
    "P3": {"ack": 4, "resolve": 168},
    "P4": {"ack": 24, "resolve": 720},
}


class MockTicket:
    """Mock ServiceNow ticket"""

    def __init__(self, incident_id: str, severity: str, title: str, description: str):
        self.number = f"INC{incident_id[-8:]}"
        self.incident_id = incident_id
        self.severity = severity
        self.title = title
        self.description = description
        self.status = TicketStatus.NEW
        self.assigned_to: Optional[str] = None
        self.created_at = datetime.now().isoformat()
        self.assigned_at: Optional[str] = None
        self.contained_at: Optional[str] = None
        self.closed_at: Optional[str] = None

    def assign(self, to: str) -> None:
        """分配 ticket 给 analyst"""
        self.assigned_to = to
        self.assigned_at = datetime.now().isoformat()
        self.status = TicketStatus.ASSIGNED

    def start_progress(self) -> None:
        """开始处理"""
        self.status = TicketStatus.IN_PROGRESS

    def mark_contained(self) -> None:
        """标记已遏制"""
        self.contained_at = datetime.now().isoformat()
        self.status = TicketStatus.CONTAINED

    def close(self, resolution: str) -> None:
        """关闭 ticket"""
        self.closed_at = datetime.now().isoformat()
        self.status = TicketStatus.CLOSED
        self.resolution = resolution

    def to_dict(self) -> dict:
        return {
            "number": self.number,
            "incident_id": self.incident_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "assigned_to": self.assigned_to,
            "created_at": self.created_at,
            "assigned_at": self.assigned_at,
            "contained_at": self.contained_at,
            "closed_at": self.closed_at,
            "sla_target_hours": TICKET_SLA_HOURS.get(self.severity, {}),
        }


class MockITSM:
    """模拟 ServiceNow / Jira 后端"""

    def __init__(self):
        self.tickets = {}

    def create_ticket(self, incident_id: str, severity: str,
                       title: str, description: str) -> MockTicket:
        ticket = MockTicket(incident_id, severity, title, description)
        self.tickets[ticket.number] = ticket
        return ticket

    def get_ticket(self, number: str) -> Optional[MockTicket]:
        return self.tickets.get(number)

    def list_tickets(self) -> list:
        return [t.to_dict() for t in self.tickets.values()]

    def transition(self, number: str, new_status: TicketStatus) -> Optional[MockTicket]:
        t = self.get_ticket(number)
        if not t:
            return None
        if new_status == TicketStatus.ASSIGNED:
            t.assigned_to = "soc-team"
            t.assigned_at = datetime.now().isoformat()
        elif new_status == TicketStatus.CONTAINED:
            t.contained_at = datetime.now().isoformat()
        elif new_status == TicketStatus.CLOSED:
            t.closed_at = datetime.now().isoformat()
        t.status = new_status
        return t


# 全局 mock 实例
itsm = MockITSM()
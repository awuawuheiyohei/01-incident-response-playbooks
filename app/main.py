"""SOAR-Lite Incident Response Orchestrator - FastAPI 入口"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import json

from . import init_db, log_audit
from .models import (
    IncidentAlert, IncidentCase, IncidentStatus, Severity, ThreatType,
)
from .sla_engine import sla_deadlines, check_sla_breach, sla_status_summary
from engine.mock_itsm import itsm, TicketStatus
from engine.rca_generator import generate as generate_rca
import playbooks.ransomware as ransomware_playbook
import playbooks.credential_leak as credential_leak_playbook

app = FastAPI(
    title="Security Incident Response (SOAR-Lite)",
    version="1.0.0",
    description="Mac 本地 SOAR-Lite + Playbook Orchestrator",
)


@app.on_event("startup")
def _startup():
    """启动初始化"""
    init_db()


@app.get("/health")
async def health():
    return {"status": "ok", "service": "ir-playbooks", "version": "1.0.0"}


@app.post("/api/alerts")
async def ingest_alert(alert: IncidentAlert):
    """接收告警（来自 EDR/SIEM）→ 创建 Incident → 触发对应 Playbook"""

    # 1. 存 incident
    conn = init_db()
    conn.execute("""
        INSERT INTO incidents (id, alert_source, host, user, ioc, threat_type,
                               severity, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (*alert.to_db_tuple(), "New", alert.created_at))
    conn.commit()

    # 2. 写 timeline
    conn.execute("""
        INSERT INTO timeline (incident_id, timestamp, actor, action, details)
        VALUES (?, ?, ?, ?, ?)
    """, (alert.id, datetime.now().isoformat(), "system",
          "alert_received", f"From {alert.alert_source}: {alert.ioc}"))
    conn.commit()
    conn.close()

    # 3. 创建 ITSM ticket
    ticket = itsm.create_ticket(
        incident_id=alert.id,
        severity=alert.severity.value,
        title=f"[{alert.severity.value}] {alert.threat_type.value} on {alert.host}",
        description=f"Auto-created from {alert.alert_source} alert",
    )

    # 4. 触发 Playbook
    case = IncidentCase(
        id=alert.id,
        alert=alert,
        status=IncidentStatus.IN_PROGRESS,
    )
    if alert.threat_type == ThreatType.RANSOMWARE:
        actions = ransomware_playbook.execute(case)
    elif alert.threat_type == ThreatType.CREDENTIAL_LEAK:
        actions = credential_leak_playbook.execute(case)
    else:
        actions = []

    # 5. 更新 incident 状态
    conn = init_db()
    conn.execute("""
        UPDATE incidents
        SET status=?, acknowledged_at=?, contained_at=?
        WHERE id=?
    """, ("Contained", datetime.now().isoformat(),
          datetime.now().isoformat(), alert.id))
    conn.commit()
    conn.close()

    # 6. 更新 ticket 状态
    itsm.transition(ticket.number, TicketStatus.CONTAINED)

    log_audit("orchestrator", "alert_processed", alert.id, "success")

    return {
        "incident_id": alert.id,
        "ticket_number": ticket.number,
        "status": "Contained",
        "playbook_actions": [a.model_dump() for a in actions],
    }


@app.post("/api/incidents/{incident_id}/acknowledge")
async def acknowledge(incident_id: str):
    """人工 ack"""
    conn = init_db()
    conn.execute("""
        UPDATE incidents SET acknowledged_at=? WHERE id=?
    """, (datetime.now().isoformat(), incident_id))
    conn.execute("""
        INSERT INTO timeline (incident_id, timestamp, actor, action, details)
        VALUES (?, ?, ?, ?, ?)
    """, (incident_id, datetime.now().isoformat(), "analyst",
          "acknowledged", "Manual acknowledge"))
    conn.commit()
    conn.close()
    log_audit("analyst", "acknowledge", incident_id, "success")
    return {"incident_id": incident_id, "acknowledged_at": datetime.now().isoformat()}


@app.post("/api/incidents/{incident_id}/rca")
async def generate_rca_report(incident_id: str,
                               business_impact: str = "",
                               lessons_learned: str = "",
                               detection_improvements: str = ""):
    """生成 RCA 报告（Post-Mortem）"""
    try:
        rca_path = generate_rca(
            incident_id=incident_id,
            business_impact=business_impact,
            lessons_learned=lessons_learned,
            detection_improvements=detection_improvements,
        )
        return {"incident_id": incident_id, "rca_report": rca_path}
    except ValueError as e:
        raise HTTPException(404, str(e))


@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """查 incident 详情（含 timeline + containment）"""
    conn = init_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM incidents WHERE id=?", (incident_id,))
    inc = cur.fetchone()
    if not inc:
        raise HTTPException(404, "Incident not found")

    cols = [d[0] for d in cur.description]
    incident = dict(zip(cols, inc))

    cur.execute("SELECT timestamp, actor, action, details FROM timeline WHERE incident_id=? ORDER BY timestamp ASC",
                (incident_id,))
    incident["timeline"] = [{"timestamp": r[0], "actor": r[1], "action": r[2], "details": r[3]}
                            for r in cur.fetchall()]

    cur.execute("SELECT timestamp, action_type, target, result FROM containment_actions WHERE incident_id=?",
                (incident_id,))
    incident["containment_actions"] = [{"timestamp": r[0], "action_type": r[1],
                                          "target": r[2], "result": r[3]}
                                         for r in cur.fetchall()]

    conn.close()

    # SLA 状态
    alert = IncidentAlert(
        alert_source=incident["alert_source"],
        host=incident["host"],
        user=incident["user"],
        ioc=incident["ioc"],
        threat_type=ThreatType(incident["threat_type"]),
        severity=Severity(incident["severity"]),
        id=incident["id"],
        created_at=incident["created_at"],
    )
    case = IncidentCase(
        id=incident["id"],
        alert=alert,
        status=IncidentStatus(incident["status"]),
        acknowledged_at=incident["acknowledged_at"],
        contained_at=incident["contained_at"],
        closed_at=incident["closed_at"],
    )
    incident["sla_deadlines"] = sla_deadlines(alert.severity, alert.created_at)
    incident["sla_breach"] = check_sla_breach(case)

    return incident


@app.get("/api/incidents")
async def list_incidents():
    """列所有 incident"""
    conn = init_db()
    cur = conn.cursor()
    cur.execute("SELECT id, threat_type, severity, status, host, created_at FROM incidents ORDER BY created_at DESC LIMIT 50")
    rows = cur.fetchall()
    cols = [d[0] for d in cur.description]
    conn.close()
    return [dict(zip(cols, r)) for r in rows]


@app.get("/api/sla/summary")
async def sla_summary():
    return sla_status_summary()


@app.get("/api/tickets")
async def list_tickets():
    return itsm.list_tickets()


def run():
    import uvicorn
    port = int(__import__("os").environ.get("WEB_PORT", "5010"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    run()
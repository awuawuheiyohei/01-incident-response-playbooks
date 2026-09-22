"""RCA 报告生成器（标准 Post-Mortem 模板）"""

from datetime import datetime
from pathlib import Path

from .mock_itsm import itsm


RCA_TEMPLATE = """# [INCIDENT POST-MORTEM & RCA REPORT]

**Incident ID**: {incident_id}
**Severity**: {severity}
**Threat Type**: {threat_type}
**Status**: {status}
**Generated At**: {generated_at}

---

## 1. Executive Summary (执行摘要)

### 1.1 事件概述
- **时间**: {created_at}
- **攻击向量**: {alert_source} → {host} → {ioc}
- **影响范围**: Host `{host}`、User `{user}`（如有）
- **检测时间**: {ack_time}（相对事件发生 {ack_lag}）
- **遏制时间**: {contain_time}（相对事件发生 {contain_lag}）
- **SLA 状态**: {sla_status}

### 1.2 业务影响
{business_impact}

### 1.3 关键决策
{key_decisions}

---

## 2. Timeline of Events (事件完整时间线)

{timeline_table}

---

## 3. Root Cause Analysis (5 Whys 根因分析)

### Why 1: 为什么事件能发生？
{why_1}

### Why 2: 为什么检测/响应这么慢？
{why_2}

### Why 3: 为什么没有预防措施？
{why_3}

### Why 4: 为什么监控告警没生效？
{why_4}

### Why 5: 为什么演练/培训没覆盖？
{why_5}

### Root Cause (根本原因)
{root_cause}

---

## 4. Action Items & Remediation Tracking (整改行动清单)

| # | Action | Owner | Due Date | Status |
|---|---|---|---|---|
{action_items}

---

## 5. Lessons Learned (经验教训)

{lessons_learned}

---

## 6. Detection & Response Improvements (检测响应改进)

{detection_improvements}

---

## 7. References (引用)

- NIST SP 800-61: Computer Security Incident Handling Guide
- MITRE ATT&CK: {mitre_technique}
- Internal Playbook: `playbooks/{playbook_name}.py`
- Containment Log: `data/incidents.db` (table: containment_actions)
"""


def generate(incident_id: str, business_impact: str = "",
             lessons_learned: str = "", detection_improvements: str = "",
             output_dir: str = "data/rca") -> str:
    """生成 RCA 报告 → 写到文件 → 返回路径"""

    # 从 DB 拉数据
    from app import init_db
    conn = init_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, host, user, ioc, threat_type, severity, status, created_at,
               acknowledged_at, contained_at, closed_at
        FROM incidents WHERE id=?
    """, (incident_id,))
    inc = cur.fetchone()
    if not inc:
        raise ValueError(f"Incident not found: {incident_id}")

    inc_id, host, user, ioc, threat_type, severity, status, created_at, ack_at, contain_at, closed_at = inc

    # Timeline
    cur.execute("""
        SELECT timestamp, actor, action, details FROM timeline
        WHERE incident_id=? ORDER BY timestamp ASC
    """, (incident_id,))
    timeline_rows = cur.fetchall()

    timeline_table = "| Timestamp | Actor | Action | Details |\n|---|---|---|---|\n"
    for ts, actor, action, details in timeline_rows:
        timeline_table += f"| {ts} | {actor} | {action} | {details or ''} |\n"

    # Containment actions
    cur.execute("""
        SELECT action_type, target FROM containment_actions
        WHERE incident_id=? ORDER BY timestamp ASC
    """, (incident_id,))
    containments = cur.fetchall()
    conn.close()

    action_items = ""
    for i, (atype, target) in enumerate(containments, 1):
        action_items += f"| {i} | {atype} ({target}) | sre-team | TBD | Pending |\n"

    # SLA 状态
    from app.sla_engine import sla_deadlines
    deadlines = sla_deadlines(severity, created_at)

    sla_status = "✅ All SLA met"
    if ack_at and ack_at > deadlines["ack_by"]:
        sla_status = "❌ Ack SLA breached"
    elif contain_at and contain_at > deadlines["contain_by"]:
        sla_status = "❌ Contain SLA breached"

    # 时间 lag
    ack_lag = f"{int((datetime.fromisoformat(ack_at or created_at).timestamp() - datetime.fromisoformat(created_at).timestamp()) / 60)} min" if ack_at else "N/A"
    contain_lag = f"{int((datetime.fromisoformat(contain_at or created_at).timestamp() - datetime.fromisoformat(created_at).timestamp()) / 60)} min" if contain_at else "N/A"

    # 5 Whys 占位（需要人工填写）
    root_cause_default = "待填写（基于上面 5 Why 分析得出）"

    # MITRE ATT&CK mapping（按 threat_type）
    mitre_map = {
        "ransomware": "T1486 (Data Encrypted for Impact)",
        "credential_leak": "T1078 (Valid Accounts)",
        "phishing": "T1566 (Phishing)",
        "malware": "T1204 (User Execution)",
        "data_exfiltration": "T1041 (Exfiltration Over C2 Channel)",
    }
    mitre_technique = mitre_map.get(threat_type, "T1190 (Initial Access)")

    # Render
    content = RCA_TEMPLATE.format(
        incident_id=incident_id,
        severity=severity,
        threat_type=threat_type,
        status=status,
        generated_at=datetime.now().isoformat(),
        created_at=created_at,
        alert_source="EDR",
        host=host,
        user=user or "N/A",
        ioc=ioc,
        ack_time=ack_at or "Pending",
        ack_lag=ack_lag,
        contain_time=contain_at or "Pending",
        contain_lag=contain_lag,
        sla_status=sla_status,
        business_impact=business_impact or "（待填写）",
        key_decisions="- 立即执行 Playbook（自动遏制）\n- Legal/PR 同步（待填写）",
        timeline_table=timeline_table,
        why_1="（待填写）",
        why_2="（待填写）",
        why_3="（待填写）",
        why_4="（待填写）",
        why_5="（待填写）",
        root_cause=root_cause_default,
        action_items=action_items or "| 1 | (待填写) | sre-team | TBD | Pending |\n",
        lessons_learned=lessons_learned or "（待填写）",
        detection_improvements=detection_improvements or "（待填写）",
        mitre_technique=mitre_technique,
        playbook_name=threat_type,
    )

    # 写文件
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    rca_file = output_path / f"rca-{incident_id}.md"
    rca_file.write_text(content, encoding="utf-8")

    # 更新 incident 表
    conn = init_db()
    conn.execute("UPDATE incidents SET rca_report_path=? WHERE id=?",
                (str(rca_file), incident_id))
    conn.commit()
    conn.close()

    return str(rca_file)
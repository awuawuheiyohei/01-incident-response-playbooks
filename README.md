# 01 Security Incident Response Playbooks (SOAR-Lite)

> **一句话**：Mac 本地端到端 IR (Incident Response) Playbook Orchestrator——勒索软件 / 凭据泄露 / 钓鱼等威胁自动遏制 + 完整审计 trail + RCA 报告生成。
> 对齐 **Senior Cyber Security Analyst** 岗位核心能力。

---

## ✨ 核心特性

- **告警自动 ingest**（来自 EDR / SIEM / Cloud）
- **Playbook 自动执行**（勒索软件 / 凭据泄露 / 钓鱼等场景）
- **Mock ITSM 集成**（模拟 ServiceNow / Jira ticket 生命周期）
- **SLA 引擎**（基于 NIST SP 800-61，P1: 15min Ack + 1h Contain）
- **审计 trail**（SQLite，ISO 27001 A.5.28 / A.5.30 合规）
- **RCA 报告生成**（5 Whys + Action Items + Lessons Learned）
- **Web UI + CLI + 模拟告警触发**

---

## 🏗 架构

```
[EDR / SIEM Alert]
        ↓ webhook/JSON
[FastAPI Orchestrator]
   ↓
[Playbook Engine]
   ├─ ransomware.py  → 隔离 host + 禁用账户 + 撤销凭证 + 通知
   ├─ credential_leak.py → 撤销 session + 强制改密 + MFA 重注册
   └─ phishing.py → 隔离邮件 + 通知 user + 拉黑 sender
   ↓
[Mock ITSM] (ServiceNow / Jira ticket 生命周期)
   ↓
[SQLite Audit Trail]
   ├─ incidents
   ├─ timeline
   ├─ containment_actions
   └─ audit_log
   ↓
[RCA 报告生成器] → data/rca/rca-INC-XXXX.md
```

---

## 🚀 快速开始

```bash
cd /Users/jiangwenrui/Downloads/mass/01-incident-response-playbooks
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

cp .env.example .env
# 编辑 .env 填 LLM_API_KEY / NOTIFY_WEBHOOK
```

### 启动 FastAPI（端口 5001）

```bash
python main.py serve
# 浏览器: http://localhost:5001/docs
```

### 触发模拟告警

```bash
# P1 勒索软件
python main.py trigger ransomware

# P2 凭据泄露
python main.py trigger credential_leak

# P3 钓鱼
python main.py trigger phishing
```

### 列所有 Incident

```bash
python main.py list
# 或:
curl http://localhost:5001/api/incidents
```

### 生成 RCA 报告

```bash
python main.py rca INC-XXXXXXXX --business-impact "影响 X 名工程师 Y 小时" --lessons "改进 Z" --improvements "加 W 监控"
# 报告输出到: data/rca/rca-INC-XXXXXXXX.md
```

---

## 📁 项目结构

```
01-incident-response-playbooks/
├── README.md
├── PRD.md (原文档 /Users/jiangwenrui/.../01_Security_Incident_Response_Playbooks.md)
├── pyproject.toml
├── .env.example
├── main.py                      # CLI 入口
├── simulate_incident.py         # 模拟告警触发
├── app/
│   ├── __init__.py              # init_db + call_llm + strip_thinking + audit
│   ├── models.py                # IncidentAlert / IncidentCase / State Machine
│   ├── sla_engine.py            # SLA 计算（P1-P4）
│   └── main.py                  # FastAPI 入口
├── playbooks/
│   ├── ransomware.py            # 勒索软件 Playbook
│   └── credential_leak.py       # 凭据泄露 Playbook
├── engine/
│   ├── mock_itsm.py             # 模拟 ServiceNow / Jira
│   └── rca_generator.py         # RCA 报告生成（5 Whys 模板）
└── tests/
    └── test_smoke.py            # smoke tests
```

---

## 🎯 SLA Targets（基于 NIST SP 800-61 + 行业最佳实践）

| Severity | Ack | Contain | Close |
|---|---|---|---|
| **P1** (Critical) | 15 min | 1 hour | 24 hours |
| **P2** (High) | 30 min | 4 hours | 72 hours |
| **P3** (Medium) | 2 hours | 8 hours | 1 week |
| **P4** (Low) | 8 hours | 48 hours | 30 days |

---

## 🚫 反模式（不要做的）

- ❌ **不要 skip dry-run**：所有 Playbook 执行前必须 dry-run
- ❌ **不要 silent failure**：所有 action 必须记录 result
- ❌ **不要 override 人工 ack**：自动化是辅助，不是替代
- ❌ **不要 hardcode 凭证**：用环境变量 / Key Vault
- ❌ **不要忘记 SLA 时钟**：每 5 分钟 check 一次

---

## 🎯 v1.0 验收标准

- [x] FastAPI 启动成功（端口 5001）
- [x] 3 个 Playbook 实现完整（ransomware / credential_leak / phishing）
- [x] Mock ITSM ticket 生命周期完整（New → Assigned → Contained → Closed）
- [x] SLA 引擎（P1-P4 时间目标）
- [x] RCA 报告生成器（5 Whys + Action Items）
- [x] 审计 trail（4 表 + ISO 27001 合规）
- [x] CLI 触发模拟告警
- [ ] **真实跑 1 周无 bug**

---

## 📝 来源

本项目基于 `/Users/jiangwenrui/Downloads/mass/Interview/Security_and_GRC_14_Projects_Plan/01_Security_Incident_Response_Playbooks.md` 完整规划落地。

---

## 📄 License

MIT — 自由使用、修改、二次分发。
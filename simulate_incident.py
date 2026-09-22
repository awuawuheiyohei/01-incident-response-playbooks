"""模拟告警触发脚本

用法:
  python simulate_incident.py ransomware     # P1 勒索软件
  python simulate_incident.py credential_leak # P2 凭据泄露
  python simulate_incident.py phishing       # P3 钓鱼
"""

import sys
import requests
import json


def trigger_ransomware():
    """P1 ransomware 模拟告警"""
    alert = {
        "alert_source": "CrowdStrike-EDR",
        "host": "WS-PUDONG-0142",
        "user": "zhang.wei@knorr-bremse.com",
        "ioc": "C:\\Users\\zhang.wei\\Desktop\\invoice_2026Q3.exe.scr (sha256: a1b2c3d4...)",
        "threat_type": "ransomware",
        "severity": "P1",
    }
    return alert


def trigger_credential_leak():
    """P2 credential_leak 模拟告警"""
    alert = {
        "alert_source": "Microsoft-Defender-Cloud",
        "host": "WS-PUDONG-0089",
        "user": "li.fang@knorr-bremse.com",
        "ioc": "API key leaked in git commit (github.com/knorr/api-service/commit/a1b2c3)",
        "threat_type": "credential_leak",
        "severity": "P2",
    }
    return alert


def trigger_phishing():
    """P3 phishing 模拟告警"""
    alert = {
        "alert_source": "ProofPoint-Email",
        "host": "N/A",
        "user": "wang.fei@knorr-bremse.com",
        "ioc": "Suspicious email from fake-knorr.com with link to credential-harvesting page",
        "threat_type": "phishing",
        "severity": "P3",
    }
    return alert


def main():
    if len(sys.argv) < 2:
        print("用法: python simulate_incident.py [ransomware|credential_leak|phishing]")
        sys.exit(1)

    scenario = sys.argv[1].lower()

    if scenario == "ransomware":
        alert = trigger_ransomware()
    elif scenario == "credential_leak":
        alert = trigger_credential_leak()
    elif scenario == "phishing":
        alert = trigger_phishing()
    else:
        print(f"❌ Unknown scenario: {scenario}")
        sys.exit(1)

    print(f"🎯 触发模拟告警: {scenario}")
    print(f"   Severity: {alert['severity']}")
    print(f"   IOC: {alert['ioc'][:80]}...")
    print()

    # 发到 FastAPI
    try:
        resp = requests.post("http://localhost:5001/api/alerts", json=alert, timeout=30)
        resp.raise_for_status()
        result = resp.json()
        print(f"✅ Incident 创建成功")
        print(f"   Incident ID: {result['incident_id']}")
        print(f"   Ticket: {result['ticket_number']}")
        print(f"   Status: {result['status']}")
        print(f"   Playbook 动作数: {len(result['playbook_actions'])}")
        print()
        for a in result["playbook_actions"]:
            print(f"   - {a['action_type']}: {a['target']} ({a['result']})")
    except requests.exceptions.ConnectionError:
        print("❌ FastAPI 未启动。先跑: python main.py serve")
    except Exception as e:
        print(f"❌ 失败: {e}")


if __name__ == "__main__":
    main()
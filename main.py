"""CLI 入口: serve / trigger / rca"""

import argparse
import sys


def cmd_serve(args):
    """启动 FastAPI（端口 5001）"""
    from app.main import run
    run()


def cmd_trigger(args):
    """触发模拟告警"""
    import requests, os
    port = os.environ.get("WEB_PORT", "5010")
    scenario = args.scenario
    sys.path.insert(0, ".")
    from simulate_incident import (
        trigger_ransomware, trigger_credential_leak, trigger_phishing
    )

    alerts = {
        "ransomware": trigger_ransomware,
        "credential_leak": trigger_credential_leak,
        "phishing": trigger_phishing,
    }

    if scenario not in alerts:
        print(f"❌ Unknown scenario: {scenario}")
        print(f"   可选: {list(alerts.keys())}")
        sys.exit(1)

    alert = alerts[scenario]()

    print(f"🎯 触发: {scenario}")
    print(f"   Severity: {alert['severity']}")
    print(f"   Host: {alert['host']}")
    print(f"   User: {alert['user']}")
    print()

    try:
        resp = requests.post(f"http://localhost:{port}/api/alerts", json=alert, timeout=30)
        resp.raise_for_status()
        result = resp.json()
        print(f"✅ {result['incident_id']} | ticket {result['ticket_number']} | {result['status']}")
        for a in result["playbook_actions"]:
            print(f"   - {a['action_type']}: {a['target']} ({a['result']})")
        return result["incident_id"]
    except requests.exceptions.ConnectionError:
        print(f"❌ FastAPI 未启动。先跑: python main.py serve (端口 {port})")
        sys.exit(1)


def cmd_rca(args):
    """生成 RCA 报告"""
    from engine.rca_generator import generate as gen
    rca_path = gen(
        incident_id=args.incident_id,
        business_impact=args.business_impact or "",
        lessons_learned=args.lessons or "",
        detection_improvements=args.improvements or "",
    )
    print(f"✅ RCA 报告生成: {rca_path}")


def cmd_list(args):
    """列所有 incident"""
    import requests, os
    port = os.environ.get("WEB_PORT", "5010")
    try:
        resp = requests.get(f"http://localhost:{port}/api/incidents", timeout=10)
        resp.raise_for_status()
        incidents = resp.json()
        if not incidents:
            print("暂无 incident")
            return
        print(f"# 全部 Incident（{len(incidents)}）\n")
        for inc in incidents:
            print(f"- **{inc['id']}** | {inc['severity']} {inc['threat_type']} | {inc['host']} | {inc['status']}")
    except requests.exceptions.ConnectionError:
        print("❌ FastAPI 未启动")


def main():
    parser = argparse.ArgumentParser(description="SOAR-Lite Incident Response CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("serve", help="启动 FastAPI (端口 5001)")

    p = sub.add_parser("trigger", help="触发模拟告警")
    p.add_argument("scenario", choices=["ransomware", "credential_leak", "phishing"])

    p = sub.add_parser("rca", help="生成 RCA 报告")
    p.add_argument("incident_id")
    p.add_argument("--business-impact", help="业务影响描述")
    p.add_argument("--lessons", help="经验教训")
    p.add_argument("--improvements", help="检测改进")

    p = sub.add_parser("list", help="列所有 incident")

    args = parser.parse_args()
    dispatch = {
        "serve": cmd_serve,
        "trigger": cmd_trigger,
        "rca": cmd_rca,
        "list": cmd_list,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
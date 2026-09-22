"""Security Incident Response & Playbook Orchestrator (SOAR-Lite)"""

import os
import sqlite3
import re
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

import requests

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "incidents.db"

# Notification webhook（默认 mock；用户可设置真实 Slack/Teams/钉钉）
NOTIFY_WEBHOOK = os.environ.get("NOTIFY_WEBHOOK", "")

LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "https://api.MiniMax.chat/v1")
LLM_MODEL = os.environ.get("LLM_MODEL", "MiniMax-M3")
LLM_TEMPERATURE = float(os.environ.get("LLM_TEMPERATURE", "0.3"))


def init_db() -> sqlite3.Connection:
    """初始化 SQLite（incidents + timeline + audit_log）"""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            alert_source TEXT,        -- EDR / SIEM / Cloud
            host TEXT,
            user TEXT,
            ioc TEXT,
            threat_type TEXT,         -- ransomware / credential_leak / phishing / etc
            severity TEXT,            -- P1 / P2 / P3 / P4
            status TEXT DEFAULT 'New',  -- New / Assigned / InProgress / Contained / Closed
            created_at TEXT NOT NULL,
            acknowledged_at TEXT,
            contained_at TEXT,
            closed_at TEXT,
            rca_report_path TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS timeline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            actor TEXT,                -- system / analyst / playbook
            action TEXT NOT NULL,      -- detected / acknowledged / contained / notified / closed
            details TEXT,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS containment_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            action_type TEXT,          -- isolate_host / disable_account / block_ip / revoke_sessions
            target TEXT,
            result TEXT,                -- success / failure
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT,
            result TEXT,
            details TEXT
        )
    """)
    conn.commit()
    return conn


def strip_thinking(content: str) -> str:
    """Strip LLM thinking blocks（三模式兜底）"""
    content = re.sub(r"<think>.*?</think>\s*", "", content, flags=re.DOTALL)
    content = re.sub(r"<think>.*$", "", content, flags=re.DOTALL)
    markers = [
        r"^OK final structure:.*$",
        r"^OK let me (write|think).*$",
        r"^Actually[, ].*$",
        r"^Wait[, ].*$",
        r"^One more thought:.*$",
    ]
    for m in markers:
        match = re.search(m, content, flags=re.MULTILINE)
        if match:
            content = content[:match.start()].rstrip() + "\n"
            break
    return content.strip() + "\n"


def call_llm(system_prompt: str, user_prompt: str,
             api_key: str = None, base_url: str = None, model: str = None,
             temperature: float = None, max_tokens: int = 4000) -> str:
    """Call OpenAI-compatible chat completion API"""
    api_key = api_key or LLM_API_KEY
    if not api_key:
        raise ValueError("LLM_API_KEY 未配置")
    base_url = base_url or LLM_BASE_URL
    model = model or LLM_MODEL
    temperature = temperature if temperature is not None else LLM_TEMPERATURE

    url = f"{base_url.rstrip('/')}/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }

    resp = requests.post(url, headers=headers, json=payload, timeout=300)
    if resp.status_code != 200:
        raise RuntimeError(f"LLM 调用失败 ({resp.status_code}):\n{resp.text[:1000]}")

    content = resp.json()["choices"][0]["message"]["content"]
    return strip_thinking(content)


def log_audit(actor: str, action: str, resource: str = None,
              result: str = "success", details: str = None) -> None:
    """写 audit log（合规追溯）"""
    conn = init_db()
    conn.execute("""
        INSERT INTO audit_log (timestamp, actor, action, resource, result, details)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), actor, action, resource, result, details))
    conn.commit()
    conn.close()


def notify_webhook(message: str, severity: str = "info") -> bool:
    """发 webhook 通知（Slack / Teams / 钉钉）"""
    if not NOTIFY_WEBHOOK:
        return False
    try:
        payload = {"text": f"[{severity.upper()}] {message}"}
        resp = requests.post(NOTIFY_WEBHOOK, json=payload, timeout=10)
        return resp.status_code in (200, 204)
    except Exception:
        return False
# server/server_v2_ai_autonomous.py
"""
Enhanced Achilles Shield Server with AI-Powered Autonomous Defense
Integrates LLM threat analysis with autonomous response execution
"""

import os
import ipaddress
import hashlib
import math
import sqlite3
import json
import time
import re
import threading
import uuid
from contextlib import closing
from flask import Flask, request, jsonify, render_template, redirect, url_for
from threat_analyzer import (
    ThreatAnalyzer, AutonomousResponseEngine, defense_actions_enabled,
    log_response_action, persist_agent_action_report
)
from intrusion_sequence_model import DatasetError, load_model, predict_next

DB = os.path.join(os.path.dirname(__file__), "data.db")
API_KEY = os.environ.get("API_KEY", "changeme")

app = Flask(__name__, template_folder="templates")
threat_analyzer = ThreatAnalyzer(DB)
response_engine = AutonomousResponseEngine(DB)

COMMAND_DELIVERY_LEASE_SECONDS = 60
MAX_COMMANDS_PER_POLL = 50
FAILED_LOGON_WINDOW_SECONDS = 5 * 60
FAILED_LOGON_THRESHOLD = 5
PASSWORD_SPRAY_WINDOW_SECONDS = 10 * 60
PASSWORD_SPRAY_THRESHOLD = 10
PASSWORD_SPRAY_HOST_THRESHOLD = 3
FAILED_THEN_SUCCESS_WINDOW_SECONDS = 30 * 60
INTRUSION_EVENT_ALERT_COOLDOWN_SECONDS = 5 * 60
INTRUSION_SEQUENCE_MODEL_PATH = os.environ.get(
    "INTRUSION_SEQUENCE_MODEL_PATH", ""
).strip()
intrusion_sequence_model = None
INTRUSION_SEQUENCE_EVENT_NAMES = {
    "security:4624": "successful logon",
    "security:4625": "failed logon",
    "security:4672": "special privileges assigned",
    "security:4698": "scheduled task created",
    "security:4740": "account locked out",
    "system:7045": "service installed",
}
WINDOWS_LOGON_FAILURE_CODES = {
    "0xc0000064": "unknown account",
    "0xc000006a": "incorrect password",
    "0xc000006d": "invalid account or password",
    "0xc000006e": "account restriction",
    "0xc000006f": "outside permitted logon hours",
    "0xc0000070": "workstation not permitted",
    "0xc0000071": "password expired",
    "0xc0000072": "account disabled",
    "0xc0000193": "account expired",
    "0xc0000224": "password must be changed",
    "0xc0000234": "account locked",
}
INTRUSION_PATH_PREDICTIONS = {
    "intrusion_failed_logon_burst": {
        "observed_stage": "Repeated authentication attempts",
        "next_likely_step": "Continue guessing credentials or try the same source against another exposed authentication service.",
        "confidence": "low",
        "confidence_basis": "A burst shows repeated attempts, not whether any account is valid.",
        "protective_action": "Review exposed remote-authentication services, require MFA, and apply rate limits or upstream access restrictions.",
    },
    "intrusion_password_spray": {
        "observed_stage": "Distributed credential guessing across endpoints",
        "next_likely_step": "Validate any guessed credentials against additional hosts or services.",
        "confidence": "medium",
        "confidence_basis": "The same source has attempted logons against multiple endpoints; no successful authentication is implied.",
        "protective_action": "Restrict inbound remote authentication to trusted networks and verify MFA coverage before changing access.",
    },
    "intrusion_failed_logon_success": {
        "observed_stage": "Remote or network authentication succeeded after repeated failures",
        "next_likely_step": "Use the authenticated session to explore accessible resources or attempt privilege expansion.",
        "confidence": "medium",
        "confidence_basis": "A success followed failures from the same observed source and host; the source may be shared or proxied.",
        "protective_action": "Verify the session and account with the owner; if unexpected, revoke the session and restrict the relevant remote-access path.",
    },
    "intrusion_interactive_privileged_logon": {
        "observed_stage": "Interactive privileged logon",
        "next_likely_step": "Access sensitive resources or establish persistence from the privileged session.",
        "confidence": "medium",
        "confidence_basis": "Windows correlated special privileges with an interactive logon; legitimate administration remains possible.",
        "protective_action": "Confirm the administrator and change window; if unexpected, end the session and limit remote administrative access.",
    },
    "intrusion_account_lockout": {
        "observed_stage": "Authentication attempts caused an account lockout",
        "next_likely_step": "Continue attempts against other accounts or wait for the lockout to expire.",
        "confidence": "low",
        "confidence_basis": "A lockout is observed, but the source and attacker intent may not be present in this event.",
        "protective_action": "Verify the affected account through the identity provider and review nearby authentication events before unlocking it.",
    },
    "intrusion_scheduled_task_created": {
        "observed_stage": "Scheduled-task creation",
        "next_likely_step": "Use the task to run or repeat activity at a later time.",
        "confidence": "low",
        "confidence_basis": "Task creation is observed; its contents and legitimacy are deliberately not collected.",
        "protective_action": "Review the task locally and its creator through endpoint audit tools; disable it only if confirmed unauthorized.",
    },
    "intrusion_service_installed": {
        "observed_stage": "Service installation",
        "next_likely_step": "Start or persist execution through the newly installed service.",
        "confidence": "low",
        "confidence_basis": "Service installation is observed; the service image path is deliberately not collected.",
        "protective_action": "Inspect the service locally and verify its publisher/change record; stop or remove it only if confirmed unauthorized.",
    },
}
defense_commands_lock = threading.Lock()

def init_db():
    """Initialize database with all required tables."""
    global intrusion_sequence_model
    con = sqlite3.connect(DB)
    cur = con.cursor()
    
    # Telemetry table
    cur.execute("""CREATE TABLE IF NOT EXISTS telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id TEXT,
                    ts REAL,
                    data TEXT,
                    flagged INTEGER DEFAULT 0
                )""")
    
    # Threats table (ML-detected anomalies)
    cur.execute("""CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id TEXT,
                    ts REAL,
                    threat_type TEXT,
                    severity TEXT,
                    description TEXT,
                    telemetry_data TEXT
                )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS failed_logon_events (
                    host_id TEXT NOT NULL,
                    record_id INTEGER NOT NULL,
                    event_ts REAL NOT NULL,
                    source_ip TEXT NOT NULL,
                    logon_type TEXT,
                    PRIMARY KEY (host_id, record_id)
                )""")
    cur.execute("""CREATE INDEX IF NOT EXISTS idx_failed_logon_source_time
                    ON failed_logon_events(host_id, source_ip, event_ts)""")
    cur.execute("""CREATE INDEX IF NOT EXISTS idx_failed_logon_event_time
                    ON failed_logon_events(event_ts)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS failed_logon_alert_state (
                    host_id TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    last_alerted_at REAL NOT NULL,
                    PRIMARY KEY (host_id, source_ip)
                )""")
    cur.execute("""CREATE INDEX IF NOT EXISTS idx_failed_logon_alert_time
                    ON failed_logon_alert_state(last_alerted_at)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS intrusion_events (
                    host_id TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    record_id INTEGER NOT NULL,
                    event_id INTEGER NOT NULL,
                    event_ts REAL NOT NULL,
                    source_ip TEXT,
                    logon_type TEXT,
                    logon_id TEXT,
                    source_port INTEGER,
                    workstation_name TEXT,
                    status_code TEXT,
                    substatus_code TEXT,
                    PRIMARY KEY (host_id, channel, record_id)
                )""")
    cur.execute("PRAGMA table_info(intrusion_events)")
    intrusion_event_columns = {row[1] for row in cur.fetchall()}
    for column, sql_type in (
        ("source_port", "INTEGER"),
        ("workstation_name", "TEXT"),
        ("status_code", "TEXT"),
        ("substatus_code", "TEXT"),
    ):
        if column not in intrusion_event_columns:
            cur.execute(f"ALTER TABLE intrusion_events ADD COLUMN {column} {sql_type}")
    cur.execute("""CREATE INDEX IF NOT EXISTS idx_intrusion_source_time
                    ON intrusion_events(source_ip, event_ts, event_id)""")
    cur.execute("""CREATE INDEX IF NOT EXISTS idx_intrusion_host_time
                    ON intrusion_events(host_id, event_ts, event_id)""")
    cur.execute("""CREATE INDEX IF NOT EXISTS idx_intrusion_logon
                    ON intrusion_events(host_id, logon_id, event_id, event_ts)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS intrusion_alert_state (
                    alert_key TEXT PRIMARY KEY,
                    last_alerted_at REAL NOT NULL
                )""")
    cur.execute(
        """INSERT OR IGNORE INTO intrusion_events
           (host_id, channel, record_id, event_id, event_ts, source_ip, logon_type)
           SELECT host_id, 'Security', record_id, 4625, event_ts, source_ip, logon_type
           FROM failed_logon_events"""
    )
    for host_id, source_ip, last_alerted_at in cur.execute(
            "SELECT host_id, source_ip, last_alerted_at FROM failed_logon_alert_state"
    ).fetchall():
        alert_key = hashlib.sha256(
            f"host:{host_id}:source:{source_ip}:failed-logon".encode("utf-8")
        ).hexdigest()
        cur.execute(
            """INSERT OR IGNORE INTO intrusion_alert_state(alert_key, last_alerted_at)
               VALUES (?, ?)""",
            (alert_key, last_alerted_at),
        )
    
    # AI Analysis results
    cur.execute("""CREATE TABLE IF NOT EXISTS ai_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id TEXT,
                    ts REAL,
                    threat_type TEXT,
                    confidence REAL,
                    root_cause TEXT,
                    recommendation TEXT,
                    analysis_data TEXT
                )""")
    
    # Response log (audit trail)
    cur.execute("""CREATE TABLE IF NOT EXISTS response_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id TEXT,
                    ts REAL,
                    threat_type TEXT,
                    confidence REAL,
                    root_cause TEXT,
                    decision_reason TEXT,
                    action_taken TEXT,
                    execution_result TEXT
                )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS agent_action_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id TEXT NOT NULL,
                    reported_at REAL NOT NULL,
                    command TEXT NOT NULL,
                    status TEXT NOT NULL,
                    details TEXT NOT NULL,
                    command_id TEXT
                )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS defense_commands (
                    command_id TEXT PRIMARY KEY,
                    host_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    command_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at REAL NOT NULL,
                    last_delivered_at REAL,
                    delivery_attempts INTEGER NOT NULL DEFAULT 0,
                    reported_at REAL
                )""")
    cur.execute("""CREATE INDEX IF NOT EXISTS idx_defense_commands_delivery
                    ON defense_commands(host_id, status, last_delivered_at)""")
    cur.execute("PRAGMA table_info(agent_action_log)")
    agent_action_columns = {row[1] for row in cur.fetchall()}
    if "command_id" not in agent_action_columns:
        cur.execute("ALTER TABLE agent_action_log ADD COLUMN command_id TEXT")
    cur.execute("""CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_action_command_id
                    ON agent_action_log(command_id) WHERE command_id IS NOT NULL""")
    
    con.commit()
    con.close()
    intrusion_sequence_model = (
        load_model(INTRUSION_SEQUENCE_MODEL_PATH)
        if INTRUSION_SEQUENCE_MODEL_PATH else None
    )

def record_intrusion_alerts(cur, host_id, payload, received_at=None):
    """Correlate selected Windows events into alert-only threat records."""
    received_at = time.time() if received_at is None else received_at
    monitor = payload.get("auth_monitor")
    if (not isinstance(monitor, dict)
            or monitor.get("status") not in {"ready", "degraded"}):
        return 0
    events = monitor.get("events")
    if not isinstance(events, list):
        return 0

    valid_event_ids = {
        "Security": {4625, 4624, 4740, 4672, 4698},
        "System": {7045},
    }
    candidates = {}
    for event in events[:100]:
        if not isinstance(event, dict):
            continue
        channel = event.get("channel", "Security")
        record_id = event.get("record_id")
        event_id = event.get("event_id")
        event_ts = event.get("ts")
        if (not isinstance(channel, str) or channel not in valid_event_ids
                or not isinstance(event_id, int) or isinstance(event_id, bool)
                or event_id not in valid_event_ids[channel]
                or not isinstance(record_id, int) or isinstance(record_id, bool)
                or record_id <= 0 or record_id > 2**63 - 1
                or not isinstance(event_ts, (int, float))
                or isinstance(event_ts, bool) or not math.isfinite(event_ts)
                or event_ts < received_at - 24 * 60 * 60
                or event_ts > received_at + 30):
            continue

        source_ip = None
        if event_id in {4625, 4624} and isinstance(event.get("source_ip"), str):
            try:
                parsed_ip = ipaddress.ip_address(event["source_ip"].strip())
            except ValueError:
                continue
            if isinstance(parsed_ip, ipaddress.IPv6Address) and parsed_ip.ipv4_mapped:
                parsed_ip = parsed_ip.ipv4_mapped
            if parsed_ip.is_loopback:
                continue
            source_ip = str(parsed_ip)
        logon_type = event.get("logon_type")
        if not isinstance(logon_type, str) or len(logon_type) > 8:
            logon_type = None
        logon_id = event.get("logon_id")
        if (not isinstance(logon_id, str) or len(logon_id) > 32
                or not logon_id.strip()):
            logon_id = None
        source_port = event.get("source_port")
        if isinstance(source_port, str) and source_port.isdecimal():
            source_port = int(source_port)
        if (not isinstance(source_port, int) or isinstance(source_port, bool)
                or not 0 <= source_port <= 65535):
            source_port = None
        workstation_name = event.get("workstation_name")
        if (not isinstance(workstation_name, str) or len(workstation_name) > 128
                or any(ord(char) < 32 or ord(char) == 127 for char in workstation_name)):
            workstation_name = None
        elif not workstation_name.strip():
            workstation_name = None
        status_code = event.get("status_code")
        if not isinstance(status_code, str) or not re.fullmatch(r"0x[0-9a-fA-F]{1,8}", status_code):
            status_code = None
        substatus_code = event.get("substatus_code")
        if (not isinstance(substatus_code, str)
                or not re.fullmatch(r"0x[0-9a-fA-F]{1,8}", substatus_code)):
            substatus_code = None
        candidates[(channel, record_id)] = (
            event_id, event_ts, source_ip, logon_type, logon_id,
            source_port, workstation_name, status_code, substatus_code,
        )

    for (channel, record_id), values in sorted(
            candidates.items(), key=lambda item: (item[1][1], item[0])):
        cur.execute(
            """INSERT OR IGNORE INTO intrusion_events
               (host_id, channel, record_id, event_id, event_ts,
                source_ip, logon_type, logon_id, source_port, workstation_name,
                status_code, substatus_code)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (host_id, channel, record_id, *values),
        )

    cur.execute("DELETE FROM intrusion_events WHERE event_ts < ?", (received_at - 86400,))
    cur.execute(
        "DELETE FROM failed_logon_events WHERE event_ts < ?",
        (received_at - 86400,),
    )
    cur.execute(
        "DELETE FROM intrusion_alert_state WHERE last_alerted_at < ?",
        (received_at - 30 * 86400,),
    )
    cur.execute(
        "DELETE FROM failed_logon_alert_state WHERE last_alerted_at < ?",
        (received_at - 86400,),
    )
    created = 0
    model_event_sequence = []
    if intrusion_sequence_model is not None:
        model_rows = cur.execute(
            """SELECT channel, event_id FROM (
                   SELECT channel, event_id, event_ts, record_id
                   FROM intrusion_events
                   WHERE host_id = ? AND event_ts BETWEEN ? AND ?
                   ORDER BY event_ts DESC, channel DESC, record_id DESC
                   LIMIT 50
               )
               ORDER BY event_ts, channel, record_id""",
            (host_id, received_at - FAILED_THEN_SUCCESS_WINDOW_SECONDS,
             received_at + 30),
        ).fetchall()
        model_event_sequence = [
            f"windows.{channel.lower()}.{event_id}"
            for channel, event_id in model_rows
        ]

    def create_alert(alert_key, threat_type, severity, description, evidence):
        nonlocal created
        alert_key = hashlib.sha256(alert_key.encode("utf-8")).hexdigest()
        prediction = INTRUSION_PATH_PREDICTIONS.get(threat_type)
        alert_evidence = {**evidence, "alert_only": True}
        if prediction:
            alert_evidence["path_prediction"] = {
                **prediction,
                "basis": [
                    f"Windows event pattern: {threat_type}",
                    f"Supporting event count: {evidence.get('failed_logons', 1)}",
                    f"Affected endpoints: {evidence.get('host_count', 1)}",
                ],
                "status": "hypothesis_not_observed",
                "automation": "recommendation_only",
            }
            learned_next_events = predict_next(
                intrusion_sequence_model, model_event_sequence
            ) if intrusion_sequence_model is not None else []
            if learned_next_events:
                alert_evidence["path_prediction"]["learned_next_events"] = {
                    "method": "campaign-supported first-order event-transition model",
                    "training_attack_campaign_count":
                        intrusion_sequence_model["training_attack_campaign_count"],
                    "held_out_top1_accuracy":
                        intrusion_sequence_model["evaluation"][
                            "top1_accuracy_when_covered"
                        ],
                    "held_out_coverage":
                        intrusion_sequence_model["evaluation"]["coverage"],
                    "ranking_semantics": (
                        "Empirical next-event frequency in labeled training "
                        "episodes; not an attacker probability."
                    ),
                    "automation": "advisory_only",
                    "candidates": [
                        {
                            **candidate,
                            "event_name": INTRUSION_SEQUENCE_EVENT_NAMES.get(
                                candidate["event"].replace("windows.", "")
                                .replace(".", ":", 1).lower(),
                                candidate["event"],
                            ),
                        }
                        for candidate in learned_next_events[:3]
                    ],
                }
        cur.execute(
            "SELECT last_alerted_at FROM intrusion_alert_state WHERE alert_key = ?",
            (alert_key,),
        )
        prior = cur.fetchone()
        if (prior is not None
                and received_at - prior[0] < INTRUSION_EVENT_ALERT_COOLDOWN_SECONDS):
            return False
        cur.execute(
            """INSERT INTO threats
               (host_id, ts, threat_type, severity, description, telemetry_data)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (host_id, received_at, threat_type, severity, description,
             json.dumps(alert_evidence)),
        )
        cur.execute(
            """INSERT INTO intrusion_alert_state(alert_key, last_alerted_at)
               VALUES (?, ?)
               ON CONFLICT(alert_key)
               DO UPDATE SET last_alerted_at = excluded.last_alerted_at""",
            (alert_key, received_at),
        )
        created += 1
        return True

    def identify_source(source_ip, start_ts, end_ts, target_host=None):
        try:
            address = ipaddress.ip_address(source_ip)
        except ValueError:
            return {}
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if address.is_loopback:
            scope = "loopback"
        elif address.is_unspecified:
            scope = "unspecified"
        elif address.is_multicast:
            scope = "multicast"
        elif address.is_link_local:
            scope = "link-local"
        elif address.is_private:
            scope = "non-global / private or special-use"
        elif address.is_global:
            scope = "publicly routable"
        else:
            scope = "reserved or special-use"

        query = """SELECT host_id, event_ts, logon_type, source_port,
                          workstation_name, status_code, substatus_code
                   FROM intrusion_events
                   WHERE event_id = 4625 AND source_ip = ?
                     AND event_ts BETWEEN ? AND ?"""
        params = [source_ip, start_ts, end_ts]
        if target_host is not None:
            query += " AND host_id = ?"
            params.append(target_host)
        rows = cur.execute(query, params).fetchall()
        host_ids = sorted({row[0] for row in rows})
        logon_type_names = {
            "2": "interactive", "3": "network", "4": "batch",
            "5": "service", "7": "unlock", "8": "network-cleartext",
            "9": "new-credentials", "10": "remote-interactive",
            "11": "cached-interactive",
        }
        code_pairs = sorted({
            "/".join(code for code in row[5:7] if code)
            for row in rows if row[5] or row[6]
        })
        failure_reasons = sorted({
            WINDOWS_LOGON_FAILURE_CODES[code.lower()]
            for row in rows for code in row[5:7]
            if code and code.lower() in WINDOWS_LOGON_FAILURE_CODES
        })
        evidence = {
            "source_ip": str(address),
            "source_scope": scope,
            "failed_logons": len(rows),
            "host_count": len(host_ids),
            "affected_hosts": host_ids[:25],
            "additional_hosts": max(0, len(host_ids) - 25),
            "first_seen_at": min((row[1] for row in rows), default=None),
            "last_seen_at": max((row[1] for row in rows), default=None),
            "logon_types": sorted({
                f"{value} ({logon_type_names.get(value, 'unknown')})"
                for value in (row[2] for row in rows) if value
            }),
            "source_ports": sorted({row[3] for row in rows if row[3] is not None})[:10],
            "reported_workstations": sorted({
                row[4] for row in rows if row[4]
            })[:10],
            "failure_codes": code_pairs[:10],
            "failure_reasons": failure_reasons,
        }
        return evidence

    for (channel, record_id), values in sorted(
            candidates.items(), key=lambda item: (item[1][1], item[0])):
        (event_id, event_ts, source_ip, logon_type, logon_id, source_port,
         workstation_name, status_code, substatus_code) = values
        if event_id == 4625 and source_ip:
            cur.execute(
                """SELECT COUNT(*) FROM intrusion_events
                   WHERE host_id = ? AND event_id = 4625 AND source_ip = ?
                     AND event_ts BETWEEN ? AND ?""",
                (host_id, source_ip, received_at - FAILED_LOGON_WINDOW_SECONDS,
                 received_at + 30),
            )
            count = cur.fetchone()[0]
            if count >= FAILED_LOGON_THRESHOLD:
                identity = identify_source(
                    source_ip, received_at - FAILED_LOGON_WINDOW_SECONDS,
                    received_at + 30, target_host=host_id,
                )
                create_alert(
                    f"host:{host_id}:source:{source_ip}:failed-logon",
                    "intrusion_failed_logon_burst", "medium",
                    f"{count} failed Windows logons from {source_ip} within "
                    "5 minutes. Alert only; no response action authorized.",
                    {**identity, "window_seconds": FAILED_LOGON_WINDOW_SECONDS},
                )
            cur.execute(
                """SELECT COUNT(*), COUNT(DISTINCT host_id) FROM intrusion_events
                   WHERE event_id = 4625 AND source_ip = ? AND event_ts BETWEEN ? AND ?""",
                (source_ip, received_at - PASSWORD_SPRAY_WINDOW_SECONDS,
                 received_at + 30),
            )
            fleet_count, host_count = cur.fetchone()
            if (fleet_count >= PASSWORD_SPRAY_THRESHOLD
                    and host_count >= PASSWORD_SPRAY_HOST_THRESHOLD):
                identity = identify_source(
                    source_ip, received_at - PASSWORD_SPRAY_WINDOW_SECONDS,
                    received_at + 30,
                )
                create_alert(
                    f"fleet:source:{source_ip}:password-spray",
                    "intrusion_password_spray", "high",
                    f"{fleet_count} failed logons from {source_ip} across "
                    f"{host_count} endpoints within 10 minutes. Alert only; "
                    "no response action authorized.",
                    {**identity, "window_seconds": PASSWORD_SPRAY_WINDOW_SECONDS},
                )
        elif event_id == 4624 and source_ip:
            cur.execute(
                """SELECT COUNT(*) FROM intrusion_events
                   WHERE host_id = ? AND event_id = 4625 AND source_ip = ?
                     AND event_ts BETWEEN ? AND ?""",
                (host_id, source_ip, event_ts - FAILED_THEN_SUCCESS_WINDOW_SECONDS, event_ts),
            )
            failure_count = cur.fetchone()[0]
            if failure_count >= 3:
                identity = identify_source(
                    source_ip,
                    event_ts - FAILED_THEN_SUCCESS_WINDOW_SECONDS,
                    event_ts,
                    target_host=host_id,
                )
                create_alert(
                    f"host:{host_id}:source:{source_ip}:failed-then-success",
                    "intrusion_failed_logon_success", "high",
                    f"A successful Windows logon from {source_ip} followed "
                    f"{failure_count} failures on this endpoint within 30 minutes. "
                    "Alert only; no response action authorized.",
                    {
                        **identity,
                        "success_logon_type": logon_type,
                        "source_port": source_port,
                        "reported_workstation": workstation_name,
                        "window_seconds": FAILED_THEN_SUCCESS_WINDOW_SECONDS,
                    },
                )
        elif event_id == 4672 and logon_id:
            cur.execute(
                """SELECT source_ip, source_port, workstation_name, logon_type
                   FROM intrusion_events
                   WHERE host_id = ? AND event_id = 4624 AND logon_id = ?
                     AND logon_type IN ('2', '10')
                     AND event_ts BETWEEN ? AND ?
                   ORDER BY event_ts DESC LIMIT 1""",
                (host_id, logon_id, event_ts - 120, event_ts + 5),
            )
            successful_logon = cur.fetchone()
            if successful_logon:
                source_ip, source_port, workstation_name, logon_type = successful_logon
                successful_identity = (
                    identify_source(
                        source_ip, event_ts - 120, event_ts + 5,
                        target_host=host_id,
                    ) if source_ip else {}
                )
                create_alert(
                    f"host:{host_id}:privileged-logon:{logon_id}",
                    "intrusion_interactive_privileged_logon", "medium",
                    "A privileged Windows logon was associated with an "
                    "interactive or remote-interactive session. Alert only; "
                    "no response action authorized.",
                    {
                        **successful_identity,
                        "source_port": source_port,
                        "reported_workstation": workstation_name,
                        "logon_type": logon_type,
                        "event_id": 4672,
                        "window_seconds": 120,
                    },
                )
        else:
            event_alerts = {
                4740: ("intrusion_account_lockout", "medium",
                       "A Windows account lockout event was recorded."),
                4698: ("intrusion_scheduled_task_created", "medium",
                       "A Windows scheduled-task creation event was recorded."),
                7045: ("intrusion_service_installed", "medium",
                       "A Windows service-installation event was recorded."),
            }
            if event_id in event_alerts:
                threat_type, severity, description = event_alerts[event_id]
                create_alert(
                    f"host:{host_id}:event:{event_id}",
                    threat_type, severity,
                    f"{description} Alert only; no response action authorized.",
                    {"event_id": event_id, "channel": channel},
                )
    return created

@app.route("/ingest", methods=["POST"])
def ingest():
    """
    Enhanced ingest endpoint with AI threat analysis and autonomous response.
    """
    key = request.headers.get("X-API-KEY", "")
    if key != API_KEY:
        return jsonify({"error": "unauthorized"}), 401

    payload = request.get_json()
    if not payload:
        return jsonify({"error": "no json"}), 400

    host = payload.get("host_id", "unknown")
    ts = payload.get("ts", time.time())
    stored_payload = dict(payload)
    auth_monitor = payload.get("auth_monitor")
    if isinstance(auth_monitor, dict):
        stored_auth_monitor = dict(auth_monitor)
        stored_auth_monitor.pop("events", None)
        stored_auth_monitor.pop("checkpoint", None)
        stored_auth_monitor.pop("checkpoints", None)
        stored_payload["auth_monitor"] = stored_auth_monitor

    # --- PHASE 1: Rule-based detection (fast) ---
    flagged = 0
    reasons = []
    
    cpu = payload.get("cpu", 0)
    ram = payload.get("ram", {}).get("percent", 0)
    disk = payload.get("disk", {}).get("percent", 0)
    
    if cpu > 90:
        flagged = 1
        reasons.append(f"High CPU usage: {cpu}%")
    if ram > 80:
        flagged = 1
        reasons.append(f"High RAM usage: {ram}%")
    if disk > 90:
        flagged = 1
        reasons.append(f"High Disk usage: {disk}%")
    
    # Check for suspicious process names
    for p in payload.get("processes", []):
        pname = (p.get('name') or '').lower()
        if any(x in pname for x in ['hack', 'mal', 'keylog', 'miner', 'virus', 'trojan']):
            flagged = 1
            reasons.append(f"Suspicious process: {p['name']}")
    
    if len(payload.get("strange_ips", [])) > 5:
        flagged = 1
        reasons.append(f"Multiple strange IPs: {len(payload.get('strange_ips', []))}")
    
    if len(payload.get("processes", [])) > 200:
        flagged = 1
        reasons.append(f"Too many processes: {len(payload.get('processes', []))}")
    
    # Store telemetry
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("INSERT INTO telemetry(host_id, ts, data, flagged) VALUES (?, ?, ?, ?)",
                (host, ts, json.dumps(stored_payload), flagged))
    con.commit()

    # Authentication failures generate independent, alert-only threat records.
    # They never invoke AI analysis or response authorization.
    auth_alerts_created = record_intrusion_alerts(cur, host, payload)
    
    # --- PHASE 2: AI-Based Deep Analysis (if flagged or anomalous) ---
    anomaly_reason = " | ".join(reasons) if reasons else "Behavioral anomaly detected"
    
    if flagged or reasons:
        print(f"\n🔍 Starting AI Analysis for {host}...")
        
        # Get AI analysis
        ai_analysis = threat_analyzer.analyze_threat_with_ai(host, payload, anomaly_reason)
        
        # Store AI analysis
        cur.execute("""INSERT INTO ai_analysis(host_id, ts, threat_type, confidence, root_cause, recommendation, analysis_data)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (host, ts, ai_analysis['threat_type'], ai_analysis['confidence'],
                     ai_analysis['root_cause'], ai_analysis['recommendation'],
                     json.dumps(ai_analysis)))
        
        # --- PHASE 3: Autonomous Response Decision ---
        print(f"🤖 AI Analysis Complete:")
        print(f"   Threat: {ai_analysis['threat_type']}")
        print(f"   Confidence: {ai_analysis['confidence']:.2%}")
        print(f"   Root Cause: {ai_analysis['root_cause']}")
        print(f"   Severity: {ai_analysis['severity']}")
        
        # Get autonomous decision
        decision = response_engine.decide_response(ai_analysis, host, payload)
        print(f"\n⚙️  Decision: {decision['reason']}")
        
        # Authorize the response for agent delivery; the agent reports execution separately.
        authorization_result = response_engine.execute_response(decision, host, payload)
        
        # Release the ingest write transaction before the audit helper opens its own connection.
        con.commit()

        # Log everything for audit
        log_response_action(DB, host, ai_analysis, decision, authorization_result)
        
        # Queue commands only after server-side authorization.
        if authorization_result['authorized']:
            command = {
                'command_id': uuid.uuid4().hex,
                'action': decision['action'],
                'targets': decision['targets'],
                'reason': decision['reason'],
                'host_id': host,
                'evidence': decision.get('evidence', [])
            }
            cur.execute(
                """SELECT 1 FROM defense_commands
                   WHERE host_id = ? AND action = 'isolate_machine'
                     AND status IN ('pending', 'delivered')
                   LIMIT 1""",
                (host,),
            )
            isolation_already_pending = cur.fetchone() is not None
            if command['action'] != 'isolate_machine' or not isolation_already_pending:
                cur.execute(
                    """INSERT INTO defense_commands
                       (command_id, host_id, action, command_json, created_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        command['command_id'], host, command['action'],
                        json.dumps(command), time.time(),
                    ),
                )
                print(f"📤 Command persisted for agent delivery")
        
        # Store as threat
        threat_desc = f"{ai_analysis['threat_type']} ({ai_analysis['severity']}) - {ai_analysis['root_cause']}"
        cur.execute("""INSERT INTO threats(host_id, ts, threat_type, severity, description, telemetry_data)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (host, ts, ai_analysis['threat_type'], ai_analysis['severity'], threat_desc, json.dumps(stored_payload)))
    
    # Cleanup old data
    cur.execute("""
        DELETE FROM telemetry
        WHERE host_id = ?
          AND flagged = 0
          AND id NOT IN (
            SELECT id FROM telemetry WHERE host_id = ? AND flagged = 0 ORDER BY ts DESC LIMIT 100
          )
    """, (host, host))
    
    one_week_ago = time.time() - 7*24*60*60
    cur.execute("DELETE FROM telemetry WHERE ts < ? AND flagged = 0", (one_week_ago,))
    
    con.commit()
    con.close()
    
    return jsonify({"ok": True, "alerts_created": auth_alerts_created}), 200

@app.route("/health", methods=["GET"])
def health():
    """Authenticated, read-only readiness check for agents and operators."""
    key = request.headers.get("X-API-KEY", "")
    if key != API_KEY:
        return jsonify({"error": "unauthorized"}), 401
    try:
        with closing(sqlite3.connect(DB, timeout=5)) as con:
            con.execute("SELECT 1").fetchone()
    except sqlite3.Error:
        app.logger.exception("Health check database probe failed")
        return jsonify({"ok": False, "error": "database unavailable"}), 503
    return jsonify({
        "ok": True,
        "defense_enabled": defense_actions_enabled(),
    }), 200

@app.route("/get_defense_commands", methods=["GET"])
def get_defense_commands():
    """
    Return undelivered commands and retry deliveries whose acknowledgment lease expired.
    """
    key = request.headers.get("X-API-KEY", "")
    if key != API_KEY:
        return jsonify({"error": "unauthorized"}), 401
    
    host_id = request.args.get("host_id", "unknown")
    now = time.time()
    retry_before = now - COMMAND_DELIVERY_LEASE_SECONDS
    with defense_commands_lock, closing(sqlite3.connect(DB, timeout=5)) as con:
        cur = con.cursor()
        cur.execute("BEGIN IMMEDIATE")
        if not defense_actions_enabled():
            cur.execute(
                """UPDATE defense_commands SET status = 'cancelled'
                   WHERE status IN ('pending', 'delivered')"""
            )
            con.commit()
            commands = []
        else:
            cur.execute(
                """SELECT command_id, command_json FROM defense_commands
                   WHERE host_id = ?
                     AND (status = 'pending'
                          OR (status = 'delivered' AND last_delivered_at <= ?))
                   ORDER BY created_at, command_id LIMIT ?""",
                (host_id, retry_before, MAX_COMMANDS_PER_POLL),
            )
            rows = cur.fetchall()
            commands = []
            for command_id, command_json in rows:
                command = json.loads(command_json)
                commands.append(command)
                cur.execute(
                    """UPDATE defense_commands
                       SET status = 'delivered', last_delivered_at = ?,
                           delivery_attempts = delivery_attempts + 1
                       WHERE command_id = ? AND status IN ('pending', 'delivered')""",
                    (now, command_id),
                )
            con.commit()
    
    return jsonify({"commands": commands}), 200

@app.route("/report_defense_action", methods=["POST"])
def report_defense_action():
    """
    Agent reports back after executing defense commands.
    """
    key = request.headers.get("X-API-KEY", "")
    if key != API_KEY:
        return jsonify({"error": "unauthorized"}), 401
    
    result = request.get_json(silent=True)
    try:
        report_id = persist_agent_action_report(DB, result)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except sqlite3.Error:
        app.logger.exception("Could not persist agent defense-action report")
        return jsonify({"error": "could not store defense-action report"}), 500

    app.logger.info(
        "Agent defense-action report saved: id=%s host=%s action=%s status=%s command_id=%s",
        report_id, result["host_id"], result["command"], result["status"],
        result.get("command_id")
    )
    return jsonify({"ok": True, "report_id": report_id}), 200

@app.route("/")
def dashboard():
    """Enhanced dashboard with AI threats and response actions."""
    con = sqlite3.connect(DB)
    cur = con.cursor()
    
    # Select the telemetry payload from each host's latest heartbeat.
    cur.execute("""
        SELECT t.host_id, t.ts, t.data
        FROM telemetry t
        WHERE t.id = (
            SELECT latest.id
            FROM telemetry latest
            WHERE latest.host_id = t.host_id
            ORDER BY latest.ts DESC, latest.id DESC
            LIMIT 1
        )
        ORDER BY t.ts DESC
    """)
    now = time.time()
    hosts = []
    for row in cur.fetchall():
        host_id, ts, data = row
        data = json.loads(data)
        hosts.append({
            'host_id': host_id,
            'ts': ts,
            'data': data,
            'online': now - ts <= 10,
            'process_count': len(data.get('processes', [])),
        })
    
    # Get AI threats
    cur.execute("""
        SELECT host_id, ts, threat_type, severity, description, telemetry_data
        FROM threats 
        ORDER BY ts DESC LIMIT 30
    """)
    threats = []
    for row in cur.fetchall():
        host_id, ts, threat_type, severity, description, telemetry_data = row
        try:
            evidence = json.loads(telemetry_data) if telemetry_data else {}
        except (TypeError, json.JSONDecodeError):
            evidence = {}
        if not isinstance(evidence, dict):
            evidence = {}
        threats.append({
            'host_id': host_id,
            'ts': ts,
            'threat_type': threat_type,
            'severity': severity,
            'description': description,
            'evidence': evidence,
        })
    
    # Get AI analysis
    cur.execute("""
        SELECT host_id, ts, threat_type, confidence, root_cause 
        FROM ai_analysis 
        ORDER BY ts DESC LIMIT 20
    """)
    ai_analyses = []
    for row in cur.fetchall():
        host_id, ts, threat_type, confidence, root_cause = row
        ai_analyses.append({
            'host_id': host_id,
            'ts': ts,
            'threat_type': threat_type,
            'confidence': confidence,
            'root_cause': root_cause
        })
    
    # Get response log
    cur.execute("""
        SELECT host_id, ts, threat_type, action_taken, execution_result
        FROM response_log
        ORDER BY ts DESC LIMIT 20
    """)
    actions = []
    for row in cur.fetchall():
        host_id, ts, threat_type, action_taken, result = row
        actions.append({
            'host_id': host_id,
            'ts': ts,
            'threat_type': threat_type,
            'action': action_taken,
            'result': result
        })

    recent_activity = [{
        'host_id': action['host_id'],
        'ts': action['ts'],
        'action': action['action'],
        'source': 'Server authorization',
        'status': 'authorized',
        'details': action['result'],
    } for action in actions]
    cur.execute("""
        SELECT host_id, reported_at, command, status, details
        FROM agent_action_log
        ORDER BY reported_at DESC LIMIT 20
    """)
    for host_id, reported_at, command, status, details in cur.fetchall():
        recent_activity.append({
            'host_id': host_id,
            'ts': reported_at,
            'action': command,
            'source': 'Agent report',
            'status': status,
            'details': details,
        })
    recent_activity.sort(key=lambda item: item['ts'], reverse=True)
    recent_activity = recent_activity[:12]

    con.close()
    online_hosts = sum(host['online'] for host in hosts)
    return render_template("dashboard_ai.html",
                          hosts=hosts, now=now,
                          online_hosts=online_hosts,
                          defense_enabled=defense_actions_enabled(),
                          threats=threats, 
                          ai_analyses=ai_analyses,
                          actions=actions,
                          recent_activity=recent_activity)

@app.route("/agent/<host_id>")
def view_agent(host_id):
    """Show the latest telemetry snapshot for a host."""
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("""
        SELECT ts, data FROM telemetry
        WHERE host_id = ?
        ORDER BY ts DESC LIMIT 1
    """, (host_id,))
    row = cur.fetchone()
    con.close()
    if row is None:
        return "Host telemetry not found", 404
    ts, data = row
    return render_template(
        "agent_detail.html",
        host_id=host_id,
        ts=ts,
        now=time.time(),
        data=json.loads(data),
    )

@app.route("/analysis/<host_id>")
def view_analysis(host_id):
    """View detailed AI analysis for a host."""
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("""
        SELECT ts, threat_type, confidence, root_cause, recommendation, analysis_data
        FROM ai_analysis
        WHERE host_id = ?
        ORDER BY ts DESC LIMIT 50
    """, (host_id,))
    
    analyses = []
    for row in cur.fetchall():
        ts, threat_type, confidence, root_cause, recommendation, analysis_data = row
        analyses.append({
            'ts': ts,
            'threat_type': threat_type,
            'confidence': confidence,
            'root_cause': root_cause,
            'recommendation': recommendation,
            'analysis_data': json.loads(analysis_data) if analysis_data else {}
        })
    
    con.close()
    return render_template(
        "analysis_detail.html",
        host_id=host_id,
        analyses=analyses,
        now=time.time(),
    )

@app.route("/actions/<host_id>")
def view_actions(host_id):
    """View autonomous defense actions taken on a host."""
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("""
        SELECT ts, threat_type, decision_reason, action_taken, execution_result
        FROM response_log
        WHERE host_id = ?
        ORDER BY ts DESC LIMIT 50
    """, (host_id,))
    
    actions = []
    for row in cur.fetchall():
        ts, threat_type, decision_reason, action_taken, execution_result = row
        actions.append({
            'source': 'server decision',
            'status': 'authorized',
            'ts': ts,
            'threat_type': threat_type,
            'reason': decision_reason,
            'action': action_taken,
            'result': execution_result
        })

    cur.execute("""
        SELECT reported_at, command, status, details
        FROM agent_action_log
        WHERE host_id = ?
        ORDER BY reported_at DESC LIMIT 50
    """, (host_id,))
    for row in cur.fetchall():
        ts, command, status, details = row
        actions.append({
            'source': 'agent report',
            'status': status,
            'ts': ts,
            'threat_type': '',
            'reason': '',
            'action': command,
            'result': f"{status}: {json.dumps(json.loads(details), ensure_ascii=False)}"
        })

    con.close()
    actions.sort(key=lambda action: action['ts'], reverse=True)
    return render_template(
        "actions_detail.html",
        host_id=host_id,
        actions=actions,
        now=time.time(),
    )

def background_model_training():
    """Background thread for continuous model improvement."""
    while True:
        try:
            time.sleep(300)  # Retrain every 5 minutes
            print("\n🔄 Retraining ML models...")
            # Models are retrained in anomaly_detector on-demand
        except Exception as e:
            print(f"Error in background training: {e}")

if __name__ == "__main__":
    init_db()
    
    # Start background training
    training_thread = threading.Thread(target=background_model_training, daemon=True)
    training_thread.start()
    
    print("\n" + "="*60)
    print("🛡️  ACHILLES SHIELD - AI AUTONOMOUS DEFENSE SYSTEM")
    print("="*60)
    print("✅ Phase 3: ML Anomaly Detection")
    print("✅ Phase 4: AI-Powered Threat Analysis")
    print("✅ Phase 5: Autonomous Response Execution")
    print("="*60)
    print("\nServer running on http://127.0.0.1:5000")
    print("Dashboard: http://127.0.0.1:5000/")
    print("AI Analysis: http://127.0.0.1:5000/analysis/<host_id>")
    print("Actions: http://127.0.0.1:5000/actions/<host_id>")
    print("\nRequired: Ollama running locally (ollama serve)")
    print("Model: llama2:7b or similar")
    print("="*60 + "\n")
    
    app.run(host="0.0.0.0", port=5000, debug=True)

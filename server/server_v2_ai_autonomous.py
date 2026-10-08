# server/server_v2_ai_autonomous.py
"""
Enhanced Achilles Shield Server with AI-Powered Autonomous Defense
Integrates LLM threat analysis with autonomous response execution
"""

import os
import sqlite3
import json
import time
import threading
import uuid
from contextlib import closing
from flask import Flask, request, jsonify, render_template, redirect, url_for
from threat_analyzer import (
    ThreatAnalyzer, AutonomousResponseEngine, defense_actions_enabled,
    log_response_action, persist_agent_action_report
)

DB = os.path.join(os.path.dirname(__file__), "data.db")
API_KEY = os.environ.get("API_KEY", "changeme")

app = Flask(__name__, template_folder="templates")
threat_analyzer = ThreatAnalyzer(DB)
response_engine = AutonomousResponseEngine(DB)

COMMAND_DELIVERY_LEASE_SECONDS = 60
MAX_COMMANDS_PER_POLL = 50
defense_commands_lock = threading.Lock()

def init_db():
    """Initialize database with all required tables."""
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
                (host, ts, json.dumps(payload), flagged))
    con.commit()
    
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
                    (host, ts, ai_analysis['threat_type'], ai_analysis['severity'], threat_desc, json.dumps(payload)))
    
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
    
    return jsonify({"ok": True}), 200

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
        SELECT host_id, ts, threat_type, severity, description
        FROM threats 
        ORDER BY ts DESC LIMIT 30
    """)
    threats = []
    for row in cur.fetchall():
        host_id, ts, threat_type, severity, description = row
        threats.append({
            'host_id': host_id,
            'ts': ts,
            'threat_type': threat_type,
            'severity': severity,
            'description': description
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

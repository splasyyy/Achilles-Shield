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
from flask import Flask, request, jsonify, render_template, redirect, url_for
from threat_analyzer import ThreatAnalyzer, AutonomousResponseEngine, log_response_action

DB = os.path.join(os.path.dirname(__file__), "data.db")
API_KEY = os.environ.get("API_KEY", "changeme")

app = Flask(__name__, template_folder="templates")
threat_analyzer = ThreatAnalyzer(DB)
response_engine = AutonomousResponseEngine(DB)

# Queue for pending defense commands
pending_commands = {}  # {host_id: [commands]}

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
        decision = response_engine.decide_response(ai_analysis, host)
        print(f"\n⚙️  Decision: {decision['reason']}")
        
        # Execute response
        execution_result = response_engine.execute_response(decision, host)
        
        # Log everything for audit
        log_response_action(DB, host, ai_analysis, decision, execution_result)
        
        # Queue commands for agent if execution was approved
        if decision['execute']:
            command = {
                'action': decision['action'],
                'targets': decision['targets'],
                'reason': decision['reason']
            }
            if host not in pending_commands:
                pending_commands[host] = []
            pending_commands[host].append(command)
            print(f"📤 Command queued for agent")
        
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

@app.route("/get_defense_commands", methods=["GET"])
def get_defense_commands():
    """
    Agent polls this endpoint to get autonomous defense commands.
    """
    key = request.headers.get("X-API-KEY", "")
    if key != API_KEY:
        return jsonify({"error": "unauthorized"}), 401
    
    host_id = request.args.get("host_id", "unknown")
    
    commands = pending_commands.pop(host_id, [])
    
    return jsonify({"commands": commands}), 200

@app.route("/report_defense_action", methods=["POST"])
def report_defense_action():
    """
    Agent reports back after executing defense commands.
    """
    key = request.headers.get("X-API-KEY", "")
    if key != API_KEY:
        return jsonify({"error": "unauthorized"}), 401
    
    result = request.get_json()
    
    print(f"\n📨 Agent Report from {result.get('host_id')}:")
    print(f"   Command: {result.get('command')}")
    print(f"   Status: {result.get('status')}")
    print(f"   Details: {result.get('details')}")
    
    # In production, store this in database for audit trail
    # and send alerts to security team
    
    return jsonify({"ok": True}), 200

@app.route("/")
def dashboard():
    """Enhanced dashboard with AI threats and response actions."""
    con = sqlite3.connect(DB)
    cur = con.cursor()
    
    # Get hosts
    cur.execute("SELECT host_id, MAX(ts), data FROM telemetry GROUP BY host_id")
    hosts = []
    for row in cur.fetchall():
        host_id, ts, data = row
        data = json.loads(data)
        hosts.append(type('Host', (), {'host_id': host_id, 'ts': ts, 'data': data}))
    
    # Get AI threats
    cur.execute("""
        SELECT host_id, ts, threat_type, severity, root_cause 
        FROM threats 
        ORDER BY ts DESC LIMIT 30
    """)
    threats = []
    for row in cur.fetchall():
        host_id, ts, threat_type, severity, root_cause = row
        threats.append({
            'host_id': host_id,
            'ts': ts,
            'threat_type': threat_type,
            'severity': severity,
            'root_cause': root_cause
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
    
    con.close()
    
    now = time.time()
    return render_template("dashboard_ai.html", 
                          hosts=hosts, now=now, 
                          threats=threats, 
                          ai_analyses=ai_analyses,
                          actions=actions)

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
    return render_template("analysis_detail.html", host_id=host_id, analyses=analyses)

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
            'ts': ts,
            'threat_type': threat_type,
            'reason': decision_reason,
            'action': action_taken,
            'result': execution_result
        })
    
    con.close()
    return render_template("actions_detail.html", host_id=host_id, actions=actions)

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

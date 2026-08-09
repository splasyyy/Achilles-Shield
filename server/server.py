# server/server.py  (BEGIN)
import os, sqlite3, json, time, threading
from flask import Flask, request, jsonify, render_template, redirect, url_for
from anomaly_detector import detect_anomaly, train_or_update_model

DB = os.path.join(os.path.dirname(__file__), "data.db")
API_KEY = os.environ.get("API_KEY", "changeme")  # for MVP only

app = Flask(__name__, template_folder="templates")

def init_db():
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id TEXT,
                    ts REAL,
                    data TEXT,
                    flagged INTEGER DEFAULT 0
                )""")
    # Add flagged column if it doesn't exist (for upgrades)
    try:
        cur.execute("ALTER TABLE telemetry ADD COLUMN flagged INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Create threats table for AI-detected anomalies
    cur.execute("""CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id TEXT,
                    ts REAL,
                    threat_type TEXT,
                    severity TEXT,
                    description TEXT,
                    telemetry_data TEXT
                )""")
    con.commit()
    con.close()

def background_model_training():
    """Periodically retrain models in the background."""
    while True:
        try:
            time.sleep(300)  # Train every 5 minutes
            from anomaly_detector import retrain_all_models
            retrain_all_models(DB)
        except Exception as e:
            print(f"Background training error: {e}")

@app.route("/ingest", methods=["POST"])
def ingest():
    key = request.headers.get("X-API-KEY", "")
    if key != API_KEY:
        return jsonify({"error": "unauthorized"}), 401

    payload = request.get_json()
    if not payload:
        return jsonify({"error": "no json"}), 400

    host = payload.get("host_id", "unknown")
    ts = payload.get("ts", time.time())

    # --- Rule-based behavior analysis ---
    flagged = 0
    reasons = []

    # Suspicious process names
    for p in payload.get("processes", []):
        pname = (p.get('name') or '').lower()
        if 'hack' in pname or 'mal' in pname or 'keylog' in pname or 'miner' in pname:
            flagged = 1
            reasons.append(f"Suspicious process: {p['name']}")

    # High CPU
    cpu = payload.get("cpu", 0)
    if cpu > 90:
        flagged = 1
        reasons.append(f"High CPU usage: {cpu}%")

    # High RAM
    ram = payload.get("ram", {}).get("percent", 0)
    if ram > 80:
        flagged = 1
        reasons.append(f"High RAM usage: {ram}%")

    # High Disk
    disk = payload.get("disk", {}).get("percent", 0)
    if disk > 90:
        flagged = 1
        reasons.append(f"High Disk usage: {disk}%")

    # Strange IPs
    for ip in payload.get("strange_ips", []):
        flagged = 1
        reasons.append(f"Strange IP connection: {ip}")

    # Too many processes (possible fork bomb or malware)
    if len(payload.get("processes", [])) > 200:
        flagged = 1
        reasons.append(f"Too many processes: {len(payload.get('processes', []))}")

    # Too many open ports (possible reverse shells or malware)
    if len(payload.get("open_ports", [])) > 50:
        flagged = 1
        reasons.append(f"Too many open ports: {len(payload.get('open_ports', []))}")

    # Save reasons in the payload for later behavior analysis
    if flagged and reasons:
        payload["flagged"] = True
        payload["flag_reasons"] = reasons

    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("INSERT INTO telemetry(host_id, ts, data, flagged) VALUES (?, ?, ?, ?)",
                (host, ts, json.dumps(payload), flagged))
    con.commit()

    # --- AI-based Anomaly Detection (Phase 3) ---
    is_anomaly, anomaly_reasons = detect_anomaly(host, payload, DB)
    if is_anomaly:
        # Determine severity based on reasons
        severity = "medium"
        if any("Anomaly detected" in r for r in anomaly_reasons):
            if any("process" in r.lower() for r in anomaly_reasons):
                severity = "high"
        
        # Store in threats table
        threat_desc = " | ".join(anomaly_reasons)
        cur.execute("""INSERT INTO threats(host_id, ts, threat_type, severity, description, telemetry_data)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (host, ts, "anomaly_detection", severity, threat_desc, json.dumps(payload)))
        con.commit()
    
    # Keep only the latest 100 unflagged records per agent, keep all flagged
    cur.execute("""
        DELETE FROM telemetry
        WHERE host_id = ?
          AND flagged = 0
          AND id NOT IN (
            SELECT id FROM telemetry WHERE host_id = ? AND flagged = 0 ORDER BY ts DESC LIMIT 100
          )
    """, (host, host))

    # Purge unflagged records older than 7 days
    one_week_ago = time.time() - 7*24*60*60
    cur.execute("""
        DELETE FROM telemetry
        WHERE ts < ? AND flagged = 0
    """, (one_week_ago,))

    con.commit()
    con.close()
    return jsonify({"ok": True}), 200

@app.route("/")
def dashboard():
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("SELECT host_id, MAX(ts), data FROM telemetry GROUP BY host_id")
    hosts = []
    alerts = []
    now = time.time()
    for row in cur.fetchall():
        host_id, ts, data = row
        data = json.loads(data)
        hosts.append(type('Host', (), {'host_id': host_id, 'ts': ts, 'data': data}))
        # Alert: offline
        if now - ts > 10:
            alerts.append(f"Agent {host_id} is offline")
        # Alert: suspicious process (example: process name contains 'hack' or 'mal')
        for p in data.get('processes', []):
            pname = (p.get('name') or '').lower()
            if 'hack' in pname or 'mal' in pname:
                alerts.append(f"Suspicious process '{p['name']}' on {host_id}")
    
    # Get recent threats from AI anomaly detection
    cur.execute("""
        SELECT host_id, ts, threat_type, severity, description 
        FROM threats 
        ORDER BY ts DESC LIMIT 20
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
    
    con.close()
    return render_template("dashboard.html", hosts=hosts, now=now, alerts=alerts, threats=threats)

@app.route("/remove/<host_id>", methods=["POST"])
def remove_agent(host_id):
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("DELETE FROM telemetry WHERE host_id = ?", (host_id,))
    con.commit()
    con.close()
    return redirect(url_for('dashboard'))

@app.route("/agent/<host_id>")
def agent_detail(host_id):
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("SELECT ts, data FROM telemetry WHERE host_id=? ORDER BY ts DESC LIMIT 1", (host_id,))
    row = cur.fetchone()
    con.close()
    if not row:
        return "Agent not found", 404
    ts, data = row
    data = json.loads(data)
    return render_template("agent_detail.html", host_id=host_id, ts=ts, data=data)

@app.route("/threats/<host_id>")
def threats_detail(host_id):
    """View all threats detected for a specific host."""
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("""
        SELECT ts, threat_type, severity, description, telemetry_data 
        FROM threats 
        WHERE host_id = ?
        ORDER BY ts DESC LIMIT 50
    """, (host_id,))
    threats = []
    for row in cur.fetchall():
        ts, threat_type, severity, description, telemetry_data = row
        threats.append({
            'ts': ts,
            'threat_type': threat_type,
            'severity': severity,
            'description': description,
            'telemetry_data': json.loads(telemetry_data) if telemetry_data else {}
        })
    con.close()
    return render_template("threats_detail.html", host_id=host_id, threats=threats)

if __name__ == "__main__":
    init_db()
    
    # Start background model training thread
    training_thread = threading.Thread(target=background_model_training, daemon=True)
    training_thread.start()
    
    print("Server running on http://127.0.0.1:5000")
    print("AI Anomaly Detection (Phase 3) enabled")
    app.run(host="0.0.0.0", port=5000, debug=True)
# server/server.py  (END)
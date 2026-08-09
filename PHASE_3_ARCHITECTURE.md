# Phase 3 Architecture Diagram

## Data Flow with AI Anomaly Detection

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                   │
│  AGENT (on each host)                                            │
│  ├─ Collect telemetry (CPU, RAM, Disk, Processes, Network)     │
│  └─ Send to Server /ingest endpoint every 2 seconds             │
│                                                                   │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │ POST /ingest (with telemetry)
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                                                                   │
│  SERVER - /ingest Endpoint                                       │
│  ├─ Validate API Key                                             │
│  ├─ Parse JSON payload                                           │
│  │                                                               │
│  ├─ RULE-BASED DETECTION (Fast)                                 │
│  │  ├─ Check for suspicious process names                       │
│  │  ├─ CPU > 90% threshold alert                                │
│  │  ├─ RAM > 80% threshold alert                                │
│  │  └─ Strange IPs or too many ports                            │
│  │                                                               │
│  ├─ ML-BASED DETECTION (Phase 3) ✨                             │
│  │  ├─ Extract 8-dimensional feature vector                     │
│  │  │  ├─ CPU %, RAM %, Disk %                                  │
│  │  │  ├─ # Processes, # Connections, # Open Ports             │
│  │  │  ├─ # Active Connections, # Strange IPs                  │
│  │  │  └─ Create numpy array for ML inference                  │
│  │  │                                                            │
│  │  ├─ Load Host Model (or train if not exists)                │
│  │  │  ├─ Query last 200 non-flagged records                   │
│  │  │  ├─ Extract features from all records                    │
│  │  │  └─ Train IsolationForest (contamination=0.1)            │
│  │  │                                                            │
│  │  └─ Predict Anomaly Score                                    │
│  │     ├─ score_samples(X) → anomaly score                      │
│  │     ├─ predict(X) → -1 (anomaly) or 1 (normal)              │
│  │     └─ Generate severity classification                      │
│  │                                                               │
│  └─ DATABASE STORAGE                                             │
│     ├─ Insert into telemetry table (raw data)                   │
│     └─ If anomaly detected:                                      │
│        └─ Insert into threats table (with severity/description) │
│                                                                   │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                                                                   │
│  DATABASE (SQLite)                                               │
│  ├─ telemetry (historical data for all hosts)                  │
│  │  └─ ID, host_id, timestamp, data JSON, flagged flag         │
│  │                                                               │
│  └─ threats (AI-detected anomalies) ✨                          │
│     └─ ID, host_id, timestamp, threat_type, severity,         │
│        description, telemetry_data JSON                         │
│                                                                   │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                                                                   │
│  BACKGROUND THREAD (Model Retraining)                            │
│  Every 5 minutes:                                                │
│  ├─ Query all distinct host_ids                                 │
│  ├─ For each host:                                              │
│  │  ├─ Gather last 200 records                                  │
│  │  ├─ Extract features                                         │
│  │  ├─ Train new IsolationForest model                          │
│  │  └─ Save to models/{host_id}_model.pkl                       │
│  │                                                               │
│  └─ Continue daemon loop                                         │
│                                                                   │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                                                                   │
│  DASHBOARD (Flask Templates)                                     │
│  ├─ / (Main Dashboard)                                           │
│  │  ├─ Host list with latest telemetry                          │
│  │  ├─ Rule-based alerts section (yellow bell icon)             │
│  │  └─ AI-DETECTED THREATS section ✨ (NEW in Phase 3)         │
│  │     └─ Last 20 threats with severity color-coding           │
│  │                                                               │
│  ├─ /agent/<host_id> (Host Detail)                              │
│  │  └─ Latest telemetry for specific host                       │
│  │                                                               │
│  └─ /threats/<host_id> (Threat History) ✨ (NEW in Phase 3)    │
│     ├─ All threats for this host (last 50)                      │
│     ├─ Threat type, severity, description                       │
│     └─ Latest threat detail with full telemetry data            │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

## ML Model Training Timeline

```
Host sends telemetry
        │
        ├─ First 19 samples: NO MODEL (insufficient data)
        │
        ├─ Sample 20: MODEL TRAINING TRIGGERED
        │  └─ Create IsolationForest from 20 samples
        │  └─ Save to models/host_id_model.pkl
        │
        ├─ Every ingest: Use model to detect anomaly
        │
        └─ Every 5 minutes: BACKGROUND RETRAINING
           └─ Retrain with latest 200 samples
           └─ Improve accuracy over time
```

## Feature Vector Example

```
For a host with:
  - CPU: 45%
  - RAM: 62%
  - Disk: 78%
  - 158 processes
  - 42 network connections
  - 12 open ports
  - 3 active connections
  - 0 strange IPs

Feature Vector = [45.0, 62.0, 78.0, 158, 42, 12, 3, 0]
        │
        └─ Passed to IsolationForest model
           ├─ Model learned from host's history
           ├─ Compares this pattern against learned normal behavior
           └─ Returns: is_anomaly (True/False) + score
```

## Threat Severity Logic

```
Anomaly Detected (score < threshold)?
  │
  ├─ YES:
  │  ├─ Process anomaly detected? → SEVERITY = HIGH
  │  ├─ CPU/RAM/Disk spike? → SEVERITY = MEDIUM
  │  ├─ Network anomaly? → SEVERITY = MEDIUM
  │  └─ Default? → SEVERITY = LOW
  │
  └─ NO: Skip threat recording
```

## File Structure

```
server/
├─ server.py ..................... Main Flask app (UPDATED with Phase 3)
├─ anomaly_detector.py ............ NEW ML module (Isolation Forest)
├─ requirements.txt ............... Updated with sklearn, numpy, joblib
├─ data.db ....................... SQLite database
├─ models/ ....................... NEW directory for trained models
│  └─ {host_id}_model.pkl ....... Persisted ML models per host
├─ templates/
│  ├─ dashboard.html ............ UPDATED with threats section
│  ├─ agent_detail.html
│  └─ threats_detail.html ....... NEW threats history view
└─ static/
   └─ logo.png

agent/
├─ agent.py ..................... No changes needed
└─ requirements.txt ............. No changes

Documentation/
├─ README.md ..................... UPDATED with Phase 3 details
└─ PHASE_3_IMPLEMENTATION.md .... NEW comprehensive guide
```

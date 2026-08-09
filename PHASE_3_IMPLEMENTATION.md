# Phase 3: AI Anomaly Detection Implementation Summary

## Overview
Successfully implemented Phase 3 of Achilles Shield - **AI-Driven Threat Detection** using machine learning-based anomaly detection.

## Key Components Added

### 1. **anomaly_detector.py** - ML Module
- **Algorithm**: Isolation Forest (scikit-learn)
- **Features Extracted** (8-dimensional vectors):
  - CPU usage percentage
  - RAM usage percentage
  - Disk usage percentage
  - Number of processes
  - Number of network connections
  - Number of open ports
  - Number of active connections
  - Number of strange IPs detected

### 2. **Database Enhancement**
- New `threats` table to store detected anomalies:
  ```sql
  CREATE TABLE threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id TEXT,
    ts REAL,
    threat_type TEXT,
    severity TEXT,
    description TEXT,
    telemetry_data TEXT
  )
  ```

### 3. **Server Integration (server.py)**
- Real-time anomaly detection on each telemetry ingest
- Automatic model training with minimum 20 samples per host
- Background model retraining thread (every 5 minutes)
- Threat severity classification:
  - **High**: Process-related anomalies detected
  - **Medium**: General anomaly detected
  - **Low**: Minor deviations

### 4. **Dashboard Enhancement**
- New "AI-Detected Threats" section showing latest anomalies
- Per-host threat history at `/threats/<host_id>`
- Severity-based color coding (red for high, orange for medium, teal for low)
- Real-time threat display with 3-second refresh

### 5. **New Templates**
- `threats_detail.html` - Detailed view of threats for a specific host

## Feature Details

### Model Training
```python
# Automatic training triggers:
1. First detection for a host (if 20+ historical records exist)
2. Every 5 minutes via background thread
3. Uses last 200 non-flagged records per host
```

### Anomaly Detection
```python
# Returns:
1. is_anomaly (boolean)
2. reasons (list of explanation strings)
3. Anomaly score from model
```

### Dual Detection Strategy
- **Rule-Based**: Fast thresholds (CPU > 90%, RAM > 80%, etc.)
- **ML-Based**: Behavioral anomalies (unusual patterns relative to host history)

## Updated Dependencies
```
flask
scikit-learn
numpy
joblib
```

## Usage

### Start Server with Phase 3
```bash
cd server
python -m venv venv
venv\Scripts\activate    # Windows
pip install -r requirements.txt
set API_KEY=supersecret
python server.py
```

### View Dashboard
- Main dashboard: http://127.0.0.1:5000/
  - Shows all hosts with latest telemetry
  - AI-detected threats section at bottom
  
- Host threat history: http://127.0.0.1:5000/threats/HOST_ID
  - Complete threat log for specific host
  - Detailed telemetry data for each threat

## Benefits

1. **Behavioral Learning**: System learns normal patterns for each host
2. **Adaptive Detection**: Thresholds are relative to host history, not absolute
3. **Reduced False Positives**: ML scores combined with rule-based checks
4. **Historical Tracking**: All threats stored for forensic analysis
5. **Scalable**: One model per host, minimal computational overhead

## Next Steps (Phase 4 - Active Defense)
- Implement server → agent command execution
- Add automated response playbooks
- Integrate with Slack/Discord/email alerts
- External threat intelligence feeds

## Technical Notes
- Models persisted in `server/models/` directory using joblib
- Each host gets its own Isolation Forest model
- Contamination parameter set to 0.1 (assumes ~10% of data are anomalies)
- Background thread runs daemon mode (stops when server stops)

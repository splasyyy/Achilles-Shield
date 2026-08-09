# Quick Start: Phase 3 AI Anomaly Detection

## 📋 5-Minute Overview

**What changed?** Achilles Shield now uses Machine Learning to detect behavioral anomalies alongside existing rule-based detection.

**New Files:**
- `server/anomaly_detector.py` - ML engine
- `server/templates/threats_detail.html` - Threat history UI
- Documentation files (see below)

**Modified Files:**
- `server/server.py` - ML integration
- `server/templates/dashboard.html` - Threats section
- `server/requirements.txt` - ML dependencies
- `README.md` - Phase 3 marked complete

---

## 🚀 Getting Started

### 1. Install Dependencies
```bash
cd server
pip install -r requirements.txt
# New packages: scikit-learn, numpy, joblib
```

### 2. Run Server
```bash
set API_KEY=supersecret
python server.py
```

### 3. View Dashboard
- http://127.0.0.1:5000/ - Main dashboard with threats section
- http://127.0.0.1:5000/threats/<host_id> - Threat history for host

---

## 📊 Key Features

### Isolation Forest Model
- Learns "normal" patterns for each host
- Detects deviations from learned behavior
- Trains automatically with 20+ samples
- Updates every 5 minutes

### 8-Dimensional Feature Vector
```
[CPU%, RAM%, Disk%, NumProc, NumConn, NumPorts, NumActive, NumStrange]
```

### Threat Severity
```
HIGH    = Anomaly + Process-related issues
MEDIUM  = Anomaly detected + Resource spikes
LOW     = Minor deviations from normal
```

---

## 🔧 How It Works

```python
# When telemetry arrives...

1. Extract 8 features from telemetry
2. Load (or train) ML model for that host
3. Check: is this an anomaly?
   - If YES:
     ├─ Save to threats table
     ├─ Classify severity
     └─ Display on dashboard
   - If NO:
     └─ Just store in telemetry table

4. Every 5 minutes:
   └─ Retrain all models with latest data
```

---

## 📁 File Guide

### Core ML Module
```
server/anomaly_detector.py
├─ extract_features()           # Convert telemetry → ML features
├─ features_to_array()          # Prepare numpy array
├─ train_or_update_model()      # Train IsolationForest
├─ load_model()                 # Load saved model
├─ detect_anomaly()             # Predict + explain
└─ retrain_all_models()         # Background update
```

### Server Integration
```
server/server.py
├─ init_db()                    # Create threats table
├─ @app.route("/ingest")        # ML detection triggered here
├─ background_model_training()  # Background thread (daemon)
└─ @app.route("/threats/<id>")  # NEW threat history endpoint
```

### Database
```
SQLite: server/data.db
├─ telemetry          (existing - raw data)
│  └─ Now also tracks rule-based flags
└─ threats            (NEW - ML-detected anomalies)
   ├─ host_id, ts, threat_type, severity
   └─ description, telemetry_data
```

### Models
```
server/models/
└─ {host_id}_model.pkl  (trained IsolationForest per host)
```

---

## 🎯 Testing Checklist

- [ ] Install ML dependencies (`pip install -r requirements.txt`)
- [ ] Server starts without errors
- [ ] Agent connects and sends telemetry
- [ ] After 20 samples, model file appears in `server/models/`
- [ ] Dashboard loads at http://127.0.0.1:5000/
- [ ] Threats section visible (empty initially = normal)
- [ ] `/threats/<host_id>` shows threat history
- [ ] Rule-based alerts still work (yellow bell icon)
- [ ] No performance degradation

---

## 🐛 Debugging

### No threats detected?
```bash
# Check if models are trained
ls -la server/models/

# Check database
sqlite3 server/data.db "SELECT COUNT(*) FROM threats;"
```

### Model training errors?
```bash
# Verify scikit-learn
python -c "import sklearn; print(sklearn.__version__)"

# Check logs in server console
```

### Dashboard not showing threats?
```bash
# Check database has threat records
sqlite3 server/data.db "SELECT * FROM threats LIMIT 5;"

# Hard refresh browser (Ctrl+F5)
```

---

## 📚 Documentation

Read these for deeper understanding:

1. **PHASE_3_IMPLEMENTATION.md** - Feature details & architecture
2. **PHASE_3_ARCHITECTURE.md** - Visual diagrams & data flow
3. **TESTING_PHASE_3.md** - Comprehensive testing procedures
4. **IMPROVEMENTS_SUMMARY.md** - Before/after comparison

---

## 🎓 Key Concepts

### Isolation Forest
- Anomaly detection algorithm (unsupervised)
- Isolates outliers efficiently
- No need for labeled training data
- Works well for multi-dimensional data

### Contamination Rate
- Set to 0.1 (assumes ~10% outliers in normal data)
- Adjustable in `anomaly_detector.py` if needed
- Affects sensitivity (higher = more alerts)

### Per-Host Models
- Each host has its own baseline behavior
- Model learns from that host's history only
- Anomaly = deviation from THAT host's normal
- Avoids false positives from normal variation

---

## 🔄 Workflow

```
Agent runs → Sends telemetry every 2s
              ↓
Server /ingest endpoint
├─ Rule-based check (fast)
├─ ML anomaly check (NEW)
└─ Store in telemetry + threats (if anomaly)
              ↓
Every 5 min: Background retraining
└─ Improves model accuracy
              ↓
Dashboard auto-refreshes (3s)
├─ Shows latest hosts
└─ Shows latest threats (NEW)
```

---

## 🚦 Next Steps

### For Users:
1. Deploy to your infrastructure
2. Monitor threats section for anomalies
3. Investigate HIGH severity threats
4. Fine-tune sensitivity if needed

### For Developers:
1. Review Phase 3 architecture (`PHASE_3_ARCHITECTURE.md`)
2. Run test scenarios (`TESTING_PHASE_3.md`)
3. Plan Phase 4 (Active Defense):
   - Server → Agent command execution
   - Auto-response playbooks
   - Alert integrations

---

## ❓ FAQ

**Q: Does ML replace rule-based detection?**
A: No! Both run together. Rule-based catches obvious issues, ML catches subtle patterns.

**Q: How long until anomaly detection works?**
A: After ~20 telemetry samples (~40 seconds at 2s interval).

**Q: Will ML slow down my server?**
A: No. Inference is ~10-20ms. Training runs in background (every 5 min).

**Q: Can I adjust anomaly sensitivity?**
A: Yes. Edit `contamination=0.1` in `anomaly_detector.py` to `0.05` (stricter) or `0.15` (lenient).

**Q: What features does ML use?**
A: CPU%, RAM%, Disk%, Process count, Connection count, Open ports, Active connections, Strange IPs.

---

## 📞 Quick Support

**Everything works?** ✅ You're done! Phase 3 is live.

**Something broken?** 
1. Check `TESTING_PHASE_3.md` troubleshooting section
2. Review server console for errors
3. Check database schema: `sqlite3 server/data.db ".schema"`

**Want to customize?**
1. Model sensitivity: Edit `contamination` in `anomaly_detector.py`
2. Severity thresholds: Edit threat classification logic in `server.py`
3. Threat retention: Adjust database cleanup queries

---

**Phase 3 is ready! 🎉 Next up: Phase 4 - Active Defense**

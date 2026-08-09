# Phase 3 Testing Guide

## Quick Start Testing

### 1. Setup & Installation
```bash
cd server
python -m venv venv
venv\Scripts\activate    # Windows
pip install -r requirements.txt
set API_KEY=supersecret
python server.py
```

Expected output:
```
Server running on http://127.0.0.1:5000
AI Anomaly Detection (Phase 3) enabled
```

### 2. Start Agent (in another terminal)
```bash
cd agent
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
set SERVER_URL=http://127.0.0.1:5000/ingest
set API_KEY=supersecret
set HOST_ID=test-machine
python agent.py
```

### 3. View Dashboard
- Open browser: http://127.0.0.1:5000/
- Should see main host list with telemetry data

## Phase 3 Testing Scenarios

### Scenario 1: Normal Operation (No Anomalies)
**Expected Behavior:**
1. Agent sends telemetry every 2 seconds
2. Server stores in `telemetry` table
3. After 20 samples: Model training starts
4. Dashboard shows host with "Online" status
5. Threats section: "No threats detected"

**Verify:**
```bash
# Check database
sqlite3 server/data.db
SELECT COUNT(*) FROM telemetry;
SELECT COUNT(*) FROM threats;
```

### Scenario 2: Detect CPU Spike Anomaly
**Trigger Anomaly:**
- Open terminal on test machine
- Run CPU-intensive command (e.g., Python loop, build process)

**Expected:**
1. CPU usage rises (should be visible in dashboard)
2. After several samples, model learns new baseline
3. Sudden spike back down might trigger anomaly
4. Threat recorded in `threats` table
5. Dashboard shows "AI-Detected Threats" with severity

**Verify:**
```bash
sqlite3 server/data.db
SELECT * FROM threats LIMIT 5;
```

### Scenario 3: Model Training Verification
**Check Background Training:**
1. Let agent run for 30+ seconds (produces ~15 samples)
2. Check `server/models/` directory
3. After 20 samples, should see `test-machine_model.pkl` file

```bash
ls -la server/models/
# Should show: test-machine_model.pkl
```

### Scenario 4: Process Anomaly (High Severity)
**Trigger:**
1. Start multiple processes or fork bomb

**Expected:**
1. `num_processes` increases
2. Feature vector changes significantly
3. Model detects anomaly
4. Threat recorded with `severity = "high"` (if process-related)
5. Dashboard shows red badge for HIGH severity

### Scenario 5: View Threat Details
**Test Per-Host Threat View:**
1. Navigate to: http://127.0.0.1:5000/threats/test-machine
2. Should see table of detected threats
3. Click on latest threat to see full telemetry data in JSON

## Validation Checklist

### Database Schema
- [ ] `telemetry` table exists with 5 columns
- [ ] `threats` table exists with 7 columns
- [ ] Both tables have proper indexes

```sql
-- Verify schema
.schema telemetry
.schema threats
```

### Model Files
- [ ] `server/models/` directory created on first threat
- [ ] Each host gets its own `{host_id}_model.pkl` file
- [ ] Models update every 5 minutes (check file timestamps)

### Dashboard Features
- [ ] Main dashboard loads at `/`
- [ ] Hosts table shows all connected agents
- [ ] Threats section appears (empty or with threats)
- [ ] Threat severity colors:
  - [ ] Red = HIGH
  - [ ] Orange = MEDIUM
  - [ ] Teal = LOW
- [ ] Per-host threat view works at `/threats/{host_id}`

### API Endpoints
- [ ] `POST /ingest` - Accept telemetry ✓
- [ ] `GET /` - Dashboard ✓
- [ ] `GET /agent/<host_id>` - Host detail ✓
- [ ] `POST /remove/<host_id>` - Remove agent ✓
- [ ] `GET /threats/<host_id>` - Threat history ✓ (NEW)

## Performance Testing

### Load Test (Multiple Hosts)
```bash
# Start multiple agents with different HOST_IDs
for i in {1..5}; do
  set HOST_ID=host-$i
  python agent.py &
done
```

**Expected:**
- Server handles 5+ concurrent agents
- Models train for each host independently
- Dashboard updates smoothly
- No crashes or memory leaks

### Model Training Efficiency
- First model training: < 1 second (20 samples)
- Background retraining: < 2 seconds (200 samples)
- Inference per sample: < 50ms

## Troubleshooting

### No Threats Being Detected
1. Check if model is trained:
   ```bash
   ls -la server/models/
   ```
   - If empty: Need 20+ samples first
   - Run agent longer and wait

2. Check threat detection logs:
   ```bash
   sqlite3 server/data.db "SELECT * FROM threats;"
   ```
   - If empty: Normal patterns detected (good!)

3. Manually trigger anomaly by extreme values

### Model Training Errors
1. Check server logs for exceptions
2. Verify scikit-learn installed:
   ```bash
   python -c "import sklearn; print(sklearn.__version__)"
   ```
3. Check models directory permissions

### Dashboard Not Showing Threats
1. Hard refresh browser (Ctrl+F5)
2. Check server console for errors
3. Verify threats exist in database:
   ```bash
   sqlite3 server/data.db "SELECT COUNT(*) FROM threats;"
   ```

## Regression Testing

### Existing Features Still Work
- [ ] Rule-based detection still works (CPU > 90%, suspicious processes)
- [ ] Dashboard displays all telemetry correctly
- [ ] Agent filtering works
- [ ] Database cleanup (7-day retention) still runs
- [ ] API key validation still enforced

## Performance Metrics to Monitor

Track during testing:
- Server response time for `/ingest`: < 100ms
- Dashboard load time: < 1 second
- Model training time: < 2 seconds
- Database queries: < 500ms

## Success Criteria

Phase 3 is successful when:
1. ✅ Models train automatically after 20 samples per host
2. ✅ Anomalies detected and stored in threats table
3. ✅ Dashboard displays AI-detected threats section
4. ✅ Threat history accessible per host
5. ✅ Severity classification works correctly
6. ✅ Background retraining runs every 5 minutes
7. ✅ No performance degradation vs Phase 2
8. ✅ Rule-based detection still works alongside ML

## Next Steps (Phase 4 Prep)

After Phase 3 validation:
- [ ] Plan active defense response playbooks
- [ ] Design Slack/Discord alert integration
- [ ] Create threat severity thresholds for auto-response
- [ ] Build server→agent command execution framework

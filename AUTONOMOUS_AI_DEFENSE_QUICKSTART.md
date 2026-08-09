# AUTONOMOUS_AI_DEFENSE_QUICKSTART.md

# 🤖 Autonomous AI Defense System - Quick Start (5 Minutes)

## What You're Getting

A **self-defending cybersecurity system** that:

1. **Watches** all hosts for suspicious activity
2. **Analyzes** what's happening using real AI (LLM)
3. **Decides** what to do automatically
4. **Acts** to block threats in real-time
5. **Logs** everything for compliance

---

## ⚡ 5-Minute Setup

### Step 1: Install Ollama (Free LLM Framework)

**Windows:**
- Download: https://ollama.ai/download
- Or: `choco install ollama`

**Mac:**
- Download: https://ollama.ai/download
- Or: `brew install ollama`

**Linux:**
```bash
curl https://ollama.ai/install.sh | sh
```

### Step 2: Download Llama 2 (Free AI Model)

```bash
ollama pull llama2:7b
# This downloads a 4GB model (15 min - 1 hour depending on internet)
# It's FREE and runs entirely on your computer
```

### Step 3: Start Ollama Server

Open a terminal/command prompt and run:
```bash
ollama serve
# You'll see: "listening on 127.0.0.1:11434"
```

### Step 4: Install Python Dependencies

```bash
cd server
pip install -r requirements_v2.txt
```

### Step 5: Start the Autonomous Defense Server

New terminal/command prompt:
```bash
cd server
set API_KEY=supersecret
python server_v2_ai_autonomous.py
```

You should see:
```
============================================================
🛡️  ACHILLES SHIELD - AI AUTONOMOUS DEFENSE SYSTEM
============================================================
✅ Phase 3: ML Anomaly Detection
✅ Phase 4: AI-Powered Threat Analysis
✅ Phase 5: Autonomous Response Execution
============================================================
Server running on http://127.0.0.1:5000
```

### Step 6: Start the Agent

New terminal/command prompt:
```bash
cd agent
set SERVER_URL=http://127.0.0.1:5000
set API_KEY=supersecret
set HOST_ID=test-machine
python agent.py
```

You should see:
```
🛡️  Achilles Shield Agent Starting
   Host: test-machine
   Server: http://127.0.0.1:5000
   Autonomous Defense: ENABLED
✅ Autonomous Defense System Ready
```

---

## 🎯 How It Works (Simple)

```
Your Computer (Agent)
↓ sends telemetry every 2 seconds
  (CPU: 45%, RAM: 60%, processes running, network connections, etc.)
↓

Server (AI Brain)
├─ Step 1: Quick check - "Is anything obviously wrong?" (instant)
├─ Step 2: ML check - "Is this normal for this computer?" (instant)
├─ Step 3: AI analysis - "What's actually happening?" (30 seconds)
│  └─ Sends data to Ollama/Llama2
│  └─ LLM analyzes and says: "Cryptominer! 92% sure!"
├─ Step 4: Decision - "What should we do?" (instant)
│  └─ If threat is bad + AI is confident → Execute response
└─ Step 5: Action - "Kill those processes! Block those IPs!"
   └─ Sends command to agent

Agent Receives Command
├─ "Kill process X and Y"
├─ Terminates processes
├─ Reports back "Done!"
└─ Reports to server for logging

Result: Threat neutralized in < 1 minute, all logged for audit
```

---

## 🚨 Testing It (Optional)

### Simulate Cryptominer

Open a new terminal and run:
```bash
# Create a CPU-intensive process
python -c "while True: x = 2**1000000"
```

Watch the server output:
```
🔍 Starting AI Analysis for test-machine...
🤖 AI Analysis Complete:
   Threat: high_cpu_anomaly
   Confidence: 0.65
   Root Cause: "Unusual CPU spike...

⚙️  Decision: ...
🎯 Command queued for agent
```

The AI recognizes the unusual behavior and suggests actions!

---

## 📊 View the Dashboard

Open browser: **http://localhost:5000/**

You'll see:
- **Hosts**: All connected machines with their stats
- **AI-Detected Threats**: What the AI found suspicious
- **AI Analysis**: Detailed reasoning about each threat
- **Autonomous Actions**: What the system did/will do

Click on a host to see:
- Full threat history
- All AI analysis for that host
- All actions taken (audit trail)

---

## 🎓 Key Concepts

### Isolation Forest (ML)
- Learns what's "normal" for each computer
- Detects when data looks unusual
- Fast (instant detection)
- Mathematical, not AI-based

### Llama 2 (LLM AI)
- Real artificial intelligence
- Understands security threats
- Analyzes what's happening and why
- Slow-ish (30 seconds, but thorough)

### Decision Engine
- Combines ML + LLM results
- Applies confidence thresholds
- Decides if threat is serious enough to auto-respond
- Executes only when confident enough

### Autonomous Responses
```
Action 1: KILL_PROCESS
  ├─ Kills suspicious programs
  └─ Stops malware/miners
  
Action 2: BLOCK_IP
  ├─ Blocks outbound connections to bad IPs
  └─ Prevents C2 communication
  
Action 3: ISOLATE_MACHINE
  ├─ Disconnects computer from network
  └─ Last resort for critical threats
```

---

## ⚙️ Configuration

### Use Faster AI (Sacrifice Accuracy)
```bash
ollama pull mistral:7b
# In server_v2_ai_autonomous.py, set:
# OLLAMA_MODEL = "mistral:7b"
```

### Use More Powerful AI (Needs GPU)
```bash
ollama pull llama2:13b
# Requires more VRAM but much smarter analysis
```

### Change Response Aggressiveness

Edit `server/threat_analyzer.py`:

**Conservative** (alert more, execute less):
```python
if severity == 'high' and confidence > 0.85:  # Needs 85% certainty
    execute = True
```

**Balanced** (current default):
```python
if severity == 'high' and confidence > 0.6:  # Needs 60% certainty
    execute = True
```

**Aggressive** (execute more readily):
```python
if severity == 'high' and confidence > 0.5:  # Needs 50% certainty
    execute = True
```

---

## 📝 What Gets Logged

Every threat detection is logged:
- **When** it happened
- **What** the threat was
- **How confident** the AI is (0-100%)
- **Why** it's a threat (root cause analysis)
- **What action** was taken
- **Result** of the action

All data stored in SQLite database for compliance/audit.

---

## 🔍 Troubleshooting

### Ollama not connecting?
```bash
# Check if Ollama is running:
curl http://localhost:11434/api/generate

# If error, start Ollama:
ollama serve
```

### No AI analysis appearing?
```bash
# Check server logs for "🤖 AI Analyzing threat..."
# If not appearing: Ollama probably not running

# Make sure model is downloaded:
ollama list
# Should show: llama2:7b (or whatever model)
```

### Agent not receiving commands?
```bash
# Agent should show periodic output like:
# "✓ Telemetry sent | Processes: 145 | CPU: 45.3% | RAM: 62.1%"

# If no output: Check SERVER_URL environment variable
# Make sure server is running on :5000
```

### AI taking too long?
This is normal - first run might take 30 seconds while Llama thinks.
After first run, it caches responses faster.

---

## 📈 Real-World Scenario

**What happens when a cryptominer infects a host:**

```
⏰ 0:00 - Cryptominer starts running
⏰ 0:02 - Agent sends telemetry: CPU 95%, 250 processes
⏰ 0:03 - Server rule-based check: "CPU > 90% ALERT!"
⏰ 0:05 - Server ML check: "This is very abnormal for this host!"
⏰ 0:06 - Server AI analysis starts
⏰ 0:30 - Llama 2 responds: "CRYPTOMINER detected! 92% sure!"
⏰ 0:31 - Decision: "92% confidence + HIGH severity = EXECUTE"
⏰ 0:32 - Command queued for agent: "Kill mining processes"
⏰ 0:37 - Agent receives command (checks every 5 seconds)
⏰ 0:38 - Agent executes: Kills 2 mining processes
⏰ 0:39 - Agent reports: "Done! Killed svchost.exe, rundll32.exe"
⏰ 0:40 - Next telemetry arrives: CPU 35% (normal again!)

RESULT: Threat neutralized in ~40 seconds, FULLY AUTOMATED! ✅
```

---

## 🚀 Moving to Production

1. **Test locally first** - Make sure everything works
2. **Monitor false positives** - Adjust thresholds if needed
3. **Deploy agents to production hosts**
4. **Let it run in "alert only" mode for 1 week** - Watch for false alarms
5. **Enable auto-execute mode** - Turn on autonomous responses
6. **Set up alerts** - Get Slack/email notifications for high-severity threats
7. **Review logs weekly** - Audit trail for compliance

---

## 💡 Remember

This system:
- ✅ Can detect threats faster than humans
- ✅ Can respond faster than humans
- ✅ Never gets tired or distracted
- ✅ Logs everything for compliance
- ✅ Requires no manual intervention
- ✅ Can handle thousands of hosts

But it:
- ⚠️ Should be monitored initially (false positives are possible)
- ⚠️ Needs appropriate confidence thresholds
- ⚠️ Should have human oversight for critical decisions
- ⚠️ Requires incident response procedures

---

## 📞 Help

**Check these files:**
- `PHASE_4_AUTONOMOUS_AI_DEFENSE.md` - Full technical details
- `server_v2_ai_autonomous.py` - Code comments explain everything
- `threat_analyzer.py` - Where AI decisions are made

**Check logs:**
```bash
# Server logs (on-screen output)
# Agent logs (on-screen output)
# Database: server/data.db (can query with sqlite3)
```

---

**You now have an AI-powered security system! 🛡️**

It works 24/7, never sleeps, and responds faster than any human team.

Let's make cybersecurity autonomous!

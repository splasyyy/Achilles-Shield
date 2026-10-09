# Autonomous AI Defense Quick Start

## What You're Getting

A local-first endpoint defense prototype that:

1. Collects telemetry from connected agents.
2. Uses rules, anomaly signals, and optional local AI analysis to surface activity.
3. Authorizes only actions permitted by deterministic server-side policy.
4. Revalidates exact process identity and reports endpoint outcomes for audit.

---

## Before you begin

The setup includes Python dependency installation. Ollama and its model are
optional; the `llama2:7b` model uses several gigabytes of storage. Review its
size before you choose to download it. No software or model is installed or
downloaded automatically by these instructions.

## Response safety controls

Routine process mitigation remains automatic only when telemetry identifies a process
whose name matches a built-in suspicious marker (`hack`, `malware`, `keylog`, `miner`,
`virus`, or `trojan`). The action is bound to the exact PID, process name, and process
start time (microsecond precision) reported by the agent; the agent rechecks all three
before terminating it. The command is also bound to its telemetry host ID, and agents
reject commands addressed to a different host.
Protected operating-system processes and critical PIDs are excluded. LLM
recommendations and repeat detections alone cannot authorize destructive actions.

Machine isolation has a separate opt-in and requires an external-connection burst
(six or more distinct globally routable IPs) plus at least one independent signal in
the same telemetry sample: a suspicious process name, or CPU at least 95% while at
least 200 processes are reported.
Before disconnecting the host, the agent checks that the same two signal categories
including the external-connection burst are still present in fresh local telemetry.
Set `DEFENSE_ISOLATION_ENABLED=true` in
both server and agent environments to allow this response; it is off by default.
An authorized isolation disables active network interfaces/services and may interrupt
remote access. Run the agent with permissions to disable network interfaces/services;
failures are recorded per interface and reported as partial or failed isolation when
the server remains reachable. After investigating, restore connectivity locally:
enable the adapter in Windows Network Settings, run `ip link set dev <name> up` on
Linux, or re-enable the service in macOS Network Settings.

The dashboard links to per-host analysis and action history. The history distinguishes
what the server authorized from what the agent reported executing; a server decision
is not proof that the endpoint action succeeded.
Authorized commands are stored in the server database and remain outstanding until a
matching agent report arrives. A delivery is retried if it has not been acknowledged
within 60 seconds, using the same command ID and exact targets; agents revalidate
process identity before every attempt. The server rejects reports whose command ID,
host, or action does not match.
Agents keep unreported outcomes in a local SQLite outbox (by default under
`%LOCALAPPDATA%\AchillesShield\agent_state.db` on Windows, or the home directory on
other platforms). Set `AGENT_STATE_DB` to choose another path. Successfully reported
outcomes are retained locally for up to 30 days, then pruned.
Before handling a command with an ID, the agent durably records its execution intent.
If it restarts with an intent but no saved outcome, it reports the result as unknown
and does not retry the action, because the action may already have occurred. While
the recorded agent process is still running, duplicate delivery is deferred rather
than reported or executed again. Check endpoint state and audit evidence before
taking further action for an interrupted command.

Set `DEFENSE_ENABLED=false` to disable all automated response, or
`DEFENSE_SAFE_MODE=true` to pause it. Set the variable in **both the server and each
agent's environment before starting them**. Defense is enabled by default to preserve
existing deployments. When the server is in safe mode, it cancels outstanding
commands so they will not be delivered again; an agent started in safe mode also
rejects commands if the server is unavailable or bypassed. Previously delivered
commands may still report their outcome. Extend the protected-name defaults in both environments with
`PROTECTED_PROCESS_NAMES`, a comma-separated list of process names.
For non-disruptive staging checks, set `DEFENSE_DRY_RUN=true` in the agent environment.
The agent still validates the command, process identity, or isolation evidence and
reports `dry_run`, but does not terminate processes or disable network interfaces.
Unset the variable and restart the agent to enable authorized mitigation.
Run `python agent/agent.py --check` before starting the agent to verify that its local
state database is accessible and the configured server URL/API key can reach the
authenticated, read-only health endpoint. This check does not poll queued commands,
send telemetry, or perform mitigation.

## Intrusion alerts (Windows)

Every 15 seconds, the Windows agent polls selected Security events (4625 failed
logon, 4624 successful logon, 4740 account lockout, 4672 special privileges,
and 4698 scheduled-task creation) and System event 7045 (service installation).
Security and System use independent cursors. The first successful query for
each channel establishes a baseline and skips older events.

The server creates alert-only records for:

- **Failed-logon burst:** at least five failures from one source IP to one host
  within five minutes (medium severity).
- **Cross-host password spray:** at least ten failures from one IP across at
  least three distinct hosts within ten minutes (high severity).
- **Failure followed by success:** a successful logon from the same IP and host
  after at least three failures within 30 minutes (high severity).
- **Lockout, scheduled-task creation, and service installation:** Windows
  events 4740, 4698, and 7045 respectively (medium severity).
- **Interactive privileged logon:** event 4672 correlated with a successful
  interactive or remote-interactive logon (4624 logon type 2 or 10) on the
  same host within two minutes (medium severity). This correlation avoids
  alerting on the many routine service privilege assignments.

Duplicate channel/record pairs are ignored. Repeated alerts for the same
host/source or event category are limited to one per five minutes. Where
Windows provides them, failed/successful logons include source port, logon
type, workstation name, and status/substatus codes; alert summaries group the
observed values and show the affected endpoints for a cross-host spray. The
dashboard classifies IPs only as globally routable, non-global/private or
special-use, link-local, or other reserved scope. Workstation names are
explicitly reported values and are not independently verified.

This is source evidence, **not identification of a person or proof of origin**:
addresses can represent NAT gateways, VPNs, proxies, shared networks, or
spoofed/untrusted telemetry. The system does not geolocate addresses or query
external threat-intelligence services. Account names, task contents, and
service image paths are not collected. Event summaries and source details
needed for correlation are retained for up to 24 hours; compact alert
summaries remain in threat history under its normal retention.

For these alert patterns the dashboard also shows a **rules-based path
hypothesis**: the observed stage, one plausible next step, the signals behind
it, a confidence label, and a suggested containment measure. This is a
transparent heuristic, not a learned or calibrated forecast; benign
administration, shared egress IPs, and incomplete event coverage can change
the interpretation. A predicted step is explicitly labeled **not observed**.
Suggested controls are operator guidance only: intrusion predictions do not
change firewalls, terminate sessions, disable accounts, or queue response
commands. Validate alert and prediction quality with real endpoint data before
considering a later, separately designed, reversible automated control.

An optional learned event-transition baseline can supplement these heuristics
when an operator provides privacy-reviewed labeled attack and benign traces,
held out by campaign. It ranks supported next Windows event types, shows
empirical training frequencies and held-out metrics, and abstains on
unsupported transitions. The frequencies are not calibrated attacker
probabilities. No training corpus, training JSONL, evaluation JSONL, or model
artifact is bundled. Do not treat fabricated or unverified events as labeled
attack data. The README's **AI and sequence-model status** section documents
the JSONL episode fields, training command, required quality gates, and model
configuration using `INTRUSION_SEQUENCE_MODEL_PATH`.

The dashboard's **Windows logs** column shows aggregate readiness plus the status
of each channel. A **degraded** status means one channel is readable while
another is not; **unavailable** means neither can be read. Windows must be
configured to audit the relevant event types, and reading the Security log may
require additional Windows permissions. **Ready** means only that the agent can
read the channel; it does not confirm that audit policy is producing all event
types. Other operating systems report this Windows-only monitor as
**unsupported**. These detections create alerts only: they do not invoke AI
analysis, queue process termination, or isolate the host. Response decisions
for intrusion alerts remain a separate future step.

### Optional: Install Ollama for local LLM analysis

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

### Step 2: (Optional) Download a local model

```bash
ollama pull llama2:7b
# This downloads several gigabytes; check available storage first.
```

### Optional: Start Ollama Server

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

### Step 5: Start the server

New terminal/command prompt:
```bat
cd server
set API_KEY=replace-with-a-long-random-secret
python server_v2_ai_autonomous.py
```

Keep the server and agent `API_KEY` values identical. Use a unique secret,
including for local testing.

### Step 6: Start the Agent

New terminal/command prompt:
```bat
cd agent
set SERVER_URL=http://127.0.0.1:5000
set API_KEY=replace-with-a-long-random-secret
set HOST_ID=test-machine
rem Start in dry-run mode; commands are validated but not executed
set DEFENSE_DRY_RUN=true
rem Optional safety check: validates connectivity without polling or mitigation
python agent.py --check
python agent.py
```

Leave `DEFENSE_DRY_RUN=true` while validating the setup. To enable isolation,
first review its impact and recovery requirements, then explicitly set
`DEFENSE_ISOLATION_ENABLED=true` in both server and agent environments.

---

## How it works

```
Agent                          Server
  |                              |
  |------ telemetry ------------>|
  |                              |-- analyze and record activity
  |                              |-- independently authorize only
  |                              |   policy-approved actions
  |<----- queued command --------|
  |-- revalidate exact target    |
  |-- execute, dry-run, or reject|
  |------ report outcome ------->|
```

AI output is informational; it does not authorize process termination or host
isolation. Process termination requires a reported process matching the
configured suspicious-name markers and is limited to exact PID, name, and
start-time identity. Isolation is separately opt-in, evidence-gated, and
revalidated against fresh local telemetry. IP blocking is not an implemented
automatic response action.

---

## Testing

Start with the focused regression suite from the repository root:

```bash
python -m unittest tests.test_intrusion_alerts tests.test_intrusion_sequence_model tests.test_response_safety tests.test_server_flow -q
```

For a local connectivity check, run `python agent.py --check` from the `agent`
directory. To verify response handling without mitigation, set
`DEFENSE_DRY_RUN=true` for the agent. Do not use a CPU-burn loop or real malware
as a test input.

---

## 📊 View the Dashboard

Open browser: **http://127.0.0.1:5000/**

The dashboard shows connected hosts, recent detections, AI analysis when
available, server authorizations, and endpoint-reported action outcomes.

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
- Optional local model for generated analysis
- Output can be inaccurate and is informational, not a response authorization
- Response time and quality depend on the selected model and hardware

### Response authorization
- Uses deterministic server-side policy and observed telemetry.
- LLM recommendations and confidence scores do not grant authorization.
- Protected processes and critical PIDs are excluded from process termination.
- Network isolation requires explicit opt-in and independent evidence.

### Autonomous Responses
```
KILL_PROCESS    Exact observed process; identity rechecked by the agent
ISOLATE_MACHINE Opt-in, stronger evidence, and fresh local corroboration
```

---

## Configuration

### Select the local analysis model
```bat
set OLLAMA_MODEL=llama2:7b
```

Set `OLLAMA_API` and `OLLAMA_MODEL` in the server environment. Changing the
analysis model does not change response authorization policy. To extend the
protected-process defaults, set `PROTECTED_PROCESS_NAMES` in both server and
agent environments; use comma-separated process names.

---

## 📝 What Gets Logged

The server stores analysis and response authorization records; endpoint reports
are recorded separately:
- **When** it happened
- **What** activity was observed and analyzed
- **Why** the server authorized or declined an action
- **What** outcome the agent reported, if any

These records support investigation; they do not by themselves establish
compliance or prove that an authorized action succeeded.

---

## 🔍 Troubleshooting

### Ollama not connecting?
```bash
# Check whether a model is available:
ollama list

# Start the service if needed:
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

### AI analysis is slow or unavailable?
Local model latency depends on hardware and model size. AI analysis is optional;
its output does not change the deterministic response authorization policy.

---

## Before enabling response on real endpoints

1. Run the focused tests and review the current response policy in
   `server/threat_analyzer.py` and `agent/autonomous_defense.py`.
2. Exercise setup and connectivity in an isolated environment.
3. Set `DEFENSE_DRY_RUN=true` on agents and inspect reported dry-run outcomes.
4. Keep isolation disabled unless its operational impact is understood and
   explicitly approved by the operator.
5. Define an incident process for unknown, partial, failed, or rejected outcomes.
6. Enable response only after reviewing protected-process names, permissions,
   storage, and remote-access recovery procedures.

---

## 💡 Remember

This is an evolving prototype. Detection can produce false positives, and
authorization is not proof of successful execution. Monitor outcomes and retain
human oversight; do not treat the project as production-ready or certified.

---

## 📞 Help

**Check these files:**
- `README.md` — overview and entry points
- `AUTONOMOUS_AI_DEFENSE_EXPLAINED.md` — conceptual background (not a policy reference)
- `server/threat_analyzer.py` — server-side policy and analysis
- `agent/autonomous_defense.py` — agent-side validation and execution

**Check logs:**
```bash
# Server logs (on-screen output)
# Agent logs (on-screen output)
# Database: server/data.db (can query with sqlite3)
```

---

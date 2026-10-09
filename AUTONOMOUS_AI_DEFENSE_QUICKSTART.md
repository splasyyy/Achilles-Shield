# Autonomous AI Defense Quick Start

Achilles Shield is a prototype that watches computers for suspicious
activity. The server follows fixed safety rules before allowing a response.
Optional AI analysis and attack predictions only offer information; they
cannot give the system permission to stop programs or disconnect a computer.

## 1. Install and start

You need Python installed. Open a terminal in the project folder and install
the server's required Python packages:

```bash
cd server
pip install -r requirements_v2.txt
```

Start the server in that terminal (Windows Command Prompt example):

```bat
cd server
set API_KEY=replace-with-a-long-random-secret
python server_v2_ai_autonomous.py
```

Open a second terminal for the agent. Replace the example API key with the
same long, private value in both terminals. Replace `test-machine` with a
unique name for this computer:

```bat
cd agent
set SERVER_URL=http://127.0.0.1:5000
set API_KEY=replace-with-a-long-random-secret
set HOST_ID=test-machine
set DEFENSE_DRY_RUN=true
python agent.py --check
python agent.py
```

The `--check` command checks that the agent can reach the server without
sending computer data or asking for commands. Keep `DEFENSE_DRY_RUN=true`
while testing: it checks commands but does not carry them out. Open
`http://127.0.0.1:5000` to view the dashboard.

Ollama is optional. It can run AI analysis on your computer. Follow Ollama's
official installation instructions, then choose and download a model (for
example, `llama2:7b`, which takes several gigabytes). Set `OLLAMA_API` and
`OLLAMA_MODEL` for the server. Nothing is installed or downloaded
automatically. AI output cannot approve responses.

## 2. Response safeguards

- The agent may automatically stop a program if it saw that program running
  and its name matches a built-in suspicious marker (`hack`, `malware`,
  `keylog`, `miner`, `virus`, or `trojan`). It checks the program's ID, name,
  and start time again just before stopping it.
- Protected operating-system processes and critical PIDs are excluded.
  You can add protected names with the comma-separated
  `PROTECTED_PROCESS_NAMES` setting on both server and agent.
- `DEFENSE_ENABLED=false` disables automated response; `DEFENSE_SAFE_MODE=true`
  pauses it. Add either setting to both server and agent before starting
  them. Safe mode cancels commands that have not yet been delivered. Actions
  already delivered may still finish and report back.
- `DEFENSE_DRY_RUN=true` on the agent checks commands without stopping
  programs or disconnecting the computer.
- Isolation is off by default. To enable it, set
  `DEFENSE_ISOLATION_ENABLED=true` in both environments. It requires either
  connections to six or more different public internet addresses plus a
  suspicious program, or CPU use of at least 95% while at least 200 programs
  are running. The agent checks for the same signs again before disconnecting
  the computer's network. This may cut off remote access; make sure someone
  can restore the connection at the computer before enabling it.

For reliability, the server retries commands if the agent has not reported
back after 60 seconds. Before acting, the agent saves a record of the command.
If it restarts before saving the result, it reports "unknown" rather than
risk repeating an action that may already have happened. Results waiting to
be sent are kept in a local database (default Windows location:
`%LOCALAPPDATA%\AchillesShield\agent_state.db`; change it with
`AGENT_STATE_DB`). Reported results are kept for up to 30 days. The dashboard
shows separately what the server allowed and what the agent says happened.

## 3. Windows intrusion alerts

Every 15 seconds, the Windows agent checks selected Security and System logs
for sign-in and system-change records. The first check sets a starting point
and skips older records. Windows may need extra permissions and the relevant
logging settings turned on.

Alert-only patterns:

| What it looks for | When an alert is created | Severity |
| --- | --- | --- |
| Many failed sign-ins to one computer | 5 failures from one address in 5 minutes | Medium |
| Possible password guessing across computers | 10 failures from one address to 3+ computers in 10 minutes | High |
| A successful sign-in after repeated failures | 3+ failures from the same address, followed by success within 30 minutes | High |
| Account locked, task created, or service installed | Matching Windows event | Medium |
| Sign-in with special privileges | Matching sign-in and privilege events within 2 minutes | Medium |

The same log record will not be counted twice, and repeat alerts are limited.
Summaries may show the reported network address, workstation name, and sign-in
details. These can be shared or misleading and do not identify a person. The
system does not look up locations or check outside threat databases. It does
not collect account names, task contents, or service file paths. Details used
to connect related events are kept for up to 24 hours.

The dashboard may suggest what could happen next and show why it made that
suggestion. A suggestion is **not an event that has been observed**. It never
changes firewall settings, disables accounts, ends sign-in sessions, or sends
commands to agents. The optional learning feature has no example data or
trained model included; see the README before supplying data.

## 4. Verify and develop

Run the focused regression suite from the repository root:

```bash
python -m unittest tests.test_intrusion_alerts tests.test_intrusion_sequence_model tests.test_response_safety tests.test_server_flow -q
```

Use dry-run mode and an isolated test environment. Do not test with real
malware. Review `server/threat_analyzer.py` and `agent/autonomous_defense.py`
before enabling mitigation on real endpoints. Configure an incident and
recovery process for unknown, partial, failed, or rejected actions.

See the [README](README.md) for model-training details and
[How It Works](AUTONOMOUS_AI_DEFENSE_EXPLAINED.md) for a concise architecture
overview. This project is evolving prototype software, not certified
protection or a substitute for incident-response procedures.

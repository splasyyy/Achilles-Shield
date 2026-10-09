# Achilles Shield

Achilles Shield is a prototype for monitoring and responding to suspicious
activity on computers. Small programs called agents send computer status and
selected activity to a server, which records alerts and applies set safety
rules before allowing a response.

![Achilles Shield logo](server/static/logo.png)

![Dashboard preview](server/static/dashboard-preview.png)

*Dashboard preview uses synthetic example data.*

## Capabilities

- A dashboard showing computer health, alerts, and what the agent says
  happened after a response.
- Automatic stopping of certain suspicious programs, after checking the
  exact program and protecting important Windows processes.
- Optional network disconnection for a computer, disabled unless an operator
  turns it on and the required warning signs are present.
- Windows sign-in and system-change alerts, with suggestions about what might
  happen next.
- Optional AI analysis that runs on your computer with Ollama.

AI suggestions do not give the system permission to take action. Sign-in
alerts and guesses about what may happen next never trigger a response by
themselves. The dashboard shows what the server allowed separately from what
the agent reports doing. This is not certified or ready-to-deploy protection.

## AI and sequence model

The server can optionally use Ollama (default model `llama2:7b`) to review
computer activity. An older machine-learning feature can flag unusual
computer statistics, but it does not predict attacks and is not used by the
current server.

There is also an optional feature that looks for patterns in labeled Windows
event histories and suggests what type of event might come next. It is only a
suggestion: it is not a malware detector or a reliable probability that an
attacker will take a particular action. It is separate from Ollama. No
example attack data or trained model is included, so it does not make
predictions unless an operator supplies suitable data.

For this feature, the data file uses one JSON record per line. Each record
needs a `campaign_id` (an identifier shared by events from one incident),
a `label` (`attack` or `benign`), and an ordered `events` list such as
`windows.security.4625`. Training and test data must use different incidents;
each incident must have one label. Both files need attack and normal-use
examples. At least three separate attack incidents are required, and a
suggested pattern must appear in three incidents to be included. Never label
made-up events or unverified alerts as real attacks.

```bash
python -m server.intrusion_sequence_model \
  --train path/to/train.jsonl \
  --evaluate path/to/heldout.jsonl \
  --output server/models/intrusion-sequence.json \
  --minimum-top1-accuracy 0.70 \
  --minimum-coverage 0.50 \
  --maximum-benign-transition-rate 0.10
```

The command's thresholds are examples, not recommended settings for every
network. Training tests the model on incidents it has not seen and will not
save it unless it meets the chosen accuracy, coverage, and normal-use limits.
Passing those checks does not prove it will work well elsewhere. To load a
model, set `INTRUSION_SEQUENCE_MODEL_PATH` for the server and restart it.
Predictions remain suggestions and cannot authorize a response.

## Setup and safety

See the [Quick Start](AUTONOMOUS_AI_DEFENSE_QUICKSTART.md) for installation,
setup, and safety instructions. See [How It Works](AUTONOMOUS_AI_DEFENSE_EXPLAINED.md)
for a plain-language overview.

To pause automated responses, set `DEFENSE_ENABLED=false` or
`DEFENSE_SAFE_MODE=true` for both the server and agents before starting them.
To test without stopping programs or disconnecting computers, set
`DEFENSE_DRY_RUN=true` for each agent. Network disconnection is off by
default; it may interrupt remote access, so review the recovery steps before
enabling it.

## Development

Run the focused tests from the repository root:

```bash
python -m unittest tests.test_intrusion_alerts tests.test_intrusion_sequence_model tests.test_response_safety tests.test_server_flow -q
```

The dashboard listens at `http://127.0.0.1:5000` by default. Set the same
`API_KEY` on the server and agent. From the `agent` directory,
`python agent.py --check` verifies local state access and authenticated,
read-only server connectivity without sending telemetry or polling commands.

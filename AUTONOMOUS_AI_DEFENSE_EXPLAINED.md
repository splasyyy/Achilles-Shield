# Achilles Shield: How Detection, Prediction, and Response Work

Achilles Shield is a local-first endpoint-defense prototype. Agents report
telemetry to a server, which records detections and applies deterministic
policy to decide whether any supported response can be authorized. Optional AI
analysis and intrusion-path predictions provide context; neither grants
permission to perform a destructive action.

This guide describes the implementation as it exists today. It is not a claim
that the system detects every attack, identifies an attacker, or is ready for
production deployment.

## The main components

### Endpoint agent

The agent periodically reports host telemetry and can receive authorized
commands. On Windows, it also polls selected Security and System event logs for
authentication and persistence events. It validates a command's host and
target before execution, rechecks process identity immediately before
termination, and reports the outcome to the server. An authorization is not
proof that the endpoint completed the action.

### Server and response policy

The server correlates telemetry and applies deterministic rules. An optional
local Ollama model can produce general-purpose analysis of suspicious
telemetry, but its recommendation, confidence, and generated text do not
authorize a response.

Routine process termination is limited to a suspicious process observed in
telemetry and bound to its exact process identity. Protected operating-system
processes and critical process IDs are excluded. Machine isolation is a
separate opt-in and requires stronger, independent evidence; it can interrupt
remote access. Response can be paused with `DEFENSE_ENABLED=false` or
`DEFENSE_SAFE_MODE=true`. Agent-side `DEFENSE_DRY_RUN=true` validates and
reports an action without carrying it out.

### Detection and prediction

Selected Windows events can produce alert-only records, including failed
logon bursts, cross-host password sprays, a failure followed by success, and
selected account, privilege, task, and service events. Correlation uses
reported event data; IP addresses, workstation names, and alerts do not prove
who initiated activity or where it originated.

For some intrusion alerts, deterministic heuristics display a plausible next
step and the evidence behind that hypothesis. A separate optional sequence
model can rank supported next Windows event types using frequencies learned
from labeled event sequences. It abstains when evidence is insufficient.
These predictions are advisory: they do not block network traffic, disable
accounts, terminate sessions, or queue response commands.

The repository's legacy Isolation Forest is a separate anomaly detector for
numeric host telemetry; it is not used by the current autonomous server flow
to predict intrusion sequences. The sequence model is also separate from the
Ollama LLM. None of these components should be described as a validated,
calibrated predictor of attacker intent.

## An illustrative event timeline

This timeline shows the boundaries between stages; it does not promise
detection or response for every incident.

1. **An event occurs.** For example, Windows records repeated failed logons.
2. **The agent polls the event log.** It forwards selected fields, not full
   event contents such as account names or task details.
3. **The server correlates evidence.** If a configured alert pattern matches,
   it records an intrusion alert. It may also display a rule-based path
   hypothesis and, if configured, advisory sequence-model candidates.
4. **An operator reviews the evidence.** A prediction is a hypothesis, not an
   observed next step or an instruction to contain the host. Intrusion alerts
   do not automatically produce response commands.
5. **Response policy handles eligible malware detections separately.** If
   telemetry satisfies the deterministic process-response policy, the server
   may authorize termination of the exact observed process. Isolation remains
   off unless explicitly enabled and supported by the required evidence.
6. **The agent revalidates and reports.** It checks authorization, host, and
   exact target identity; it then executes, rejects, or dry-runs the command
   and reports the outcome. The dashboard distinguishes the server's
   authorization from the endpoint's report.

There is no fixed end-to-end response time guarantee. Polling intervals,
permissions, host connectivity, model availability, and system load can all
affect what is observed and when.

## Training the optional sequence model

The model is an interpretable event-transition baseline, not a fine-tuned
language model, malware classifier, or probability that an attacker will take
a particular action. The project does not bundle labeled datasets or a
trained artifact. It should remain unconfigured until representative,
permissioned, privacy-reviewed data is available.

Training input is JSONL, with one episode per line and these fields:

- `campaign_id`: stable identifier for the incident or campaign.
- `label`: `attack` or `benign`.
- `events`: ordered normalized event tokens, such as
  `windows.security.4625`.
- `episode_id`: optional unique episode identifier.

Keep campaigns wholly separate between training and evaluation, and use one
label per campaign. Both splits must contain attack and benign campaigns.
Training requires at least three distinct labeled attack campaigns, and a
transition is retained only when it is supported by the required number of
distinct attack campaigns. Do not label synthetic sequences or unverified
alerts as ground truth.

The command and quality-gate options are documented in the README's
**AI and sequence-model status** section. Passing those gates is not proof of
generalization: evaluation quality depends on the dataset and split. In
particular, the benign supported-transition rate is a screening metric, not a
calibrated false-positive rate. Keep the model advisory-only and validate it
on independent campaigns and hosts before considering any separately
designed prevention feature.

## Operator guidance

- Start in an isolated test environment and use agent dry-run mode.
- Review the quick start for response defaults, permissions, recovery steps,
  event-log access, and troubleshooting.
- Treat unknown, partial, failed, rejected, and interrupted outcomes as
  requiring investigation; do not infer success from authorization alone.
- Keep intrusion alerts and learned predictions advisory. Validate their
  quality with real, permissioned data before proposing automated action.
- Treat this repository as an evolving prototype, not certified endpoint
  protection or a substitute for incident response procedures.

See the [README](README.md) for current architecture and model documentation
and the [Autonomous Defense Quick Start](AUTONOMOUS_AI_DEFENSE_QUICKSTART.md)
for setup and operational details.

# Achilles Shield

Achilles Shield is a local-first endpoint defense prototype. It collects host
telemetry, analyzes suspicious activity, and provides a dashboard and auditable
response workflow for connected agents.

![Achilles Shield logo](server/static/logo.png)

![Achilles Shield dashboard showing endpoint health, detections, response activity, and AI analysis](server/static/dashboard-preview.png)

*Dashboard preview populated with synthetic example data.*

## What it does

- Collects endpoint telemetry and reports it to a Flask server.
- Uses deterministic rules and configured threat heuristics to surface activity
  for investigation.
- Provides a dashboard for host health, detections, analysis, and response history.
- Supports bounded agent-side response actions with server authorization and
  reported outcomes recorded separately for audit.
- On Windows, correlates selected authentication and persistence events into
  alert-only failed-logon, password-spray, and intrusion summaries, with
  transparent rules-based hypotheses about plausible next steps and
  operator-reviewed ways to reduce exposure.
- Can use a local Ollama model for general-purpose AI-assisted telemetry
  analysis.

## Response safety

AI recommendations do not authorize destructive actions. Routine process
mitigation is bound to the exact suspicious process identity reported by the
agent and revalidated before termination; protected processes are excluded.
Machine isolation is disabled by default and requires a separate opt-in plus
stronger evidence. Authorization and endpoint-reported results are shown
separately, so an authorization is not proof that an action succeeded.

For an immediate response pause, set `DEFENSE_ENABLED=false` or
`DEFENSE_SAFE_MODE=true` in both the server and agent environments before
starting them. `DEFENSE_DRY_RUN=true` on an agent validates commands without
performing mitigation. See the [quick start](AUTONOMOUS_AI_DEFENSE_QUICKSTART.md)
for controls, defaults, and operational details.

## Intrusion path hypotheses

Intrusion alerts now include a deterministic, evidence-linked hypothesis about
one plausible next attacker step and an operator-reviewed containment idea.
The dashboard separates observed events from predicted behavior and labels
confidence and supporting signals. These are early heuristics, not calibrated
forecasts or identification of a person. Intrusion predictions are advisory:
they do not change firewall rules, terminate sessions, disable accounts, or
queue commands. The next milestone is validating detections and prediction
quality on permissioned endpoints before designing reversible automatic
containment.

## AI and sequence-model status

The current `server_v2_ai_autonomous.py` path uses deterministic rules for
response authorization and can call the local Ollama LLM (default
`llama2:7b`) to explain suspicious telemetry. That general-purpose LLM is not
fine-tuned on this project's incident data and is not the source of the
intrusion path predictions. The repository also contains a separate,
legacy Isolation Forest anomaly detector for numeric host telemetry; it does
not predict attack sequences and is not called by the current autonomous
server flow.

An optional learned next-event baseline is now available for selected Windows
event sequences. It learns campaign-supported transition frequencies from
operator-supplied, labeled JSONL episodes, evaluates on campaign-disjoint
attack and benign holdouts, and abstains where a transition lacks support. It
is a small interpretable statistical baseline—not a fine-tuned LLM, a malware
classifier, or a calibrated probability that an attacker will take an action.
No corpus or trained model is bundled. The model only adds advisory candidate
events; it cannot authorize endpoint or network changes.

To train, provide privacy-reviewed event-sequence data whose event tokens use
the normalized names (for example, `windows.security.4625` and
`windows.system.7045`), labels are `attack` or `benign`, and `campaign_id`
identifiers are consistent within an incident. Each JSONL line is one episode
with `campaign_id`, `label`, and an ordered `events` array; an optional
`episode_id` can identify the episode. Keep every campaign entirely in either
the training or evaluation split, and do not mix attack and benign labels
within one campaign. Include both labels in both splits; the tool requires at
least three distinct labeled attack campaigns for training and support from
three distinct campaigns for any transition. Do not use synthetic examples
or unverified alerts as attack ground truth. No JSONL training or evaluation
files are bundled: use only representative, permissioned, privacy-reviewed
data.

```bash
python -m server.intrusion_sequence_model \
  --train path/to/train.jsonl \
  --evaluate path/to/heldout.jsonl \
  --output server/models/intrusion-sequence.json \
  --minimum-top1-accuracy 0.70 \
  --minimum-coverage 0.50 \
  --maximum-benign-transition-rate 0.10
```

Choose quality gates based on your environment and validation goals; the
example values are not universal production thresholds. The trainer refuses
to write an artifact unless held-out top-1 accuracy and coverage meet the
chosen minimums and the benign supported-transition rate stays below its
chosen maximum. This benign rate is a screening proxy, **not** a calibrated
false-positive rate. Review the reported metrics and dataset provenance. To
enable an approved artifact, set `INTRUSION_SEQUENCE_MODEL_PATH` to its path
in the server environment and restart the server. The dashboard will show
supported next-event candidates with empirical training frequencies and
held-out metrics; those frequencies are not attacker probabilities. Obtain
representative, permissioned data and validate across independent hosts and
campaigns before considering any automated containment.

## Get started

Follow the [Autonomous Defense Quick Start](AUTONOMOUS_AI_DEFENSE_QUICKSTART.md)
for prerequisites, server and agent setup, configuration, and troubleshooting.
It documents the optional Ollama/model setup; installing software or downloading
a model are operator-run steps, not actions performed by the repository.

The server listens on `http://127.0.0.1:5000` by default. Set the same
`API_KEY` on the server and agent, and configure the agent's `SERVER_URL` as
the server base URL. A legacy URL ending in `/ingest` is also accepted.
From the `agent` directory, `python agent.py --check` checks local state access
and authenticated server connectivity without sending telemetry or polling
commands.

## Documentation

| Guide | Use it for |
| --- | --- |
| [Autonomous Defense Quick Start](AUTONOMOUS_AI_DEFENSE_QUICKSTART.md) | Current setup, safety controls, configuration, and troubleshooting |
| [Autonomous Defense Explained](AUTONOMOUS_AI_DEFENSE_EXPLAINED.md) | Conceptual background; use the quick start for current behavior and safety policy |

## Development

Run the focused intrusion-alert, sequence-model, response-safety, and
server-flow tests from the repository root:

```bash
python -m unittest tests.test_intrusion_alerts tests.test_intrusion_sequence_model tests.test_response_safety tests.test_server_flow -q
```

## Project status

This repository is an actively evolving prototype, not a certified or
production-ready endpoint protection product. Validate behavior in an isolated
environment, review the response policy for your deployment, and use dry-run
mode before enabling mitigation on real endpoints.

# How Achilles Shield Works

Achilles Shield monitors computers for suspicious activity. An agent is a
small program running on each monitored computer. It sends selected computer
status and activity to a server, which records alerts and uses fixed safety
rules before allowing supported responses.

Optional AI analysis and guesses about what an intruder might do next are
information for review; they cannot authorize actions. This is an evolving
prototype, not a guarantee that every attack will be detected or stopped.

## Components

- **Agent:** Sends selected computer information to the server, checks
  certain Windows sign-in and system-change records, checks commands before
  acting, and reports the result.
- **Server:** Looks for alert patterns and follows fixed response rules.
  Optional Ollama AI can explain suspicious activity, but cannot approve
  actions.
- **Alerts and predictions:** Sign-in alerts and suggestions about what might
  happen next are for people to review. An optional prediction feature can
  learn patterns from labeled past events, but it cannot act on those
  predictions.
- **Responses:** The system may stop a suspicious program only after
  checking the exact program and excluding protected Windows processes.
  Disconnecting a computer from the network is a separate option and is off
  by default. Set `DEFENSE_ENABLED=false` or `DEFENSE_SAFE_MODE=true` to pause
  responses; set `DEFENSE_DRY_RUN=true` for an agent to test without acting.

An older feature can flag unusual computer statistics, but it does not predict
attacks and is not used by the current server. The optional event-prediction
feature is a separate tool from Ollama. It looks for patterns in supplied
examples; it does not know how likely an attack is. No examples or trained
model are included.

## Example flow

1. Windows records a sign-in or system-change event.
2. The agent checks selected records and sends relevant details to the server.
3. If the events match a known pattern, the server records an alert. It may
   also show a suggestion about what could happen next.
4. A person reviews the alert. These intrusion alerts do not automatically
   cause the agent to act.
5. Separately, computer activity may match the rules for stopping a
   suspicious program. Disconnecting a computer requires a separate setting
   and stronger evidence.
6. Before acting, the agent checks the command and the target again. It
   reports whether it acted, refused, or only tested the command. Permission
   to act does not prove the action succeeded.

What the agent can see depends on Windows settings and permissions. Alerts
also depend on the computer being able to reach the server; there is no
guaranteed response time.

## Sequence-model data

The optional prediction feature needs a text data file with one record per
line. Each record needs an incident ID (`campaign_id`), a label (`attack` or
`benign`), and an ordered list of event names (`events`). Test incidents must
be separate from training incidents, and each incident must have only one
label. Both sets need attack and normal-use examples. Training needs at least
three separate attack incidents, and a pattern must appear in three incidents
before it can be suggested.

Use only real, permissioned, privacy-reviewed data—not made-up examples or
unverified alerts. Passing the model's checks does not guarantee it will work
on other computers. Keep predictions advisory and test them on separate
computers and incidents. See the [README](README.md) for the training command
and the [Quick Start](AUTONOMOUS_AI_DEFENSE_QUICKSTART.md) for setup and
safety instructions.

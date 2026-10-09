"""Offline, campaign-held-out next-event sequence model for intrusion telemetry."""

import argparse
import json
import math
import os
import re
import sys
import tempfile

MODEL_VERSION = 1
MAX_EPISODES = 100_000
MAX_EVENTS_PER_EPISODE = 256
MAX_SEQUENCE_ORDER = 2
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


class DatasetError(ValueError):
    """Raised when a supplied labeled sequence dataset is invalid."""


def load_jsonl(path):
    episodes = []
    with open(path, "r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            if len(episodes) >= MAX_EPISODES:
                raise DatasetError(f"dataset exceeds {MAX_EPISODES} episodes")
            try:
                episode = json.loads(line)
            except json.JSONDecodeError as error:
                raise DatasetError(f"invalid JSON on line {line_number}") from error
            validate_episode(episode, line_number)
            episodes.append(episode)
    return episodes


def validate_episode(episode, line_number=None):
    where = f" on line {line_number}" if line_number is not None else ""
    if not isinstance(episode, dict):
        raise DatasetError(f"episode must be a JSON object{where}")
    campaign_id = episode.get("campaign_id")
    if (not isinstance(campaign_id, str) or not campaign_id.strip()
            or len(campaign_id) > 128):
        raise DatasetError(f"campaign_id must be 1-128 characters{where}")
    if episode.get("label") not in {"attack", "benign"}:
        raise DatasetError(f"label must be 'attack' or 'benign'{where}")
    events = episode.get("events")
    if (not isinstance(events, list) or len(events) < 2
            or len(events) > MAX_EVENTS_PER_EPISODE):
        raise DatasetError(
            f"events must contain 2-{MAX_EVENTS_PER_EPISODE} tokens{where}"
        )
    if any(not isinstance(token, str) or not TOKEN_PATTERN.fullmatch(token)
           for token in events):
        raise DatasetError(f"event tokens contain invalid values{where}")


def _read_split(episodes, split_name):
    if not isinstance(episodes, list) or not episodes:
        raise DatasetError(f"{split_name} split must not be empty")
    seen_episode_ids = set()
    for index, episode in enumerate(episodes, 1):
        validate_episode(episode, index)
        episode_id = episode.get("episode_id")
        if episode_id is not None:
            if (not isinstance(episode_id, str) or not episode_id.strip()
                    or len(episode_id) > 128):
                raise DatasetError(
                    f"episode_id must be 1-128 characters in {split_name} split"
                )
            if episode_id in seen_episode_ids:
                raise DatasetError(
                    f"duplicate episode_id {episode_id!r} in {split_name} split"
                )
            seen_episode_ids.add(episode_id)


def _context_keys(history):
    available = history[-MAX_SEQUENCE_ORDER:]
    return [
        "|".join(available[-order:])
        for order in range(len(available), 0, -1)
    ]


def train_model(train_episodes, evaluation_episodes, min_campaign_support=3):
    """Fit attack-event transitions after enforcing a campaign-disjoint split."""
    _read_split(train_episodes, "training")
    _read_split(evaluation_episodes, "evaluation")
    if (not isinstance(min_campaign_support, int)
            or isinstance(min_campaign_support, bool)
            or min_campaign_support < 2):
        raise DatasetError("min_campaign_support must be an integer of at least 2")

    all_train_campaigns = {episode["campaign_id"] for episode in train_episodes}
    all_evaluation_campaigns = {
        episode["campaign_id"] for episode in evaluation_episodes
    }
    overlap = all_train_campaigns & all_evaluation_campaigns
    if overlap:
        raise DatasetError(
            "training/evaluation campaign overlap is prohibited: "
            + ", ".join(sorted(overlap)[:5])
        )
    for split_name, episodes in (
        ("training", train_episodes), ("evaluation", evaluation_episodes)
    ):
        campaign_labels = {}
        for episode in episodes:
            prior_label = campaign_labels.setdefault(
                episode["campaign_id"], episode["label"]
            )
            if prior_label != episode["label"]:
                raise DatasetError(
                    f"campaigns must not mix attack and benign labels in {split_name}"
                )
    train_campaigns = {
        episode["campaign_id"] for episode in train_episodes
        if episode["label"] == "attack"
    }
    evaluation_campaigns = {
        episode["campaign_id"] for episode in evaluation_episodes
        if episode["label"] == "attack"
    }
    if len(train_campaigns) < min_campaign_support:
        raise DatasetError(
            f"at least {min_campaign_support} distinct labeled attack campaigns "
            "are required for training"
        )
    if not any(episode["label"] == "benign" for episode in train_episodes):
        raise DatasetError("training split must include benign-labeled campaigns")
    if (not evaluation_campaigns
            or not any(episode["label"] == "benign"
                       for episode in evaluation_episodes)):
        raise DatasetError(
            "evaluation split must include both attack and benign campaigns"
        )

    counts = {}
    for episode in train_episodes:
        if episode["label"] != "attack":
            continue
        for next_index in range(1, len(episode["events"])):
            history = episode["events"][:next_index]
            next_event = episode["events"][next_index]
            for context in _context_keys(history):
                transition = counts.setdefault(context, {})
                item = transition.setdefault(
                    next_event, {"episodes": 0, "campaigns": []}
                )
                item["episodes"] += 1
                if episode["campaign_id"] not in item["campaigns"]:
                    item["campaigns"].append(episode["campaign_id"])

    transitions = {}
    for context, next_events in counts.items():
        supported = {}
        for next_event, support in next_events.items():
            campaigns = sorted(support["campaigns"])
            if len(campaigns) < min_campaign_support:
                continue
            supported[next_event] = {
                "episodes": support["episodes"],
                "campaign_count": len(campaigns),
            }
        total = sum(item["episodes"] for item in supported.values())
        if total:
            transitions[context] = {
                "total_supported_episodes": total,
                "next_events": {
                    next_event: {
                        **support,
                        "empirical_frequency": support["episodes"] / total,
                    }
                    for next_event, support in supported.items()
                },
            }

    model = {
        "model_version": MODEL_VERSION,
        "model_type": "campaign_supported_event_transition_counts",
        "sequence_order": MAX_SEQUENCE_ORDER,
        "min_campaign_support": min_campaign_support,
        "training_episode_count": len(train_episodes),
        "training_attack_campaign_count": len(train_campaigns),
        "transitions": transitions,
        "probability_semantics": (
            "Empirical transition frequency in the supplied labeled training "
            "corpus; not calibrated and not a probability of maliciousness."
        ),
        "action_policy": "advisory_only",
    }
    model["evaluation"] = evaluate_model(
        model, evaluation_episodes, min_campaign_support=min_campaign_support
    )
    return model


def _ranked_predictions(model, history, min_campaign_support=None):
    minimum = (
        model["min_campaign_support"]
        if min_campaign_support is None else min_campaign_support
    )
    for context in _context_keys(history):
        transition = model.get("transitions", {}).get(context)
        if not transition:
            continue
        choices = [
            {
                "event": event,
                "frequency": support["empirical_frequency"],
                "campaign_count": support["campaign_count"],
                "episode_count": support["episodes"],
            }
            for event, support in transition["next_events"].items()
            if support["campaign_count"] >= minimum
        ]
        if choices:
            return sorted(
                choices, key=lambda choice: (
                    -choice["frequency"], -choice["campaign_count"], choice["event"]
                )
            )
    return []


def predict_next(model, history):
    """Return supported next-event hypotheses or abstain."""
    if not isinstance(model, dict) or model.get("model_version") != MODEL_VERSION:
        return []
    if not isinstance(history, list) or any(
        not isinstance(token, str) or not TOKEN_PATTERN.fullmatch(token)
        for token in history
    ):
        return []
    return _ranked_predictions(model, history)


def evaluate_model(model, episodes, min_campaign_support=3):
    """Report held-out top-k accuracy and coverage; benign rows stay separate."""
    _read_split(episodes, "evaluation")
    attack_predictions = []
    benign_prefixes = 0
    benign_with_supported_prediction = 0
    for episode in episodes:
        for index in range(1, len(episode["events"])):
            history = episode["events"][:index]
            ranked = _ranked_predictions(
                model, history, min_campaign_support=min_campaign_support
            )
            if episode["label"] == "benign":
                benign_prefixes += 1
                if ranked:
                    benign_with_supported_prediction += 1
                continue
            attack_predictions.append({
                "expected": episode["events"][index],
                "ranked": ranked,
            })

    covered = [item for item in attack_predictions if item["ranked"]]
    if not attack_predictions:
        raise DatasetError("evaluation split must contain attack sequence prefixes")
    top1 = sum(
        item["ranked"][0]["event"] == item["expected"] for item in covered
    )
    top3 = sum(
        any(option["event"] == item["expected"] for option in item["ranked"][:3])
        for item in covered
    )
    return {
        "held_out_attack_campaign_count": len({
            episode["campaign_id"] for episode in episodes
            if episode["label"] == "attack"
        }),
        "attack_prefix_count": len(attack_predictions),
        "supported_attack_prefix_count": len(covered),
        "coverage": len(covered) / len(attack_predictions),
        "top1_accuracy_when_covered": top1 / len(covered) if covered else None,
        "top3_accuracy_when_covered": top3 / len(covered) if covered else None,
        "benign_prefix_count": benign_prefixes,
        "benign_prefixes_with_supported_attack_transition":
            benign_with_supported_prediction,
        "benign_supported_transition_rate": (
            benign_with_supported_prediction / benign_prefixes
            if benign_prefixes else None
        ),
        "notes": (
            "Held-out sequence metrics are corpus-dependent; benign transition "
            "rate is not a calibrated false-positive rate."
        ),
    }


def save_model(
    model, path, minimum_top1_accuracy, minimum_coverage,
    maximum_benign_transition_rate,
):
    """Write an artifact only when explicit held-out quality gates pass."""
    for name, value in (
        ("minimum_top1_accuracy", minimum_top1_accuracy),
        ("minimum_coverage", minimum_coverage),
        ("maximum_benign_transition_rate", maximum_benign_transition_rate),
    ):
        if (not isinstance(value, (int, float)) or isinstance(value, bool)
                or not math.isfinite(value) or not 0 <= value <= 1):
            raise DatasetError(f"{name} must be a finite value from 0 to 1")
    evaluation = model.get("evaluation", {})
    accuracy = evaluation.get("top1_accuracy_when_covered")
    coverage = evaluation.get("coverage")
    benign_rate = evaluation.get("benign_supported_transition_rate")
    if (accuracy is None or accuracy < minimum_top1_accuracy
            or coverage is None or coverage < minimum_coverage
            or benign_rate is None
            or benign_rate > maximum_benign_transition_rate):
        raise DatasetError(
            "held-out quality gates failed; no deployable model was written"
        )
    model = {
        **model,
        "deployment_gates": {
            "minimum_top1_accuracy": minimum_top1_accuracy,
            "minimum_coverage": minimum_coverage,
            "maximum_benign_transition_rate": maximum_benign_transition_rate,
        },
    }
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(
        prefix=".intrusion-sequence-", suffix=".tmp", dir=directory
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            json.dump(model, target, separators=(",", ":"), allow_nan=False)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary_path, path)
    except Exception:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
        raise
    return model


def load_model(path):
    """Load only structurally valid advisory model artifacts."""
    with open(path, "r", encoding="utf-8") as source:
        model = json.load(source)
    if (not isinstance(model, dict)
            or model.get("model_version") != MODEL_VERSION
            or model.get("action_policy") != "advisory_only"
            or model.get("model_type") != "campaign_supported_event_transition_counts"
            or model.get("sequence_order") != MAX_SEQUENCE_ORDER
            or not isinstance(model.get("transitions"), dict)):
        raise DatasetError("unsupported or invalid intrusion sequence model")
    support = model.get("min_campaign_support")
    campaigns = model.get("training_attack_campaign_count")
    evaluation = model.get("evaluation")
    gates = model.get("deployment_gates")
    if (not isinstance(support, int) or isinstance(support, bool) or support < 2
            or not isinstance(campaigns, int) or isinstance(campaigns, bool)
            or campaigns < support or not isinstance(evaluation, dict)
            or not isinstance(gates, dict)):
        raise DatasetError("model is missing training or evaluation metadata")
    for metric, gate in (
        ("top1_accuracy_when_covered", "minimum_top1_accuracy"),
        ("coverage", "minimum_coverage"),
    ):
        actual = evaluation.get(metric)
        required = gates.get(gate)
        if (not isinstance(actual, (int, float)) or isinstance(actual, bool)
                or not math.isfinite(actual) or not 0 <= actual <= 1
                or not isinstance(required, (int, float))
                or isinstance(required, bool) or not math.isfinite(required)
                or not 0 <= required <= 1 or actual < required):
            raise DatasetError("model does not satisfy its held-out deployment gates")
    benign_rate = evaluation.get("benign_supported_transition_rate")
    benign_gate = gates.get("maximum_benign_transition_rate")
    if (not isinstance(benign_rate, (int, float)) or isinstance(benign_rate, bool)
            or not math.isfinite(benign_rate) or not 0 <= benign_rate <= 1
            or not isinstance(benign_gate, (int, float))
            or isinstance(benign_gate, bool) or not math.isfinite(benign_gate)
            or not 0 <= benign_gate <= 1 or benign_rate > benign_gate):
        raise DatasetError("model does not satisfy its held-out benign-rate gate")
    transitions = model["transitions"]
    if not transitions:
        raise DatasetError("model has no campaign-supported transitions")
    for context, transition in transitions.items():
        context_tokens = context.split("|")
        if (len(context_tokens) > MAX_SEQUENCE_ORDER
                or any(not TOKEN_PATTERN.fullmatch(token) for token in context_tokens)
                or not isinstance(transition, dict)
                or not isinstance(transition.get("next_events"), dict)
                or not transition["next_events"]):
            raise DatasetError("model contains an invalid transition context")
        for next_event, candidate in transition["next_events"].items():
            if (not TOKEN_PATTERN.fullmatch(next_event)
                    or not isinstance(candidate, dict)
                    or not isinstance(candidate.get("episodes"), int)
                    or candidate["episodes"] < 1
                    or not isinstance(candidate.get("campaign_count"), int)
                    or candidate["campaign_count"] < support
                    or not isinstance(candidate.get("empirical_frequency"), (int, float))
                    or not math.isfinite(candidate["empirical_frequency"])
                    or not 0 < candidate["empirical_frequency"] <= 1):
                raise DatasetError("model contains an invalid transition candidate")
    return model


def _main(argv=None):
    parser = argparse.ArgumentParser(
        description="Train/evaluate an advisory event-sequence model on labeled JSONL."
    )
    parser.add_argument("--train", required=True, help="training JSONL episodes")
    parser.add_argument("--evaluate", required=True, help="campaign-disjoint held-out JSONL")
    parser.add_argument("--output", required=True, help="model artifact destination")
    parser.add_argument("--minimum-top1-accuracy", type=float, required=True)
    parser.add_argument("--minimum-coverage", type=float, required=True)
    parser.add_argument(
        "--maximum-benign-transition-rate", type=float, required=True
    )
    parser.add_argument("--minimum-campaign-support", type=int, default=3)
    args = parser.parse_args(argv)
    try:
        model = train_model(
            load_jsonl(args.train),
            load_jsonl(args.evaluate),
            min_campaign_support=args.minimum_campaign_support,
        )
        print(json.dumps(model["evaluation"], indent=2))
        save_model(
            model,
            args.output,
            minimum_top1_accuracy=args.minimum_top1_accuracy,
            minimum_coverage=args.minimum_coverage,
            maximum_benign_transition_rate=args.maximum_benign_transition_rate,
        )
        print(f"Advisory sequence model written to {args.output}")
        return 0
    except (DatasetError, OSError, json.JSONDecodeError) as error:
        print(f"Model training failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(_main())

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from server.intrusion_sequence_model import (
    DatasetError,
    _main,
    load_model,
    predict_next,
    save_model,
    train_model,
)


class IntrusionSequenceModelTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)

    @staticmethod
    def episode(campaign_id, events, label="attack"):
        return {
            "campaign_id": campaign_id,
            "label": label,
            "events": events,
        }

    def training_data(self):
        attack_sequence = [
            "windows.security.4625",
            "windows.security.4624",
            "windows.security.4672",
            "windows.system.7045",
        ]
        training = [
            self.episode(f"train-{index}", attack_sequence)
            for index in range(3)
        ]
        training.append(self.episode(
            "benign-training",
            ["windows.security.4625", "windows.security.4624",
             "windows.security.4740"],
            label="benign",
        ))
        evaluation = [
            self.episode("heldout-1", attack_sequence),
            self.episode("heldout-2", attack_sequence),
            self.episode(
                "benign-heldout",
                ["windows.security.4625", "windows.security.4624",
                 "windows.security.4740"],
                label="benign",
            ),
        ]
        return training, evaluation

    def test_trains_campaign_supported_model_and_reports_heldout_metrics(self):
        training, evaluation = self.training_data()

        model = train_model(training, evaluation, min_campaign_support=3)

        predictions = predict_next(
            model,
            ["windows.security.4625", "windows.security.4624"],
        )
        self.assertEqual("windows.security.4672", predictions[0]["event"])
        self.assertEqual(1.0, predictions[0]["frequency"])
        self.assertEqual(3, predictions[0]["campaign_count"])
        self.assertEqual(1.0, model["evaluation"]["coverage"])
        self.assertEqual(1.0, model["evaluation"]["top1_accuracy_when_covered"])
        self.assertEqual(1.0, model["evaluation"]["top3_accuracy_when_covered"])
        self.assertEqual(1.0, model["evaluation"]["benign_supported_transition_rate"])
        self.assertEqual("advisory_only", model["action_policy"])
        self.assertNotIn("train-0", json.dumps(model))
        self.assertIn("not calibrated", model["probability_semantics"])

    def test_abstains_for_unseen_or_below_campaign_support_transitions(self):
        training, evaluation = self.training_data()
        model = train_model(training, evaluation, min_campaign_support=3)

        self.assertEqual([], predict_next(model, ["windows.security.4698"]))
        self.assertEqual([], predict_next(
            model, ["windows.security.4625", "windows.security.4698"]
        ))

    def test_rejects_campaign_leakage_and_insufficient_attack_campaigns(self):
        sequence = ["auth.failed", "auth.success"]
        with self.assertRaisesRegex(DatasetError, "must not mix"):
            train_model(
                [
                    self.episode("mixed-campaign", sequence),
                    self.episode("mixed-campaign", sequence, "benign"),
                    self.episode("train-2", sequence),
                    self.episode("train-3", sequence),
                ],
                [
                    self.episode("heldout", sequence),
                    self.episode("benign-heldout", ["a", "b"], "benign"),
                ],
            )

        training = [
            self.episode("same-campaign", sequence),
            self.episode("train-2", sequence),
            self.episode("train-3", sequence),
            self.episode("benign-training", ["normal.a", "normal.b"], "benign"),
        ]
        evaluation = [self.episode("same-campaign", sequence)]
        with self.assertRaisesRegex(DatasetError, "campaign overlap"):
            train_model(
                training,
                evaluation + [
                    self.episode("benign-heldout", ["a", "b"], "benign")
                ],
            )

        with self.assertRaisesRegex(DatasetError, "distinct labeled attack campaigns"):
            train_model(
                [
                    self.episode("only-one", sequence),
                    self.episode("benign-training", ["normal.a", "normal.b"], "benign"),
                ],
                [
                    self.episode("heldout", sequence),
                    self.episode("benign-heldout", ["normal.a", "normal.b"], "benign"),
                ],
            )

    def test_rejects_invalid_labels_and_event_tokens(self):
        with self.assertRaisesRegex(DatasetError, "label"):
            train_model(
                [self.episode(f"train-{index}", ["a", "b"], "unknown")
                 for index in range(3)],
                [self.episode("heldout", ["a", "b"])],
            )
        with self.assertRaisesRegex(DatasetError, "invalid values"):
            train_model(
                [self.episode(f"train-{index}", ["valid", "../invalid"])
                 for index in range(3)],
                [self.episode("heldout", ["valid", "next"])],
            )

    def test_requires_explicit_quality_gate_and_saves_validated_artifact(self):
        training, evaluation = self.training_data()
        model = train_model(training, evaluation, min_campaign_support=3)
        path = os.path.join(self.temp_directory.name, "model.json")

        with self.assertRaisesRegex(DatasetError, "quality gates failed"):
            save_model(
                model, path,
                minimum_top1_accuracy=1.0,
                minimum_coverage=1.0,
                maximum_benign_transition_rate=0.0,
            )
        self.assertFalse(os.path.exists(path))

        saved = save_model(
            model, path,
            minimum_top1_accuracy=1.0,
            minimum_coverage=1.0,
            maximum_benign_transition_rate=1.0,
        )
        loaded = load_model(path)
        self.assertEqual(saved, loaded)
        self.assertEqual(
            "advisory_only",
            loaded["action_policy"],
        )
        self.assertEqual(
            "windows.security.4672",
            predict_next(
                loaded, ["windows.security.4625", "windows.security.4624"]
            )[0]["event"],
        )

    def test_command_line_requires_holdout_and_explicit_gates(self):
        training, evaluation = self.training_data()
        train_path = os.path.join(self.temp_directory.name, "train.jsonl")
        evaluation_path = os.path.join(self.temp_directory.name, "evaluation.jsonl")
        output_path = os.path.join(self.temp_directory.name, "model.json")
        for path, episodes in (
            (train_path, training),
            (evaluation_path, evaluation),
        ):
            with open(path, "w", encoding="utf-8") as destination:
                for episode in episodes:
                    destination.write(json.dumps(episode) + "\n")

        with patch("sys.stdout"), patch("sys.stderr"):
            result = _main([
                "--train", train_path,
                "--evaluate", evaluation_path,
                "--output", output_path,
                "--minimum-top1-accuracy", "1",
                "--minimum-coverage", "1",
                "--maximum-benign-transition-rate", "1",
            ])

        self.assertEqual(0, result)
        self.assertTrue(os.path.exists(output_path))


if __name__ == "__main__":
    unittest.main()

import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import Mock, patch

from agent.autonomous_defense import AutonomousDefense
from server.intrusion_sequence_model import train_model


SERVER_DIRECTORY = Path(__file__).resolve().parents[1] / "server"
sys.path.insert(0, str(SERVER_DIRECTORY))
try:
    import threat_analyzer as server_threat_analyzer

    with patch.object(server_threat_analyzer.CompromiseTracker, "_init_compromise_table"):
        import server_v2_ai_autonomous as server
finally:
    sys.path.remove(str(SERVER_DIRECTORY))


class ServerAgentFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.database = os.path.join(self.temp_directory.name, "flow.db")
        self.previous_db = server.DB
        self.previous_api_key = server.API_KEY
        self.previous_engine = server.response_engine
        self.previous_analyzer = server.threat_analyzer
        self.previous_sequence_model = server.intrusion_sequence_model
        server.DB = self.database
        server.API_KEY = "flow-test-key"
        server.response_engine = server.AutonomousResponseEngine(self.database)
        server.threat_analyzer = Mock()
        server.threat_analyzer.analyze_threat_with_ai.return_value = {
            "threat_type": "unknown",
            "severity": "high",
            "confidence": 0.5,
            "root_cause": "Synthetic test telemetry",
            "recommendation": "investigate_further",
        }
        self.environment = patch.dict(os.environ, {
            "DEFENSE_ENABLED": "true",
            "DEFENSE_SAFE_MODE": "false",
            "DEFENSE_ISOLATION_ENABLED": "false",
        })
        self.environment.start()
        server.init_db()
        server.app.config["TESTING"] = True
        self.client = server.app.test_client()
        self.addCleanup(self.cleanup)

    def cleanup(self):
        self.environment.stop()
        server.DB = self.previous_db
        server.API_KEY = self.previous_api_key
        server.response_engine = self.previous_engine
        server.threat_analyzer = self.previous_analyzer
        server.intrusion_sequence_model = self.previous_sequence_model
        self.temp_directory.cleanup()

    def test_telemetry_to_agent_outcome_and_action_history(self):
        host_id = "flow-test-host"
        headers = {"X-API-KEY": server.API_KEY}
        telemetry = {
            "host_id": host_id,
            "ts": 1710000000,
            "cpu": 12,
            "ram": {"percent": 30},
            "disk": {"percent": 40},
            "processes": [{
                "pid": 4321,
                "name": "crypto-miner.exe",
                "create_time_us": 123456000,
            }],
            "strange_ips": [],
        }

        ingest_response = self.client.post("/ingest", json=telemetry, headers=headers)
        self.assertEqual(200, ingest_response.status_code)
        server.threat_analyzer.analyze_threat_with_ai.assert_called_once()

        dashboard_response = self.client.get("/")
        self.assertEqual(200, dashboard_response.status_code)
        self.assertIn(b"Fleet overview", dashboard_response.data)
        self.assertIn(b"/static/app.css", dashboard_response.data)
        self.assertIn(b"flow-test-host", dashboard_response.data)
        stylesheet_response = self.client.get("/static/app.css")
        self.assertEqual(200, stylesheet_response.status_code)
        self.assertIn(b"@media (max-width: 560px)", stylesheet_response.data)
        stylesheet_response.close()
        self.assertIn(b"Endpoint fleet", dashboard_response.data)
        self.assertIn(b"Response activity", dashboard_response.data)
        endpoint_response = self.client.get(f"/agent/{host_id}")
        self.assertEqual(200, endpoint_response.status_code)
        self.assertIn(b"Process inventory", endpoint_response.data)
        analysis_response = self.client.get(f"/analysis/{host_id}")
        self.assertEqual(200, analysis_response.status_code)
        self.assertIn(b"informational, not response authorization", analysis_response.data)

        # Durable commands remain available when the server is reinitialized.
        server.init_db()
        poll_response = self.client.get(
            "/get_defense_commands", query_string={"host_id": host_id}, headers=headers
        )
        self.assertEqual(200, poll_response.status_code)
        commands = poll_response.get_json()["commands"]
        self.assertEqual(1, len(commands))
        self.assertEqual("kill_process", commands[0]["action"])
        self.assertEqual(telemetry["processes"], commands[0]["targets"])
        command_id = commands[0]["command_id"]

        immediate_retry = self.client.get(
            "/get_defense_commands", query_string={"host_id": host_id}, headers=headers
        )
        self.assertEqual([], immediate_retry.get_json()["commands"])
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute(
                """UPDATE defense_commands SET last_delivered_at = 0
                   WHERE command_id = ?""",
                (command_id,),
            )
            connection.commit()

        retry_response = self.client.get(
            "/get_defense_commands", query_string={"host_id": host_id}, headers=headers
        )
        retried_command = retry_response.get_json()["commands"][0]
        self.assertEqual(command_id, retried_command["command_id"])

        defense = AutonomousDefense(
            state_db=os.path.join(self.temp_directory.name, "agent-state.db")
        )
        defense.host_id = host_id
        process = Mock()
        process.name.return_value = "crypto-miner.exe"
        process.create_time.return_value = 123.456
        with patch("agent.autonomous_defense.psutil.Process", return_value=process):
            outcome = defense.execute_command(retried_command)
        self.assertEqual("executed", outcome["status"])
        self.assertEqual(command_id, outcome["command_id"])
        process.terminate.assert_called_once_with()

        mismatched_report = self.client.post(
            "/report_defense_action",
            json={**outcome, "host_id": "different-host"},
            headers=headers,
        )
        self.assertEqual(400, mismatched_report.status_code)
        with closing(sqlite3.connect(self.database)) as connection:
            status = connection.execute(
                "SELECT status FROM defense_commands WHERE command_id = ?",
                (command_id,),
            ).fetchone()[0]
        self.assertEqual("delivered", status)

        report_response = self.client.post(
            "/report_defense_action", json=outcome, headers=headers
        )
        self.assertEqual(200, report_response.status_code)
        duplicate_report = self.client.post(
            "/report_defense_action", json=outcome, headers=headers
        )
        self.assertEqual(200, duplicate_report.status_code)
        self.assertEqual(
            report_response.get_json()["report_id"],
            duplicate_report.get_json()["report_id"],
        )

        with closing(sqlite3.connect(self.database)) as connection:
            server_decision = connection.execute(
                "SELECT execution_result FROM response_log WHERE host_id = ?",
                (host_id,),
            ).fetchone()
            agent_report = connection.execute(
                "SELECT command, status FROM agent_action_log WHERE host_id = ?",
                (host_id,),
            ).fetchone()
            agent_report_count = connection.execute(
                "SELECT COUNT(*) FROM agent_action_log WHERE command_id = ?",
                (command_id,),
            ).fetchone()[0]
            command_record = connection.execute(
                """SELECT status, delivery_attempts FROM defense_commands
                   WHERE command_id = ?""",
                (command_id,),
            ).fetchone()
        self.assertIn("awaiting agent execution", server_decision[0])
        self.assertEqual(("kill_process", "executed"), agent_report)
        self.assertEqual(1, agent_report_count)
        self.assertEqual(("reported", 2), command_record)

        after_ack = self.client.get(
            "/get_defense_commands", query_string={"host_id": host_id}, headers=headers
        )
        self.assertEqual([], after_ack.get_json()["commands"])

        history_response = self.client.get(f"/actions/{host_id}")
        self.assertEqual(200, history_response.status_code)
        self.assertIn(b"server decision", history_response.data)
        self.assertIn(b"agent report", history_response.data)
        self.assertIn(b"awaiting agent execution", history_response.data)
        self.assertIn(b"executed:", history_response.data)
        self.assertIn(b"<th>Outcome</th>", history_response.data)

    def test_unauthorized_agent_report_is_not_persisted(self):
        response = self.client.post(
            "/report_defense_action",
            json={
                "host_id": "flow-test-host",
                "command": "kill_process",
                "status": "executed",
                "details": {},
            },
            headers={"X-API-KEY": "wrong-key"},
        )
        self.assertEqual(401, response.status_code)
        with closing(sqlite3.connect(self.database)) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM agent_action_log"
            ).fetchone()[0]
        self.assertEqual(0, count)

    def test_failed_logon_burst_creates_alert_only_threat_without_response(self):
        host_id = "auth-alert-host"
        now = time.time()
        telemetry = {
            "host_id": host_id,
            "ts": now,
            "cpu": 10,
            "ram": {"percent": 20},
            "disk": {"percent": 30},
            "processes": [],
            "auth_monitor": {
                "source": "windows_intrusion_events",
                "status": "ready",
                "detail": "Monitoring selected Windows Security and System events.",
                "channels": {"Security": "ready", "System": "ready"},
                "events": [{
                    "channel": "Security",
                    "record_id": record_id,
                    "event_id": 4625,
                    "ts": now - index,
                    "source_ip": "203.0.113.8",
                    "logon_type": "10",
                    "source_port": str(53000 + index),
                    "workstation_name": "reported-client",
                    "status_code": "0xC000006D",
                    "substatus_code": "0xC000006A",
                } for index, record_id in enumerate(range(100, 105))],
            },
        }
        headers = {"X-API-KEY": server.API_KEY}

        response = self.client.post("/ingest", json=telemetry, headers=headers)
        self.assertEqual(200, response.status_code)
        self.assertEqual(1, response.get_json()["alerts_created"])
        server.threat_analyzer.analyze_threat_with_ai.assert_not_called()

        with closing(sqlite3.connect(self.database)) as connection:
            threats = connection.execute(
                """SELECT threat_type, severity, description FROM threats
                   WHERE host_id = ?""",
                (host_id,),
            ).fetchall()
            command_count = connection.execute(
                "SELECT COUNT(*) FROM defense_commands WHERE host_id = ?",
                (host_id,),
            ).fetchone()[0]
            response_count = connection.execute(
                "SELECT COUNT(*) FROM response_log WHERE host_id = ?",
                (host_id,),
            ).fetchone()[0]
            stored_telemetry = connection.execute(
                "SELECT data FROM telemetry WHERE host_id = ?",
                (host_id,),
            ).fetchone()[0]
            intrusion_event_count = connection.execute(
                "SELECT COUNT(*) FROM intrusion_events WHERE host_id = ?",
                (host_id,),
            ).fetchone()[0]
            threat_evidence = json.loads(connection.execute(
                "SELECT telemetry_data FROM threats WHERE host_id = ?",
                (host_id,),
            ).fetchone()[0])

        self.assertEqual(1, len(threats))
        self.assertEqual("intrusion_failed_logon_burst", threats[0][0])
        self.assertEqual("medium", threats[0][1])
        self.assertIn("Alert only", threats[0][2])
        self.assertEqual(0, command_count)
        self.assertEqual(0, response_count)
        self.assertNotIn("events", json.loads(stored_telemetry)["auth_monitor"])
        self.assertEqual(5, intrusion_event_count)
        self.assertEqual("non-global / private or special-use",
                         threat_evidence["source_scope"])
        self.assertEqual(["reported-client"],
                         threat_evidence["reported_workstations"])
        self.assertEqual([53000, 53001, 53002, 53003, 53004],
                         threat_evidence["source_ports"])
        self.assertEqual(["0xC000006D/0xC000006A"],
                         threat_evidence["failure_codes"])
        self.assertEqual(["incorrect password", "invalid account or password"],
                         threat_evidence["failure_reasons"])
        prediction = threat_evidence["path_prediction"]
        self.assertEqual("low", prediction["confidence"])
        self.assertEqual("hypothesis_not_observed", prediction["status"])
        self.assertEqual("recommendation_only", prediction["automation"])
        self.assertEqual(
            [
                "Windows event pattern: intrusion_failed_logon_burst",
                "Supporting event count: 5",
                "Affected endpoints: 1",
            ],
            prediction["basis"],
        )
        self.assertIn("another exposed authentication service",
                      prediction["next_likely_step"])
        self.assertIn("MFA", prediction["protective_action"])
        self.assertNotIn("private-account", str(threat_evidence))

        repeated = self.client.post("/ingest", json=telemetry, headers=headers)
        self.assertEqual(0, repeated.get_json()["alerts_created"])
        dashboard = self.client.get("/")
        self.assertIn(b"Failed Logon Burst", dashboard.data)
        self.assertIn(b"alert-only Windows intrusion alerts", dashboard.data)
        self.assertIn(b"Security: ready", dashboard.data)
        self.assertIn(b"203.0.113.8", dashboard.data)
        self.assertIn(b"Reported workstation(s) (unverified): reported-client",
                      dashboard.data)
        self.assertIn(b"Windows failure code(s)", dashboard.data)
        self.assertIn(b"incorrect password", dashboard.data)
        self.assertIn(b"Rules-based possible next step", dashboard.data)
        self.assertIn(b"Hypothesis, not observed", dashboard.data)
        self.assertIn(b"Close a door:", dashboard.data)

    def test_password_spray_across_hosts_creates_one_alert_only_fleet_record(self):
        headers = {"X-API-KEY": server.API_KEY}
        now = time.time()
        responses = []
        for host_index in range(3):
            for attempt in range(4):
                host_id = f"spray-host-{host_index}"
                responses.append(self.client.post(
                    "/ingest",
                    json={
                        "host_id": host_id, "ts": now,
                        "cpu": 10, "ram": {"percent": 20},
                        "disk": {"percent": 30}, "processes": [],
                        "auth_monitor": {
                            "status": "degraded",
                            "events": [{
                                "channel": "Security",
                                "record_id": host_index * 10 + attempt + 1,
                                "event_id": 4625,
                                "ts": now - attempt,
                                "source_ip": "203.0.113.22",
                            }],
                        },
                    },
                    headers=headers,
                ))

        self.assertTrue(all(response.status_code == 200 for response in responses))
        with closing(sqlite3.connect(self.database)) as connection:
            spray_count = connection.execute(
                """SELECT COUNT(*) FROM threats
                   WHERE threat_type = 'intrusion_password_spray'"""
            ).fetchone()[0]
            commands = connection.execute(
                "SELECT COUNT(*) FROM defense_commands"
            ).fetchone()[0]
            responses_count = connection.execute(
                "SELECT COUNT(*) FROM response_log"
            ).fetchone()[0]
            spray_evidence = json.loads(connection.execute(
                """SELECT telemetry_data FROM threats
                   WHERE threat_type = 'intrusion_password_spray'"""
            ).fetchone()[0])
        self.assertEqual(1, spray_count)
        self.assertEqual(0, commands)
        self.assertEqual(0, responses_count)
        self.assertEqual(
            ["spray-host-0", "spray-host-1", "spray-host-2"],
            spray_evidence["affected_hosts"],
        )
        self.assertGreaterEqual(spray_evidence["failed_logons"], 10)
        self.assertEqual(
            "hypothesis_not_observed",
            spray_evidence["path_prediction"]["status"],
        )
        self.assertEqual(
            "recommendation_only",
            spray_evidence["path_prediction"]["automation"],
        )
        self.assertIn(
            "Affected endpoints: 3",
            spray_evidence["path_prediction"]["basis"],
        )
        self.assertIn("additional hosts or services",
                      spray_evidence["path_prediction"]["next_likely_step"])
        dashboard = self.client.get("/")
        self.assertIn(b"Affected endpoints: spray-host-0, spray-host-1, spray-host-2",
                      dashboard.data)
        server.threat_analyzer.analyze_threat_with_ai.assert_not_called()

    def test_success_after_failures_and_selected_windows_events_are_alert_only(self):
        host_id = "correlated-auth-host"
        now = time.time()
        base = {
            "host_id": host_id, "ts": now,
            "cpu": 10, "ram": {"percent": 20},
            "disk": {"percent": 30}, "processes": [],
        }
        headers = {"X-API-KEY": server.API_KEY}
        failed = [{
            "channel": "Security", "record_id": record_id,
            "event_id": 4625, "ts": now - (4 - record_id),
            "source_ip": "203.0.113.33",
        } for record_id in (1, 2, 3)]
        self.client.post(
            "/ingest",
            json={**base, "auth_monitor": {"status": "ready", "events": failed}},
            headers=headers,
        )
        correlated_events = [
            {
                "channel": "Security", "record_id": 4, "event_id": 4624,
                "ts": now, "source_ip": "203.0.113.33", "logon_type": "10",
                "logon_id": "0xabc",
                "source_port": "3389", "workstation_name": "rdp-client",
            },
            {
                "channel": "Security", "record_id": 5, "event_id": 4672,
                "ts": now + 1, "logon_id": "0xabc",
            },
            {"channel": "Security", "record_id": 6, "event_id": 4740, "ts": now},
            {"channel": "Security", "record_id": 7, "event_id": 4698, "ts": now},
            {"channel": "System", "record_id": 8, "event_id": 7045, "ts": now},
        ]
        response = self.client.post(
            "/ingest",
            json={**base, "auth_monitor": {
                "status": "ready", "events": correlated_events,
                "checkpoints": {"Security": 7, "System": 8},
            }},
            headers=headers,
        )

        self.assertEqual(200, response.status_code)
        self.assertEqual(5, response.get_json()["alerts_created"])
        server.threat_analyzer.analyze_threat_with_ai.assert_not_called()
        with closing(sqlite3.connect(self.database)) as connection:
            threat_types = {
                row[0] for row in connection.execute(
                    "SELECT threat_type FROM threats WHERE host_id = ?", (host_id,)
                )
            }
            queued = connection.execute(
                "SELECT COUNT(*) FROM defense_commands WHERE host_id = ?",
                (host_id,),
            ).fetchone()[0]
            stored = json.loads(connection.execute(
                "SELECT data FROM telemetry WHERE host_id = ? ORDER BY id DESC LIMIT 1",
                (host_id,),
            ).fetchone()[0])
            success_evidence = json.loads(connection.execute(
                """SELECT telemetry_data FROM threats
                   WHERE host_id = ? AND threat_type = 'intrusion_failed_logon_success'""",
                (host_id,),
            ).fetchone()[0])
        self.assertEqual({
            "intrusion_failed_logon_success",
            "intrusion_interactive_privileged_logon",
            "intrusion_account_lockout",
            "intrusion_scheduled_task_created",
            "intrusion_service_installed",
        }, threat_types)
        self.assertEqual(0, queued)
        self.assertEqual("203.0.113.33", success_evidence["source_ip"])
        self.assertEqual(3389, success_evidence["source_port"])
        self.assertEqual("rdp-client", success_evidence["reported_workstation"])
        self.assertEqual("10", success_evidence["success_logon_type"])
        self.assertNotIn("events", stored["auth_monitor"])
        self.assertNotIn("checkpoints", stored["auth_monitor"])
        repeated = self.client.post(
            "/ingest",
            json={**base, "auth_monitor": {
                "status": "ready", "events": correlated_events,
            }},
            headers=headers,
        )
        self.assertEqual(0, repeated.get_json()["alerts_created"])

    def test_validated_sequence_model_adds_advisory_next_event_candidates(self):
        event_sequence = [
            "windows.security.4625",
            "windows.security.4624",
            "windows.security.4672",
        ]
        benign_sequence = [
            "windows.security.4625",
            "windows.security.4624",
            "windows.security.4740",
        ]
        server.intrusion_sequence_model = train_model(
            [
                {"campaign_id": f"model-training-{index}",
                 "label": "attack", "events": event_sequence}
                for index in range(3)
            ] + [{
                "campaign_id": "model-benign-training",
                "label": "benign", "events": benign_sequence,
            }],
            [
                {
                    "campaign_id": "model-heldout",
                    "label": "attack", "events": event_sequence,
                },
                {
                    "campaign_id": "model-benign-heldout",
                    "label": "benign", "events": benign_sequence,
                },
            ],
        )
        now = time.time()
        response = self.client.post(
            "/ingest",
            json={
                "host_id": "sequence-model-host", "ts": now,
                "cpu": 10, "ram": {"percent": 20},
                "disk": {"percent": 30}, "processes": [],
                "auth_monitor": {
                    "status": "ready",
                    "events": [{
                        "channel": "Security",
                        "record_id": record_id,
                        "event_id": 4625,
                        "ts": now - index,
                        "source_ip": "203.0.113.77",
                    } for index, record_id in enumerate(range(700, 705))],
                },
            },
            headers={"X-API-KEY": server.API_KEY},
        )
        self.assertEqual(200, response.status_code)
        with closing(sqlite3.connect(self.database)) as connection:
            evidence = json.loads(connection.execute(
                """SELECT telemetry_data FROM threats
                   WHERE host_id = ? AND threat_type = 'intrusion_failed_logon_burst'""",
                ("sequence-model-host",),
            ).fetchone()[0])
            command_count = connection.execute(
                "SELECT COUNT(*) FROM defense_commands"
            ).fetchone()[0]
        learned = evidence["path_prediction"]["learned_next_events"]
        self.assertEqual(
            "windows.security.4624",
            learned["candidates"][0]["event"],
        )
        self.assertEqual("successful logon", learned["candidates"][0]["event_name"])
        self.assertEqual(1.0, learned["candidates"][0]["frequency"])
        self.assertEqual(3, learned["candidates"][0]["campaign_count"])
        self.assertEqual(1.0, learned["held_out_top1_accuracy"])
        self.assertIn("not an attacker probability", learned["ranking_semantics"])
        self.assertEqual("advisory_only", learned["automation"])
        self.assertEqual(0, command_count)
        dashboard = self.client.get("/")
        self.assertIn(b"Labeled-sequence model", dashboard.data)
        self.assertIn(b"empirical frequency, not attacker probability",
                      dashboard.data)
        self.assertIn(b"successful logon", dashboard.data)

    def test_failed_logons_without_source_ips_do_not_form_a_burst(self):
        now = time.time()
        telemetry = {
            "host_id": "auth-alert-no-source-host",
            "ts": now,
            "cpu": 10,
            "ram": {"percent": 20},
            "disk": {"percent": 30},
            "processes": [],
            "auth_monitor": {
                "status": "ready",
                "events": [{
                    "record_id": record_id,
                    "event_id": 4625,
                    "ts": now - index,
                    "source_ip": None,
                } for index, record_id in enumerate(range(200, 206))],
            },
        }

        response = self.client.post(
            "/ingest",
            json=telemetry,
            headers={"X-API-KEY": server.API_KEY},
        )

        self.assertEqual(200, response.status_code)
        self.assertEqual(0, response.get_json()["alerts_created"])
        with closing(sqlite3.connect(self.database)) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM threats WHERE host_id = ?",
                (telemetry["host_id"],),
            ).fetchone()[0]
        self.assertEqual(0, count)

    def test_authenticated_health_check_is_read_only_and_reports_defense_state(self):
        headers = {"X-API-KEY": server.API_KEY}
        with closing(sqlite3.connect(self.database)) as connection:
            before = connection.execute(
                "SELECT COUNT(*) FROM defense_commands"
            ).fetchone()[0]

        unauthorized = self.client.get("/health")
        self.assertEqual(401, unauthorized.status_code)
        with patch.dict(os.environ, {
            "DEFENSE_ENABLED": "true",
            "DEFENSE_SAFE_MODE": "false",
        }):
            response = self.client.get("/health", headers=headers)

        self.assertEqual(200, response.status_code)
        self.assertEqual({"ok": True, "defense_enabled": True}, response.get_json())
        with closing(sqlite3.connect(self.database)) as connection:
            after = connection.execute(
                "SELECT COUNT(*) FROM defense_commands"
            ).fetchone()[0]
        self.assertEqual(before, after)

    def test_safe_mode_cancels_pending_delivery_across_reenable(self):
        host_id = "safe-mode-host"
        telemetry = {
            "host_id": host_id,
            "cpu": 10,
            "ram": {"percent": 20},
            "disk": {"percent": 20},
            "processes": [{
                "pid": 9876,
                "name": "malware-test.exe",
                "create_time_us": 987654321,
            }],
        }
        headers = {"X-API-KEY": server.API_KEY}
        self.assertEqual(
            200,
            self.client.post("/ingest", json=telemetry, headers=headers).status_code,
        )
        with patch.dict(os.environ, {"DEFENSE_SAFE_MODE": "true"}):
            disabled_poll = self.client.get(
                "/get_defense_commands",
                query_string={"host_id": host_id},
                headers=headers,
            )
        self.assertEqual([], disabled_poll.get_json()["commands"])

        with patch.dict(os.environ, {"DEFENSE_SAFE_MODE": "false"}):
            enabled_poll = self.client.get(
                "/get_defense_commands",
                query_string={"host_id": host_id},
                headers=headers,
            )
        self.assertEqual([], enabled_poll.get_json()["commands"])
        with closing(sqlite3.connect(self.database)) as connection:
            status = connection.execute(
                "SELECT status FROM defense_commands WHERE host_id = ?",
                (host_id,),
            ).fetchone()[0]
        self.assertEqual("cancelled", status)

    def test_agent_outbox_retries_report_without_reexecuting_redelivered_command(self):
        host_id = "outbox-test-host"
        telemetry = {
            "host_id": host_id,
            "cpu": 10,
            "ram": {"percent": 20},
            "disk": {"percent": 20},
            "processes": [{
                "pid": 8765,
                "name": "miner-outbox.exe",
                "create_time_us": 876543210,
            }],
        }
        headers = {"X-API-KEY": server.API_KEY}
        self.assertEqual(
            200,
            self.client.post("/ingest", json=telemetry, headers=headers).status_code,
        )

        defense = AutonomousDefense(
            state_db=os.path.join(self.temp_directory.name, "agent-outbox.db")
        )
        defense.host_id = host_id
        process = Mock()
        process.name.return_value = "miner-outbox.exe"
        process.create_time.return_value = 876.54321
        delivered_commands = []

        def get_response(url, **kwargs):
            if delivered_commands:
                return Mock(
                    status_code=200,
                    json=lambda: {"commands": delivered_commands},
                )
            response = self.client.get(
                "/get_defense_commands",
                query_string={"host_id": host_id},
                headers=kwargs["headers"],
            )
            payload = response.get_json()
            delivered_commands.extend(payload["commands"])
            return Mock(status_code=response.status_code, json=lambda: payload)
        post_attempts = 0

        def post_response(url, **kwargs):
            nonlocal post_attempts
            post_attempts += 1
            if post_attempts == 1:
                return Mock(status_code=503)
            return self.client.post(
                "/report_defense_action",
                json=kwargs["json"],
                headers=kwargs["headers"],
            )

        with patch("agent.autonomous_defense.API_KEY", server.API_KEY), \
             patch("agent.autonomous_defense.requests.get", side_effect=get_response), \
             patch("agent.autonomous_defense.requests.post", side_effect=post_response) as post, \
             patch("agent.autonomous_defense.psutil.Process", return_value=process):
            self.assertTrue(defense.check_for_commands())
            defense = AutonomousDefense(
                state_db=os.path.join(self.temp_directory.name, "agent-outbox.db")
            )
            defense.host_id = host_id
            self.assertTrue(defense.check_for_commands())

        process.terminate.assert_called_once_with()
        self.assertEqual(3, post.call_count)
        with closing(sqlite3.connect(self.database)) as connection:
            command_record = connection.execute(
                """SELECT status, delivery_attempts FROM defense_commands
                   WHERE host_id = ?""",
                (host_id,),
            ).fetchone()
            report_count = connection.execute(
                """SELECT COUNT(*) FROM agent_action_log
                   WHERE host_id = ? AND command_id IS NOT NULL""",
                (host_id,),
            ).fetchone()[0]
        self.assertEqual(("reported", 1), command_record)
        self.assertEqual(1, report_count)

    def test_interrupted_command_is_reported_unknown_without_reexecution(self):
        host_id = "interrupted-test-host"
        telemetry = {
            "host_id": host_id,
            "cpu": 10,
            "ram": {"percent": 20},
            "disk": {"percent": 20},
            "processes": [{
                "pid": 8766,
                "name": "miner-interrupted.exe",
                "create_time_us": 876543210,
            }],
        }
        headers = {"X-API-KEY": server.API_KEY}
        self.assertEqual(
            200,
            self.client.post("/ingest", json=telemetry, headers=headers).status_code,
        )
        queued = self.client.get(
            "/get_defense_commands",
            query_string={"host_id": host_id},
            headers=headers,
        ).get_json()["commands"][0]

        state_db = os.path.join(self.temp_directory.name, "interrupted-agent.db")
        defense = AutonomousDefense(state_db=state_db)
        defense.host_id = host_id
        self.assertEqual((True, None), defense._prepare_command_execution(queued))
        self.assertEqual((False, None), defense._prepare_command_execution(queued))
        with closing(sqlite3.connect(state_db)) as connection:
            connection.execute(
                """UPDATE defense_action_outbox
                   SET execution_pid = 0, execution_create_time = 0
                   WHERE command_id = ?""",
                (queued["command_id"],),
            )
            connection.commit()

        restarted_defense = AutonomousDefense(state_db=state_db)
        restarted_defense.host_id = host_id
        process = Mock()
        process.name.return_value = "miner-interrupted.exe"
        process.create_time.return_value = 876.54321

        with patch("agent.autonomous_defense.API_KEY", server.API_KEY), \
             patch(
                 "agent.autonomous_defense.requests.get",
                 return_value=Mock(status_code=200, json=lambda: {"commands": [queued]}),
             ), \
             patch(
                 "agent.autonomous_defense.requests.post",
                 side_effect=lambda url, **kwargs: self.client.post(
                     "/report_defense_action",
                     json=kwargs["json"],
                     headers=kwargs["headers"],
                 ),
             ), \
             patch("agent.autonomous_defense.psutil.Process", return_value=process):
            self.assertTrue(restarted_defense.check_for_commands())

        process.terminate.assert_not_called()
        with closing(sqlite3.connect(self.database)) as connection:
            report = connection.execute(
                """SELECT status, details FROM agent_action_log
                   WHERE host_id = ? AND command_id = ?""",
                (host_id, queued["command_id"]),
            ).fetchone()
        self.assertEqual("unknown", report[0])
        self.assertIn("was not retried", report[1])
        audit_response = self.client.get(f"/actions/{host_id}")
        self.assertIn(b"Outcome unknown.", audit_response.data)
        self.assertIn(b"unknown", audit_response.data)

    def test_dry_run_command_reports_via_server_without_termination(self):
        host_id = "dry-run-test-host"
        telemetry = {
            "host_id": host_id,
            "cpu": 10,
            "ram": {"percent": 20},
            "disk": {"percent": 20},
            "processes": [{
                "pid": 8767,
                "name": "miner-dryrun.exe",
                "create_time_us": 876543210,
            }],
        }
        headers = {"X-API-KEY": server.API_KEY}
        self.assertEqual(
            200,
            self.client.post("/ingest", json=telemetry, headers=headers).status_code,
        )
        defense = AutonomousDefense(
            state_db=os.path.join(self.temp_directory.name, "dry-run-agent.db")
        )
        defense.host_id = host_id
        process = Mock()
        process.name.return_value = "miner-dryrun.exe"
        process.create_time.return_value = 876.54321

        with patch.dict(os.environ, {"DEFENSE_DRY_RUN": "true"}), \
             patch("agent.autonomous_defense.API_KEY", server.API_KEY), \
             patch("agent.autonomous_defense.psutil.Process", return_value=process), \
             patch(
                 "agent.autonomous_defense.requests.get",
                 side_effect=lambda url, **kwargs: self._requests_response(
                     self.client.get(
                         "/get_defense_commands",
                         query_string={"host_id": host_id},
                         headers=kwargs["headers"],
                     )
                 ),
             ), \
             patch(
                 "agent.autonomous_defense.requests.post",
                 side_effect=lambda url, **kwargs: self.client.post(
                     "/report_defense_action",
                     json=kwargs["json"],
                     headers=kwargs["headers"],
                 ),
             ), patch("agent.autonomous_defense.logger.debug") as debug_log:
            self.assertTrue(
                defense.check_for_commands(),
                msg=f"Command polling failed: {debug_log.call_args_list}",
            )

        process.terminate.assert_not_called()
        with closing(sqlite3.connect(self.database)) as connection:
            outcome = connection.execute(
                """SELECT c.status, l.status FROM defense_commands c
                   JOIN agent_action_log l ON l.command_id = c.command_id
                   WHERE c.host_id = ?""",
                (host_id,),
            ).fetchone()
        self.assertEqual(("reported", "dry_run"), outcome)
        audit_response = self.client.get(f"/actions/{host_id}")
        self.assertIn(b'class="status dry-run">dry run</span>', audit_response.data)

    @staticmethod
    def _requests_response(response):
        return Mock(status_code=response.status_code, json=response.get_json)


if __name__ == "__main__":
    unittest.main()

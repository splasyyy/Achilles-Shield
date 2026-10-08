import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import Mock, patch

from agent.autonomous_defense import AutonomousDefense


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

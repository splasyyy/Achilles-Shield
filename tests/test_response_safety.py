import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest.mock import Mock, patch

from agent.autonomous_defense import (
    AutonomousDefense,
    DEFAULT_PROTECTED_PROCESS_NAMES as AGENT_DEFAULT_PROTECTED_PROCESS_NAMES,
    MAX_PROCESSES_PER_COMMAND as AGENT_MAX_PROCESSES_PER_COMMAND,
    MIN_CPU_FOR_ISOLATION as AGENT_MIN_CPU_FOR_ISOLATION,
    MIN_EXTERNAL_IPS_FOR_ISOLATION as AGENT_MIN_EXTERNAL_IPS_FOR_ISOLATION,
    MIN_PROCESSES_FOR_RESOURCE_SIGNAL as AGENT_MIN_PROCESSES_FOR_RESOURCE_SIGNAL,
    PROTECTED_PROCESS_NAMES as AGENT_PROTECTED_PROCESS_NAMES,
    SUSPICIOUS_PROCESS_MARKERS as AGENT_SUSPICIOUS_PROCESS_MARKERS,
    assess_isolation_evidence as assess_agent_isolation_evidence,
    normalize_server_url,
)
from server.threat_analyzer import (
    AutonomousResponseEngine,
    DEFAULT_PROTECTED_PROCESS_NAMES as SERVER_DEFAULT_PROTECTED_PROCESS_NAMES,
    MAX_PROCESSES_PER_RESPONSE as SERVER_MAX_PROCESSES_PER_RESPONSE,
    MIN_CPU_FOR_ISOLATION as SERVER_MIN_CPU_FOR_ISOLATION,
    MIN_EXTERNAL_IPS_FOR_ISOLATION as SERVER_MIN_EXTERNAL_IPS_FOR_ISOLATION,
    MIN_PROCESSES_FOR_RESOURCE_SIGNAL as SERVER_MIN_PROCESSES_FOR_RESOURCE_SIGNAL,
    PROTECTED_PROCESS_NAMES as SERVER_PROTECTED_PROCESS_NAMES,
    SUSPICIOUS_PROCESS_MARKERS as SERVER_SUSPICIOUS_PROCESS_MARKERS,
    assess_isolation_evidence,
    log_response_action,
    persist_agent_action_report,
)


class ResponseAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.engine = AutonomousResponseEngine(":memory:")
        self.analysis = {
            "threat_type": "ransomware",
            "severity": "critical",
            "confidence": 0.99,
            "root_cause": "Synthetic test analysis",
            "recommendation": "isolate_machine",
            "suspicious_processes": ["attacker-supplied.exe"],
        }
        self.enabled = patch.dict(
            os.environ,
            {"DEFENSE_ENABLED": "true", "DEFENSE_SAFE_MODE": "false"},
        )
        self.enabled.start()
        self.addCleanup(self.enabled.stop)

    def test_server_and_agent_response_policies_stay_in_sync(self):
        self.assertEqual(
            SERVER_SUSPICIOUS_PROCESS_MARKERS,
            AGENT_SUSPICIOUS_PROCESS_MARKERS,
        )
        self.assertEqual(
            SERVER_MAX_PROCESSES_PER_RESPONSE,
            AGENT_MAX_PROCESSES_PER_COMMAND,
        )
        self.assertEqual(
            SERVER_MIN_EXTERNAL_IPS_FOR_ISOLATION,
            AGENT_MIN_EXTERNAL_IPS_FOR_ISOLATION,
        )
        self.assertEqual(SERVER_MIN_CPU_FOR_ISOLATION, AGENT_MIN_CPU_FOR_ISOLATION)
        self.assertEqual(
            SERVER_MIN_PROCESSES_FOR_RESOURCE_SIGNAL,
            AGENT_MIN_PROCESSES_FOR_RESOURCE_SIGNAL,
        )
        self.assertEqual(
            SERVER_DEFAULT_PROTECTED_PROCESS_NAMES,
            AGENT_DEFAULT_PROTECTED_PROCESS_NAMES,
        )
        self.assertEqual(SERVER_PROTECTED_PROCESS_NAMES, AGENT_PROTECTED_PROCESS_NAMES)

        telemetry = {
            "cpu": 98,
            "processes": [
                {"pid": 1234, "name": "Crypto-Miner.exe"},
                {"pid": 2345, "name": "svchost.exe"},
                {"pid": True, "name": "malware-bogus.exe"},
                {"pid": 4, "name": "malware-kernel.exe"},
            ] + [
                {"pid": pid, "name": f"worker-{pid}.exe"}
                for pid in range(3000, 3210)
            ],
            "strange_ips": [f"8.8.8.{index}" for index in range(1, 7)]
                + ["127.0.0.1", "invalid"],
        }
        self.assertEqual(
            assess_isolation_evidence(telemetry),
            assess_agent_isolation_evidence(telemetry),
        )

        candidates = [
            [{"pid": 1234, "name": "Crypto-Miner.exe", "create_time_us": 123456}],
            [{"pid": 4, "name": "malware-kernel.exe", "create_time_us": 1}],
            [{"pid": True, "name": "malware-bogus.exe", "create_time_us": 1}],
            [
                {"pid": 1234, "name": "miner.exe", "create_time_us": 123456},
                {"pid": 1234, "name": "virus.exe", "create_time_us": 123456},
            ],
            [
                {"pid": pid, "name": f"miner-{pid}.exe", "create_time_us": pid}
                for pid in range(1, SERVER_MAX_PROCESSES_PER_RESPONSE + 2)
            ],
        ]
        for targets in candidates:
            with self.subTest(targets=targets):
                self.assertEqual(
                    AutonomousResponseEngine._valid_process_targets(targets),
                    AutonomousDefense._valid_process_targets(targets),
                )

    def test_llm_recommendation_cannot_authorize_isolation_or_process_kill(self):
        decision = self.engine.decide_response(
            self.analysis,
            "test-host",
            {"processes": [{"pid": 4321, "name": "normal.exe"}]},
        )

        self.assertFalse(decision["execute"])
        self.assertEqual("alert_only", decision["action"])
        self.assertEqual([], decision["targets"])

    def test_exact_observed_suspicious_process_remains_automatically_actionable(self):
        telemetry = {"processes": [{
            "pid": 4321,
            "name": "crypto-miner.exe",
            "create_time_us": 123456000,
        }]}
        decision = self.engine.decide_response(
            self.analysis,
            "test-host",
            telemetry,
        )
        authorization = self.engine.execute_response(decision, "test-host", telemetry)

        self.assertTrue(decision["execute"])
        self.assertEqual("kill_process", decision["action"])
        self.assertEqual([{
            "pid": 4321,
            "name": "crypto-miner.exe",
            "create_time_us": 123456000,
        }], decision["targets"])
        self.assertTrue(authorization["authorized"])
        self.assertFalse(authorization["executed"])

    def test_safe_mode_and_disabled_defense_reject_server_authorization(self):
        telemetry = {"processes": [{
            "pid": 4321,
            "name": "crypto-miner.exe",
            "create_time_us": 123456000,
        }]}
        for settings in (
            {"DEFENSE_ENABLED": "false", "DEFENSE_SAFE_MODE": "false"},
            {"DEFENSE_ENABLED": "true", "DEFENSE_SAFE_MODE": "true"},
            {"DEFENSE_ENABLED": "invalid", "DEFENSE_SAFE_MODE": "false"},
        ):
            with self.subTest(settings=settings), patch.dict(os.environ, settings):
                decision = self.engine.decide_response(self.analysis, "test-host", telemetry)
                self.assertFalse(decision["execute"])

    def test_agent_safe_mode_blocks_commands(self):
        defense = AutonomousDefense()
        command = {
            "action": "kill_process",
            "host_id": defense.host_id,
            "targets": [{
                "pid": 4321,
                "name": "crypto-miner.exe",
                "create_time_us": 123456000,
            }],
        }
        with patch.dict(os.environ, {
            "DEFENSE_ENABLED": "true",
            "DEFENSE_SAFE_MODE": "true",
        }):
            result = defense.execute_command(command)

        self.assertEqual("disabled", result["status"])

    def test_agent_preflight_checks_database_and_authenticated_server(self):
        defense = AutonomousDefense()
        with patch("agent.autonomous_defense.requests.get", return_value=Mock(
            status_code=200,
            json=lambda: {"ok": True, "defense_enabled": True},
        )) as get:
            result = defense.preflight()

        self.assertTrue(result["ready"])
        self.assertEqual("ok", result["local_state"])
        self.assertEqual("ok", result["server"])
        get.assert_called_once()
        self.assertTrue(get.call_args.args[0].endswith("/health"))

    def test_agent_preflight_reports_auth_failure(self):
        defense = AutonomousDefense()
        with patch("agent.autonomous_defense.requests.get", return_value=Mock(
            status_code=401,
        )):
            result = defense.preflight()

        self.assertFalse(result["ready"])
        self.assertEqual("unauthorized (check API_KEY)", result["server"])

    def test_agent_normalizes_legacy_ingest_server_url(self):
        for value in (
            "http://127.0.0.1:5000",
            "http://127.0.0.1:5000/",
            "http://127.0.0.1:5000/ingest",
            "http://127.0.0.1:5000/ingest/",
        ):
            with self.subTest(value=value):
                self.assertEqual(
                    "http://127.0.0.1:5000",
                    normalize_server_url(value),
                )
        self.assertEqual(
            "https://shield.example/api",
            normalize_server_url("https://shield.example/api/ingest"),
        )

    def test_agent_rejects_commands_for_another_host_before_execution(self):
        defense = AutonomousDefense()
        command = {
            "action": "kill_process",
            "host_id": "different-host",
            "targets": [{
                "pid": 4321,
                "name": "crypto-miner.exe",
                "create_time_us": 123456000,
            }],
        }
        with patch.dict(os.environ, {
            "DEFENSE_ENABLED": "true",
            "DEFENSE_SAFE_MODE": "false",
        }), patch("agent.autonomous_defense.psutil.Process") as process_factory:
            result = defense.execute_command(command)

        self.assertEqual("rejected", result["status"])
        self.assertIn("host does not match", result["details"])
        process_factory.assert_not_called()

    def test_agent_safe_mode_guards_the_termination_primitive(self):
        defense = AutonomousDefense()
        with patch("agent.autonomous_defense.psutil.Process") as process_factory:
            with patch.dict(os.environ, {
                "DEFENSE_ENABLED": "true",
                "DEFENSE_SAFE_MODE": "true",
            }):
                result = defense.kill_process([{
                    "pid": 4321,
                    "name": "crypto-miner.exe",
                    "create_time_us": 123456000,
                }])

        self.assertIn("defense is disabled", result["4321"])
        process_factory.assert_not_called()

    def test_agent_rejects_isolation_and_malformed_targets(self):
        defense = AutonomousDefense()
        with patch.dict(os.environ, {
            "DEFENSE_ENABLED": "true",
            "DEFENSE_SAFE_MODE": "false",
        }):
            isolation = defense.execute_command({
                "action": "isolate_machine",
                "targets": ["test-host"],
            })
            malformed = defense.execute_command({
                "action": "kill_process",
                "targets": ["crypto-miner.exe"],
            })

        self.assertEqual("rejected", isolation["status"])
        self.assertEqual("rejected", malformed["status"])

    def test_server_revalidates_action_before_authorizing_delivery(self):
        result = self.engine.execute_response({
            "action": "isolate_machine",
            "targets": ["test-host"],
            "execute": True,
            "reason": "LLM recommendation",
        }, "test-host")

        self.assertFalse(result["executed"])
        self.assertIn("Rejected", result["result"])

    @staticmethod
    def isolation_telemetry(process_name=None, public_ips=None, cpu=10, process_count=1):
        processes = [
            {"pid": pid + 100, "name": "worker.exe"}
            for pid in range(process_count)
        ]
        if process_name:
            processes.append({"pid": 4321, "name": process_name})
        return {
            "cpu": cpu,
            "processes": processes,
            "strange_ips": public_ips or [],
        }

    def test_isolation_requires_two_independent_deterministic_signals(self):
        process_signal = self.isolation_telemetry(process_name="malware.exe")
        network_signal = self.isolation_telemetry(public_ips=[
            f"8.8.8.{address}" for address in range(1, 7)
        ])
        both = self.isolation_telemetry(
            process_name="malware.exe",
            public_ips=[f"8.8.8.{address}" for address in range(1, 7)],
        )
        with patch.dict(os.environ, {"DEFENSE_ISOLATION_ENABLED": "true"}):
            self.assertEqual(1, len(assess_isolation_evidence(process_signal)))
            self.assertEqual(1, len(assess_isolation_evidence(network_signal)))
            self.assertEqual(
                assess_isolation_evidence(both),
                assess_agent_isolation_evidence(both),
            )
            decision = self.engine.decide_response(self.analysis, "test-host", both)

        self.assertEqual("isolate_machine", decision["action"])
        self.assertTrue(decision["execute"])
        self.assertEqual(
            {"suspicious_process", "external_connection_burst"},
            {item["signal"] for item in decision["evidence"]},
        )
        self.assertIn("independent telemetry signals", decision["reason"])

    def test_llm_isolation_recommendation_alone_never_authorizes_isolation(self):
        telemetry = self.isolation_telemetry(process_name="malware.exe")
        with patch.dict(os.environ, {"DEFENSE_ISOLATION_ENABLED": "true"}):
            decision = self.engine.decide_response(self.analysis, "test-host", telemetry)

        self.assertNotEqual("isolate_machine", decision["action"])

    def test_extreme_load_is_one_signal_and_needs_an_independent_signal(self):
        load_only = self.isolation_telemetry(cpu=96, process_count=200)
        process_and_load = self.isolation_telemetry(
            process_name="malware.exe",
            cpu=96,
            process_count=200,
        )
        combined = self.isolation_telemetry(
            cpu=96,
            process_count=200,
            public_ips=[f"8.8.8.{address}" for address in range(1, 7)],
        )
        with patch.dict(os.environ, {"DEFENSE_ISOLATION_ENABLED": "true"}):
            self.assertEqual(
                ["extreme_resource_load"],
                [item["signal"] for item in assess_isolation_evidence(load_only)],
            )
            self.assertNotEqual(
                "isolate_machine",
                self.engine.decide_response(self.analysis, "test-host", process_and_load)["action"],
            )
            decision = self.engine.decide_response(self.analysis, "test-host", combined)

        self.assertEqual("isolate_machine", decision["action"])
        self.assertEqual(
            {"external_connection_burst", "extreme_resource_load"},
            {item["signal"] for item in decision["evidence"]},
        )

    def test_isolation_signals_ignore_duplicate_process_ids_and_non_public_ips(self):
        telemetry = {
            "cpu": 100,
            "processes": [{"pid": 1234, "name": "worker.exe"}] * 200,
            "strange_ips": [
                "10.0.0.1", "192.168.1.2", "172.16.0.1",
                "127.0.0.1", "::1", "fe80::1",
            ],
        }
        self.assertEqual([], assess_isolation_evidence(telemetry))

    def test_isolation_requires_explicit_opt_in_and_global_enable(self):
        telemetry = self.isolation_telemetry(
            process_name="malware.exe",
            public_ips=[f"8.8.8.{address}" for address in range(1, 7)],
        )
        for settings in (
            {"DEFENSE_ISOLATION_ENABLED": "false"},
            {"DEFENSE_ISOLATION_ENABLED": "true", "DEFENSE_SAFE_MODE": "true"},
            {"DEFENSE_ISOLATION_ENABLED": "true", "DEFENSE_ENABLED": "false"},
        ):
            with self.subTest(settings=settings), patch.dict(os.environ, settings):
                decision = self.engine.decide_response(self.analysis, "test-host", telemetry)
                self.assertNotEqual("isolate_machine", decision["action"])
        with patch.dict(os.environ, {}, clear=True):
            decision = self.engine.decide_response(self.analysis, "test-host", telemetry)
        self.assertNotEqual("isolate_machine", decision["action"])

    def test_server_revalidates_isolation_evidence_before_delivery(self):
        telemetry = self.isolation_telemetry(
            process_name="malware.exe",
            public_ips=[f"8.8.8.{address}" for address in range(1, 7)],
        )
        with patch.dict(os.environ, {"DEFENSE_ISOLATION_ENABLED": "true"}):
            decision = self.engine.decide_response(self.analysis, "test-host", telemetry)
            authorized = self.engine.execute_response(decision, "test-host", telemetry)
            tampered = self.engine.execute_response(
                {**decision, "evidence": []}, "test-host", telemetry
            )
            without_network = self.isolation_telemetry(
                process_name="malware.exe",
                cpu=96,
                process_count=200,
            )
            unsupported_pair = self.engine.execute_response({
                "action": "isolate_machine",
                "targets": ["test-host"],
                "execute": True,
                "reason": "not enough independent evidence",
                "evidence": assess_isolation_evidence(without_network),
            }, "test-host", without_network)

        self.assertTrue(authorized["authorized"])
        self.assertFalse(authorized["executed"])
        self.assertFalse(tampered["authorized"])
        self.assertIn("validation failed", tampered["result"])
        self.assertFalse(unsupported_pair["authorized"])

    def test_isolation_reason_and_evidence_are_written_to_server_audit_log(self):
        telemetry = self.isolation_telemetry(
            process_name="malware.exe",
            public_ips=[f"8.8.8.{address}" for address in range(1, 7)],
        )
        with patch.dict(os.environ, {"DEFENSE_ISOLATION_ENABLED": "true"}):
            decision = self.engine.decide_response(self.analysis, "test-host", telemetry)
            result = self.engine.execute_response(decision, "test-host", telemetry)
        with tempfile.TemporaryDirectory() as directory:
            database = os.path.join(directory, "audit.db")
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("""CREATE TABLE response_log (
                    id INTEGER PRIMARY KEY,
                    host_id TEXT,
                    ts REAL,
                    threat_type TEXT,
                    confidence REAL,
                    root_cause TEXT,
                    decision_reason TEXT,
                    action_taken TEXT,
                    execution_result TEXT
                )""")
                connection.commit()
            log_response_action(database, "test-host", self.analysis, decision, result)
            with closing(sqlite3.connect(database)) as connection:
                row = connection.execute(
                    "SELECT decision_reason, action_taken, execution_result FROM response_log"
                ).fetchone()

        self.assertEqual("isolate_machine", row[1])
        self.assertIn("suspicious_process", row[0])
        self.assertIn("external_connection_burst", row[0])
        self.assertIn("awaiting agent execution", row[2])

    def test_agent_action_report_is_persisted_and_rejects_invalid_data(self):
        with tempfile.TemporaryDirectory() as directory:
            database = os.path.join(directory, "audit.db")
            report_id = persist_agent_action_report(database, {
                "host_id": "test-host",
                "command": "isolate_machine",
                "status": "partial",
                "details": {
                    "isolated": False,
                    "interfaces": {"Ethernet": "disabled", "Wi-Fi": "failed"},
                },
            })
            with closing(sqlite3.connect(database)) as connection:
                row = connection.execute(
                    """SELECT host_id, command, status, details
                       FROM agent_action_log WHERE id = ?""",
                    (report_id,),
                ).fetchone()

        self.assertEqual("test-host", row[0])
        self.assertEqual("isolate_machine", row[1])
        self.assertEqual("partial", row[2])
        self.assertIn("Wi-Fi", row[3])
        for invalid in (
            None,
            {"host_id": "", "command": "kill_process", "status": "executed"},
            {"host_id": "test-host", "command": "isolate_machine", "status": "executing"},
            {"host_id": "test-host", "command": ["isolate_machine"], "status": "executed"},
            {
                "host_id": "test-host",
                "command": "kill_process",
                "status": "executed",
                "details": {"payload": "x" * 65537},
            },
        ):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    persist_agent_action_report(os.path.join(directory, "audit.db"), invalid)

    def test_agent_requires_opt_in_and_fresh_local_corroboration(self):
        defense = AutonomousDefense()
        server_evidence = [
            {"signal": "suspicious_process"},
            {"signal": "external_connection_burst"},
        ]
        command = {
            "action": "isolate_machine",
            "host_id": defense.host_id,
            "evidence": server_evidence,
        }
        with patch.dict(os.environ, {
            "DEFENSE_ENABLED": "true",
            "DEFENSE_SAFE_MODE": "false",
            "DEFENSE_ISOLATION_ENABLED": "true",
        }), patch.object(defense, "_collect_isolation_telemetry", return_value={
            "cpu": 10,
            "processes": [{"pid": 1234, "name": "malware.exe"}],
            "strange_ips": [],
        }), patch.object(defense, "isolate_machine") as isolate:
            result = defense.execute_command(command)
        self.assertEqual("rejected", result["status"])
        isolate.assert_not_called()

        with patch.dict(os.environ, {
            "DEFENSE_ENABLED": "true",
            "DEFENSE_SAFE_MODE": "false",
            "DEFENSE_ISOLATION_ENABLED": "true",
        }), patch.object(defense, "_collect_isolation_telemetry", return_value={
            "cpu": 10,
            "processes": [{"pid": 1234, "name": "malware.exe"}],
            "strange_ips": [f"8.8.8.{address}" for address in range(1, 7)],
        }), patch.object(defense, "isolate_machine", return_value={
            "isolated": True,
            "interfaces": {"Ethernet": "disabled"},
        }) as isolate:
            result = defense.execute_command(command)
        self.assertEqual("executed", result["status"])
        isolate.assert_called_once_with()

    def test_agent_rejects_invalid_isolation_evidence_and_safe_mode(self):
        defense = AutonomousDefense()
        command = {
            "action": "isolate_machine",
            "host_id": defense.host_id,
            "evidence": [{"signal": "suspicious_process"}],
        }
        with patch.dict(os.environ, {
            "DEFENSE_ENABLED": "true",
            "DEFENSE_SAFE_MODE": "false",
            "DEFENSE_ISOLATION_ENABLED": "true",
        }), patch.object(defense, "_collect_isolation_telemetry") as collect:
            rejected = defense.execute_command(command)
        self.assertEqual("rejected", rejected["status"])
        collect.assert_not_called()

        command["evidence"].append({"signal": "external_connection_burst"})
        with patch.dict(os.environ, {
            "DEFENSE_ENABLED": "true",
            "DEFENSE_SAFE_MODE": "true",
            "DEFENSE_ISOLATION_ENABLED": "true",
        }), patch.object(defense, "_collect_isolation_telemetry") as collect:
            disabled = defense.execute_command(command)
        self.assertEqual("disabled", disabled["status"])
        collect.assert_not_called()

    def test_agent_isolation_primitive_requires_explicit_opt_in(self):
        defense = AutonomousDefense()
        with patch.dict(os.environ, {
            "DEFENSE_ENABLED": "true",
            "DEFENSE_SAFE_MODE": "false",
            "DEFENSE_ISOLATION_ENABLED": "false",
        }), patch("agent.autonomous_defense.subprocess.run") as run:
            result = defense.isolate_machine()

        self.assertFalse(result["isolated"])
        run.assert_not_called()

    def test_agent_isolation_runs_os_commands_without_shell(self):
        defense = AutonomousDefense()
        stats = {
            "Ethernet 2": Mock(isup=True),
            "Loopback Pseudo-Interface 1": Mock(isup=True),
        }
        with patch.dict(os.environ, {
            "DEFENSE_ENABLED": "true",
            "DEFENSE_SAFE_MODE": "false",
            "DEFENSE_ISOLATION_ENABLED": "true",
        }), patch("agent.autonomous_defense.platform.system", return_value="Windows"), \
             patch("agent.autonomous_defense.psutil.net_if_stats", return_value=stats), \
             patch("agent.autonomous_defense.subprocess.run") as run:
            result = defense.isolate_machine()

        self.assertTrue(result["isolated"])
        run.assert_called_once_with(
            ["netsh", "interface", "set", "interface", "name=Ethernet 2", "admin=disabled"],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )

    def test_agent_rechecks_exact_process_identity_before_termination(self):
        defense = AutonomousDefense()
        process = Mock()
        process.name.return_value = "crypto-miner.exe"
        process.create_time.return_value = 123.456
        with patch("agent.autonomous_defense.psutil.Process", return_value=process):
            result = defense.kill_process([{
                "pid": 4321,
                "name": "crypto-miner.exe",
                "create_time_us": 123456000,
            }])

        self.assertIn("Terminated", result["4321"])
        process.terminate.assert_called_once_with()

    def test_agent_dry_run_revalidates_exact_target_without_termination(self):
        defense = AutonomousDefense()
        process = Mock()
        process.name.return_value = "crypto-miner.exe"
        process.create_time.return_value = 123.456
        command = {
            "action": "kill_process",
            "host_id": defense.host_id,
            "targets": [{
                "pid": 4321,
                "name": "crypto-miner.exe",
                "create_time_us": 123456000,
            }],
        }
        with patch.dict(os.environ, {
            "DEFENSE_ENABLED": "true",
            "DEFENSE_SAFE_MODE": "false",
            "DEFENSE_DRY_RUN": "true",
        }), patch("agent.autonomous_defense.psutil.Process", return_value=process):
            result = defense.execute_command(command)

        self.assertEqual("dry_run", result["status"])
        self.assertEqual("dry_run", result["details"]["mode"])
        self.assertIn("Would terminate exact process", result["details"]["targets"]["4321"])
        process.terminate.assert_not_called()
        process.kill.assert_not_called()

    def test_agent_dry_run_plans_isolation_without_disabling_interfaces(self):
        defense = AutonomousDefense()
        command = {
            "action": "isolate_machine",
            "host_id": defense.host_id,
            "evidence": [
                {"signal": "suspicious_process"},
                {"signal": "external_connection_burst"},
            ],
        }
        telemetry = {
            "cpu": 10,
            "processes": [{"pid": 1234, "name": "malware.exe"}],
            "strange_ips": [f"8.8.8.{address}" for address in range(1, 7)],
        }
        with patch.dict(os.environ, {
            "DEFENSE_ENABLED": "true",
            "DEFENSE_SAFE_MODE": "false",
            "DEFENSE_ISOLATION_ENABLED": "true",
            "DEFENSE_DRY_RUN": "true",
        }), patch.object(
            defense, "_collect_isolation_telemetry", return_value=telemetry
        ), patch.object(
            defense, "isolate_machine",
            return_value={
                "isolated": False,
                "dry_run": True,
                "interfaces": {"Ethernet": "would disable"},
            },
        ) as isolate:
            result = defense.execute_command(command)

        self.assertEqual("dry_run", result["status"])
        isolate.assert_called_once_with(dry_run=True)

    def test_isolation_dry_run_lists_interfaces_without_disabling_them(self):
        defense = AutonomousDefense()
        stats = {
            "Ethernet 2": Mock(isup=True),
            "Loopback Pseudo-Interface 1": Mock(isup=True),
        }
        with patch.dict(os.environ, {
            "DEFENSE_ENABLED": "true",
            "DEFENSE_SAFE_MODE": "false",
            "DEFENSE_ISOLATION_ENABLED": "true",
        }), patch("agent.autonomous_defense.platform.system", return_value="Windows"), \
             patch("agent.autonomous_defense.psutil.net_if_stats", return_value=stats), \
             patch("agent.autonomous_defense.subprocess.run") as run:
            result = defense.isolate_machine(dry_run=True)

        self.assertFalse(result["isolated"])
        self.assertTrue(result["dry_run"])
        self.assertEqual({"Ethernet 2": "would disable"}, result["interfaces"])
        run.assert_not_called()

    def test_agent_does_not_terminate_reused_pid_or_protected_process(self):
        defense = AutonomousDefense()
        process = Mock()
        process.name.return_value = "crypto-miner.exe"
        process.create_time.return_value = 999.0
        with patch("agent.autonomous_defense.psutil.Process", return_value=process):
            result = defense.kill_process([{
                "pid": 4321,
                "name": "crypto-miner.exe",
                "create_time_us": 123456000,
            }])

        self.assertIn("identity no longer matches", result["4321"])
        process.terminate.assert_not_called()

        process.name.return_value = "svchost.exe"
        result = defense.kill_process([{
            "pid": 4321,
            "name": "svchost.exe",
            "create_time_us": 999000000,
        }])
        self.assertIn("validation", result["error"])
        process.terminate.assert_not_called()


if __name__ == "__main__":
    unittest.main()

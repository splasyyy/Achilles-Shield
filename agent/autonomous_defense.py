# agent/autonomous_defense.py
"""
Agent-side autonomous defense executor
Receives commands from server and executes threat responses
"""

import os
import json
import ipaddress
import platform
import sqlite3
import requests
import psutil
import subprocess
import socket
import threading
import time
from contextlib import closing
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('agent_defense.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def normalize_server_url(server_url: str) -> str:
    """Accept either the server base URL or the legacy URL ending in /ingest."""
    parsed = urlsplit(server_url.strip())
    path = parsed.path.rstrip("/")
    if path == "/ingest" or path.endswith("/ingest"):
        path = path[:-len("/ingest")]
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", "")).rstrip("/")


SERVER_URL = normalize_server_url(os.environ.get("SERVER_URL", "http://127.0.0.1:5000"))
API_KEY = os.environ.get("API_KEY", "supersecret")
HOST_ID = os.environ.get("HOST_ID", socket.gethostname())
STATE_DB = os.environ.get(
    "AGENT_STATE_DB",
    os.path.join(
        os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
        "AchillesShield",
        "agent_state.db",
    ),
)
REPORTED_RESULT_RETENTION_SECONDS = 30 * 24 * 60 * 60
SUSPICIOUS_PROCESS_MARKERS = ("hack", "malware", "keylog", "miner", "virus", "trojan")
MAX_PROCESSES_PER_COMMAND = 5
MIN_EXTERNAL_IPS_FOR_ISOLATION = 6
MIN_CPU_FOR_ISOLATION = 95
MIN_PROCESSES_FOR_RESOURCE_SIGNAL = 200
DEFAULT_PROTECTED_PROCESS_NAMES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe",
    "systemd", "init", "kthreadd", "launchd", "kernel_task",
    "securityd", "loginwindow",
}
PROTECTED_PROCESS_NAMES = DEFAULT_PROTECTED_PROCESS_NAMES | {
    name.strip().casefold()
    for name in os.environ.get("PROTECTED_PROCESS_NAMES", "").split(",")
    if name.strip()
}


def defense_actions_enabled() -> bool:
    """Defense defaults on for existing deployments; safe mode always wins."""
    truthy = {"1", "true", "yes", "on"}
    enabled = os.environ.get("DEFENSE_ENABLED", "true").strip().lower()
    safe_mode = os.environ.get("DEFENSE_SAFE_MODE", "false").strip().lower()
    return enabled in truthy and safe_mode in {"0", "false", "no", "off"}


def defense_isolation_enabled() -> bool:
    return defense_actions_enabled() and os.environ.get(
        "DEFENSE_ISOLATION_ENABLED", "false"
    ).strip().lower() in {"1", "true", "yes", "on"}


def defense_dry_run_enabled() -> bool:
    return os.environ.get("DEFENSE_DRY_RUN", "false").strip().lower() in {
        "1", "true", "yes", "on",
    }


def assess_isolation_evidence(telemetry: Dict) -> List[Dict]:
    """Mirror the server policy against a fresh local telemetry snapshot."""
    if not isinstance(telemetry, dict):
        return []

    evidence = []
    processes = telemetry.get("processes")
    observed_pids = set()
    if isinstance(processes, list):
        suspicious = {}
        for process in processes:
            if not isinstance(process, dict):
                continue
            pid = process.get("pid")
            name = process.get("name")
            if (isinstance(pid, int) and not isinstance(pid, bool) and pid > 0
                    and pid not in {1, 4}):
                observed_pids.add(pid)
            if (isinstance(pid, int) and not isinstance(pid, bool) and pid > 0
                    and pid not in {1, 4}
                    and isinstance(name, str) and name.strip()
                    and name.casefold() not in PROTECTED_PROCESS_NAMES
                    and any(marker in name.casefold() for marker in SUSPICIOUS_PROCESS_MARKERS)):
                suspicious[pid] = name
        if suspicious:
            evidence.append({
                "signal": "suspicious_process",
                "count": len(suspicious),
                "names": sorted(set(suspicious.values()), key=str.casefold)[:MAX_PROCESSES_PER_COMMAND],
                "processes": [
                    {"pid": pid, "name": suspicious[pid]}
                    for pid in sorted(suspicious)[:MAX_PROCESSES_PER_COMMAND]
                ],
            })

    strange_ips = telemetry.get("strange_ips")
    external_ips = set()
    if isinstance(strange_ips, list):
        for value in strange_ips:
            if not isinstance(value, str):
                continue
            try:
                address = ipaddress.ip_address(value.strip())
            except ValueError:
                continue
            if address.is_global:
                external_ips.add(address.compressed)
    if len(external_ips) >= MIN_EXTERNAL_IPS_FOR_ISOLATION:
        evidence.append({
            "signal": "external_connection_burst",
            "count": len(external_ips),
            "threshold": MIN_EXTERNAL_IPS_FOR_ISOLATION,
        })

    cpu = telemetry.get("cpu")
    if (isinstance(cpu, (int, float)) and not isinstance(cpu, bool)
            and MIN_CPU_FOR_ISOLATION <= cpu <= 100
            and isinstance(processes, list)
            and len(observed_pids) >= MIN_PROCESSES_FOR_RESOURCE_SIGNAL):
        evidence.append({
            "signal": "extreme_resource_load",
            "cpu_percent": cpu,
            "process_count": len(observed_pids),
            "cpu_threshold": MIN_CPU_FOR_ISOLATION,
            "process_threshold": MIN_PROCESSES_FOR_RESOURCE_SIGNAL,
        })
    return evidence


class AutonomousDefense:
    """
    Autonomous defense executor on agent side.
    Receives threat response commands and executes them.
    """
    
    def __init__(self, state_db: Optional[str] = None):
        self.host_id = HOST_ID
        self.state_db = state_db or STATE_DB
        self._outbox_lock = threading.Lock()
        self._init_report_outbox()

    def _init_report_outbox(self) -> None:
        """Create the local durable store used to retry command reports."""
        state_directory = os.path.dirname(os.path.abspath(self.state_db))
        os.makedirs(state_directory, exist_ok=True)
        with closing(sqlite3.connect(self.state_db, timeout=5)) as con:
            con.execute("""CREATE TABLE IF NOT EXISTS defense_action_outbox (
                command_id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL,
                command TEXT NOT NULL,
                status TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                reported_at REAL,
                execution_pid INTEGER,
                execution_create_time REAL
            )""")
            columns = {
                row[1] for row in con.execute(
                    "PRAGMA table_info(defense_action_outbox)"
                ).fetchall()
            }
            if "execution_pid" not in columns:
                con.execute(
                    "ALTER TABLE defense_action_outbox ADD COLUMN execution_pid INTEGER"
                )
            if "execution_create_time" not in columns:
                con.execute(
                    "ALTER TABLE defense_action_outbox "
                    "ADD COLUMN execution_create_time REAL"
                )
            con.execute("""CREATE INDEX IF NOT EXISTS idx_defense_action_outbox_pending
                            ON defense_action_outbox(reported_at, created_at)""")
            con.execute(
                """DELETE FROM defense_action_outbox
                   WHERE reported_at IS NOT NULL AND created_at < ?""",
                (time.time() - REPORTED_RESULT_RETENTION_SECONDS,),
            )
            con.commit()

    def preflight(self) -> Dict:
        """Check local state storage and authenticated server readiness without actions."""
        result = {
            "host_id": self.host_id,
            "state_db": self.state_db,
            "local_state": "ok",
            "server": "unavailable",
            "defense_enabled": defense_actions_enabled(),
            "dry_run": defense_dry_run_enabled(),
            "ready": False,
        }
        try:
            with closing(sqlite3.connect(self.state_db, timeout=5)) as con:
                con.execute("SELECT 1").fetchone()
        except sqlite3.Error as error:
            result["local_state"] = f"error: {error}"
            return result

        try:
            response = requests.get(
                f"{SERVER_URL}/health",
                headers={"X-API-KEY": API_KEY},
                timeout=5,
            )
            if response.status_code == 200:
                payload = response.json()
                if not isinstance(payload, dict) or payload.get("ok") is not True:
                    result["server"] = "invalid health response"
                    return result
                result["server"] = "ok"
                result["server_defense_enabled"] = payload.get("defense_enabled")
                result["ready"] = True
            elif response.status_code == 401:
                result["server"] = "unauthorized (check API_KEY)"
            else:
                result["server"] = f"HTTP {response.status_code}"
        except (requests.RequestException, ValueError) as error:
            result["server"] = f"error: {error}"
        return result

    @staticmethod
    def _valid_command_id(command_id: object) -> bool:
        return (
            isinstance(command_id, str)
            and bool(command_id.strip())
            and len(command_id) <= 64
        )

    @staticmethod
    def _execution_owner_is_alive(pid: Optional[int], create_time: Optional[float]) -> bool:
        if not isinstance(pid, int) or pid <= 0 or create_time is None:
            return False
        try:
            return abs(psutil.Process(pid).create_time() - create_time) < 0.01
        except psutil.NoSuchProcess:
            return False
        except psutil.Error:
            return True

    def _prepare_command_execution(
        self, command: Dict
    ) -> Tuple[bool, Optional[Dict]]:
        """Persist execution intent, or return a prior result without re-execution."""
        command_id = command["command_id"]
        action = command.get("action", "unknown")
        owner_pid = os.getpid()
        owner_create_time = psutil.Process(owner_pid).create_time()
        intent = {
            "host_id": self.host_id,
            "command": action,
            "status": "unknown",
            "details": "Execution intent recorded; outcome has not been persisted.",
            "command_id": command_id,
        }
        intent_json = json.dumps(intent, allow_nan=False)
        with self._outbox_lock, closing(sqlite3.connect(self.state_db, timeout=5)) as con:
            cursor = con.execute(
                """INSERT OR IGNORE INTO defense_action_outbox
                   (command_id, host_id, command, status, result_json, created_at,
                    execution_pid, execution_create_time)
                   VALUES (?, ?, ?, 'executing', ?, ?, ?, ?)""",
                (
                    command_id, self.host_id, action, intent_json, time.time(),
                    owner_pid, owner_create_time,
                ),
            )
            if cursor.rowcount == 1:
                con.commit()
                return True, None

            row = con.execute(
                """SELECT host_id, status, result_json, execution_pid,
                          execution_create_time
                   FROM defense_action_outbox
                   WHERE command_id = ?""",
                (command_id,),
            ).fetchone()
            if row is None or row[0] != self.host_id:
                raise RuntimeError("Command ID is already bound to another host")
            if row[1] == "executing":
                if self._execution_owner_is_alive(row[3], row[4]):
                    con.commit()
                    return False, None
                result = json.loads(row[2])
                result["details"] = (
                    "Execution may have been interrupted after it started. "
                    "The action was not retried because it may already have occurred."
                )
                result_json = json.dumps(result, allow_nan=False)
                con.execute(
                    """UPDATE defense_action_outbox
                       SET status = 'unknown', result_json = ?,
                           execution_pid = NULL, execution_create_time = NULL
                       WHERE command_id = ? AND host_id = ? AND status = 'executing'""",
                    (result_json, command_id, self.host_id),
                )
                con.commit()
                return False, result

            con.commit()
            return False, json.loads(row[2])

    def _save_command_result(self, result: Dict) -> None:
        command_id = result.get("command_id")
        if not self._valid_command_id(command_id):
            return
        result_json = json.dumps(result, allow_nan=False)
        with self._outbox_lock, closing(sqlite3.connect(self.state_db, timeout=5)) as con:
            cursor = con.execute(
                """UPDATE defense_action_outbox
                   SET status = ?, result_json = ?,
                       execution_pid = NULL, execution_create_time = NULL
                   WHERE command_id = ? AND host_id = ? AND status = 'executing'""",
                (result["status"], result_json, command_id, self.host_id),
            )
            if cursor.rowcount == 0:
                con.execute(
                    """INSERT OR IGNORE INTO defense_action_outbox
                       (command_id, host_id, command, status, result_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        command_id, self.host_id, result["command"],
                        result["status"], result_json, time.time(),
                    ),
                )
            con.commit()

    def _pending_command_results(self) -> List[Dict]:
        with self._outbox_lock, closing(sqlite3.connect(self.state_db, timeout=5)) as con:
            rows = con.execute(
                """SELECT result_json FROM defense_action_outbox
                   WHERE host_id = ? AND reported_at IS NULL AND status != 'executing'
                   ORDER BY created_at, command_id""",
                (self.host_id,),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def _mark_command_reported(self, command_id: str) -> None:
        with self._outbox_lock, closing(sqlite3.connect(self.state_db, timeout=5)) as con:
            con.execute(
                """UPDATE defense_action_outbox SET reported_at = ?
                   WHERE command_id = ? AND host_id = ? AND reported_at IS NULL""",
                (time.time(), command_id, self.host_id),
            )
            con.commit()

    @staticmethod
    def _valid_isolation_evidence(evidence: List[Dict]) -> bool:
        allowed_signals = {
            'suspicious_process',
            'external_connection_burst',
            'extreme_resource_load',
        }
        return (
            isinstance(evidence, list)
            and len(evidence) >= 2
            and all(
                isinstance(item, dict)
                and item.get('signal') in allowed_signals
                for item in evidence
            )
            and len({item['signal'] for item in evidence}) == len(evidence)
            and any(item['signal'] == 'external_connection_burst' for item in evidence)
        )

    @staticmethod
    def _collect_isolation_telemetry() -> Dict:
        cpu = psutil.cpu_percent(interval=0.5)
        processes = []
        for process in psutil.process_iter(['pid', 'name']):
            try:
                processes.append({
                    'pid': process.info['pid'],
                    'name': process.info.get('name'),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        strange_ips = set()
        try:
            for connection in psutil.net_connections(kind='inet'):
                if not connection.raddr:
                    continue
                try:
                    address = ipaddress.ip_address(connection.raddr.ip)
                except ValueError:
                    continue
                if address.is_global:
                    strange_ips.add(address.compressed)
        except psutil.AccessDenied:
            logger.warning("Cannot read network connections; isolation evidence will be incomplete")

        return {
            'cpu': cpu,
            'processes': processes,
            'strange_ips': sorted(strange_ips),
        }

    def isolate_machine(self, dry_run: bool = False) -> Dict:
        """Disable active network services/interfaces using argument-safe OS commands."""
        if not defense_isolation_enabled():
            logger.warning("Rejected network isolation: isolation is disabled or safe mode is active")
            return {'isolated': False, 'error': 'Isolation is disabled or safe mode is active'}

        system = platform.system()
        commands = []
        if system == 'Windows':
            commands = [
                (name, ['netsh', 'interface', 'set', 'interface',
                               f'name={name}', 'admin=disabled'])
                for name, stats in psutil.net_if_stats().items()
                if stats.isup and 'loopback' not in name.casefold()
            ]
        elif system == 'Linux':
            ignored_prefixes = ('lo', 'docker', 'veth', 'br-', 'virbr', 'podman', 'cni')
            commands = [
                (interface, ['ip', 'link', 'set', 'dev', interface, 'down'])
                for interface, stats in psutil.net_if_stats().items()
                if stats.isup and not interface.casefold().startswith(ignored_prefixes)
            ]
        elif system == 'Darwin':
            listing = subprocess.run(
                ['networksetup', '-listallnetworkservices'],
                check=True, capture_output=True, text=True, timeout=10
            )
            services = [
                line for line in listing.stdout.splitlines()[1:]
                if line and not line.startswith('*')
            ]
            commands = [
                (service, ['networksetup', '-setnetworkserviceenabled', service, 'off'])
                for service in services
            ]
        else:
            return {'isolated': False, 'error': f'Unsupported operating system: {system}'}

        if not commands:
            return {'isolated': False, 'error': 'No active network interfaces/services found'}

        if dry_run:
            return {
                'isolated': False,
                'dry_run': True,
                'interfaces': {name: 'would disable' for name, _ in commands},
            }

        results = {}
        for name, command in commands:
            try:
                subprocess.run(command, check=True, capture_output=True, text=True, timeout=15)
                results[name] = 'disabled'
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                logger.error(f"Failed to disable network interface/service {name}: {error}")
                results[name] = f'failed: {error}'

        succeeded = sum(value == 'disabled' for value in results.values())
        return {
            'isolated': succeeded == len(commands),
            'interfaces': results,
            'error': None if succeeded == len(commands) else 'One or more interfaces/services could not be disabled',
        }

    @staticmethod
    def _valid_process_targets(targets: List[Dict]) -> bool:
        return (
            isinstance(targets, list)
            and 0 < len(targets) <= MAX_PROCESSES_PER_COMMAND
            and all(
                isinstance(target, dict)
                and set(target) == {'pid', 'name', 'create_time_us'}
                and isinstance(target.get('pid'), int)
                and not isinstance(target.get('pid'), bool)
                and target['pid'] > 0
                and target['pid'] not in {1, 4}
                and isinstance(target.get('name'), str)
                and target['name'].strip()
                and target['name'].casefold() not in PROTECTED_PROCESS_NAMES
                and isinstance(target.get('create_time_us'), int)
                and not isinstance(target.get('create_time_us'), bool)
                and target['create_time_us'] > 0
                and any(marker in target['name'].casefold()
                        for marker in SUSPICIOUS_PROCESS_MARKERS)
                for target in targets
            )
            and len({target['pid'] for target in targets}) == len(targets)
        )

    def kill_process(self, targets: List[Dict], dry_run: bool = False) -> Dict:
        """
        Terminate only exact, observed process identities after local revalidation.
        """
        if not defense_actions_enabled():
            logger.warning("Rejected process termination: defense is disabled or in safe mode")
            if not isinstance(targets, list):
                return {'error': 'Process targets must be a list'}
            return {
                str(target.get('pid', 'unknown')): 'Rejected: defense is disabled or in safe mode'
                for target in targets
                if isinstance(target, dict)
            }

        if not self._valid_process_targets(targets):
            return {'error': 'Process targets failed validation'}

        logger.warning(f"🔴 DEFENSE ACTION: Killing validated process targets: {targets}")
        results = {}
        for target in targets:
            pid = target['pid']
            expected_name = target['name']
            expected_created_at = target['create_time_us']
            try:
                process = psutil.Process(pid)
                actual_name = process.name()
                actual_normalized = actual_name.casefold()
                if actual_name.casefold() != expected_name.casefold():
                    results[str(pid)] = "Rejected: process name no longer matches telemetry"
                    continue
                if int(process.create_time() * 1_000_000) != expected_created_at:
                    results[str(pid)] = "Rejected: process identity no longer matches telemetry"
                    continue
                if (pid in {0, 1, 4, os.getpid(), os.getppid()}
                        or actual_normalized in PROTECTED_PROCESS_NAMES):
                    results[str(pid)] = "Rejected: protected process"
                    continue
                if not any(marker in actual_normalized for marker in SUSPICIOUS_PROCESS_MARKERS):
                    results[str(pid)] = "Rejected: process no longer matches mitigation policy"
                    continue

                if dry_run:
                    results[str(pid)] = f"Would terminate exact process {actual_name}"
                    continue

                logger.warning(f"   Terminating: {actual_name} (PID: {pid})")
                process.terminate()
                try:
                    process.wait(timeout=3)
                except psutil.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                results[str(pid)] = f"Terminated exact process {actual_name}"
            except psutil.NoSuchProcess:
                results[str(pid)] = "Process no longer exists"
            except psutil.AccessDenied:
                results[str(pid)] = "Rejected: insufficient permission"
            except (OSError, psutil.Error) as e:
                logger.error(f"Error terminating PID {pid}: {e}")
                results[str(pid)] = f"Failed: {e}"
        return results
    
    def execute_command(self, command: Dict) -> Dict:
        """
        Execute autonomous defense command from server.
        Command format: {
            'action': 'kill_process' | 'isolate_machine',
            'targets': [{'pid': 123, 'name': 'name.exe', 'create_time_us': 123456000}]
                       or [host_id],
            'host_id': 'this agent host',
            'evidence': [independent server telemetry signal summaries],
            'reason': 'Why this action'
        }
        """
        if not isinstance(command, dict):
            return {
                'host_id': self.host_id,
                'command': 'unknown',
                'status': 'rejected',
                'details': 'Command must be an object'
            }

        action = command.get('action', 'unknown')
        targets = command.get('targets', [])
        reason = command.get('reason', 'No reason provided')
        
        logger.info(f"📥 Received defense command: {action}")
        logger.info(f"   Reason: {reason}")
        
        result = {
            'host_id': self.host_id,
            'command': action,
            'status': 'unknown',
            'details': {}
        }
        command_id = command.get('command_id')
        if command_id is not None:
            if not self._valid_command_id(command_id):
                result['status'] = 'rejected'
                result['details'] = 'Command ID is invalid'
                return result
            result['command_id'] = command_id
        
        try:
            if not defense_actions_enabled():
                result['status'] = 'disabled'
                result['details'] = 'Defense actions are disabled or safe mode is active'
                return result
            dry_run = defense_dry_run_enabled()

            if command.get('host_id') != self.host_id:
                result['status'] = 'rejected'
                result['details'] = 'Command host does not match this agent'
                return result

            if action == 'kill_process':
                if not self._valid_process_targets(targets):
                    result['status'] = 'rejected'
                    result['details'] = 'Process targets failed validation'
                    return result
                result['details'] = self.kill_process(targets, dry_run=dry_run)
                if dry_run:
                    result['status'] = 'dry_run'
                    result['details'] = {
                        'mode': 'dry_run',
                        'targets': result['details'],
                    }
                    return result
                terminated = sum(
                    detail.startswith('Terminated exact process')
                    for detail in result['details'].values()
                )
                if terminated == len(targets):
                    result['status'] = 'executed'
                elif terminated:
                    result['status'] = 'partial'
                else:
                    result['status'] = 'rejected'
            elif action == 'isolate_machine':
                evidence = command.get('evidence')
                if (not defense_isolation_enabled()
                        or not self._valid_isolation_evidence(evidence)):
                    result['status'] = 'rejected'
                    result['details'] = 'Isolation opt-in or server evidence validation failed'
                    return result

                local_evidence = assess_isolation_evidence(
                    self._collect_isolation_telemetry()
                )
                local_signals = {item['signal'] for item in local_evidence}
                server_signals = {item['signal'] for item in evidence}
                if len(local_signals & server_signals) < 2:
                    result['status'] = 'rejected'
                    result['details'] = {
                        'reason': 'Fresh local telemetry did not corroborate two server signals',
                        'server_signals': sorted(server_signals),
                        'local_signals': sorted(local_signals),
                    }
                    return result

                if dry_run:
                    result['details'] = self.isolate_machine(dry_run=True)
                else:
                    result['details'] = self.isolate_machine()
                logger.info("Network isolation outcome: %s", result['details'])
                if result['details'].get('dry_run'):
                    result['status'] = 'dry_run'
                elif result['details']['isolated']:
                    result['status'] = 'executed'
                elif any(value == 'disabled' for value in result['details'].get('interfaces', {}).values()):
                    result['status'] = 'partial'
                else:
                    result['status'] = 'failed'
            else:
                result['status'] = 'rejected'
                result['details'] = 'Action is not authorized by local response policy'
                logger.warning(f"Rejected unauthorized defense action: {action}")
        
        except Exception as e:
            result['status'] = 'failed'
            result['error'] = str(e)
            logger.error(f"Error executing command: {e}")
        
        logger.info(f"✅ Command executed: {result['status']}")
        return result
    
    def report_action(self, result: Dict) -> bool:
        """
        Report an action and acknowledge the local outbox after server persistence.
        """
        try:
            headers = {"Content-Type": "application/json", "X-API-KEY": API_KEY}
            response = requests.post(
                f"{SERVER_URL}/report_defense_action",
                json=result,
                headers=headers,
                timeout=5
            )
            if response.status_code != 200:
                return False
            command_id = result.get("command_id")
            if self._valid_command_id(command_id):
                self._mark_command_reported(command_id)
            return True
        except Exception as e:
            logger.error(f"Error reporting action to server: {e}")
            return False
    
    def check_for_commands(self) -> bool:
        """
        Poll server for autonomous defense commands.
        Called periodically to check if server wants to execute actions.
        """
        try:
            for pending_result in self._pending_command_results():
                self.report_action(pending_result)
            if self._pending_command_results():
                return False

            headers = {"X-API-KEY": API_KEY}
            response = requests.get(
                f"{SERVER_URL}/get_defense_commands?host_id={self.host_id}",
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                commands = response.json().get('commands', [])
                for command in commands:
                    logger.info(f"🎯 Executing command from server")
                    command_id = command.get("command_id") if isinstance(command, dict) else None
                    result = None
                    should_execute = True
                    if self._valid_command_id(command_id):
                        should_execute, result = self._prepare_command_execution(command)
                    if should_execute:
                        result = self.execute_command(command)
                        self._save_command_result(result)
                    elif result is None:
                        continue
                    self.report_action(result)
                
                return len(commands) > 0
        except Exception as e:
            logger.debug(f"Error checking for commands: {e}")
        
        return False


# Integration with existing agent
def run_defense_monitoring(interval: int = 5):
    """
    Run autonomous defense monitoring alongside telemetry collection.
    Checks for server commands every `interval` seconds.
    """
    defense = AutonomousDefense()
    logger.info(f"🛡️  Autonomous Defense System Started (checking every {interval}s)")
    
    while True:
        try:
            defense.check_for_commands()
            import time
            time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Autonomous Defense System stopped")
            break
        except Exception as e:
            logger.error(f"Defense monitoring error: {e}")
            import time
            time.sleep(interval)


if __name__ == "__main__":
    run_defense_monitoring()

# server/threat_analyzer.py
"""
Advanced AI Threat Analyzer using Ollama (Free LLM)
Performs deep analysis, root cause detection, and autonomous response decisions
"""

import os
import json
import requests
import sqlite3
import ipaddress
from typing import Dict, List, Tuple
import time

OLLAMA_API = os.environ.get("OLLAMA_API", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama2:7b")
SUSPICIOUS_PROCESS_MARKERS = ("hack", "malware", "keylog", "miner", "virus", "trojan")
MAX_PROCESSES_PER_RESPONSE = 5
MIN_EXTERNAL_IPS_FOR_ISOLATION = 6
MIN_CPU_FOR_ISOLATION = 95
MIN_PROCESSES_FOR_RESOURCE_SIGNAL = 200
AGENT_ACTIONS = {"kill_process", "isolate_machine"}
AGENT_ACTION_STATUSES = {
    "executed", "partial", "failed", "rejected", "disabled", "unknown", "dry_run",
}
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
    """Fail closed when defense is disabled, safe mode is enabled, or config is invalid."""
    truthy = {"1", "true", "yes", "on"}
    enabled = os.environ.get("DEFENSE_ENABLED", "true").strip().lower()
    safe_mode = os.environ.get("DEFENSE_SAFE_MODE", "false").strip().lower()
    return enabled in truthy and safe_mode in {"0", "false", "no", "off"}


def defense_isolation_enabled() -> bool:
    return defense_actions_enabled() and os.environ.get(
        "DEFENSE_ISOLATION_ENABLED", "false"
    ).strip().lower() in {"1", "true", "yes", "on"}


def assess_isolation_evidence(telemetry: Dict) -> List[Dict]:
    """Return independent deterministic signal summaries from one telemetry sample."""
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
                "names": sorted(set(suspicious.values()), key=str.casefold)[:MAX_PROCESSES_PER_RESPONSE],
                "processes": [
                    {"pid": pid, "name": suspicious[pid]}
                    for pid in sorted(suspicious)[:MAX_PROCESSES_PER_RESPONSE]
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


def persist_agent_action_report(db_path: str, report: Dict) -> int:
    """Validate and persist the agent's outcome; return its audit-row ID."""
    if not isinstance(report, dict):
        raise ValueError("report must be a JSON object")

    host_id = report.get("host_id")
    command = report.get("command")
    status = report.get("status")
    if not isinstance(host_id, str) or not host_id.strip() or len(host_id) > 256:
        raise ValueError("host_id must be a non-empty string of at most 256 characters")
    if not isinstance(command, str) or command not in AGENT_ACTIONS:
        raise ValueError("command is not an authorized defense action")
    if not isinstance(status, str) or status not in AGENT_ACTION_STATUSES:
        raise ValueError("status is not a recognized agent outcome")
    command_id = report.get("command_id")
    if command_id is not None and (
        not isinstance(command_id, str) or not command_id.strip() or len(command_id) > 64
    ):
        raise ValueError("command_id must be a non-empty string of at most 64 characters")

    try:
        details_json = json.dumps(report.get("details", {}), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("details must be valid JSON data") from error
    if len(details_json.encode("utf-8")) > 65536:
        raise ValueError("details exceed the 64 KiB audit limit")

    con = sqlite3.connect(db_path, timeout=5)
    try:
        cur = con.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS agent_action_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id TEXT NOT NULL,
            reported_at REAL NOT NULL,
            command TEXT NOT NULL,
            status TEXT NOT NULL,
            details TEXT NOT NULL,
            command_id TEXT
        )""")
        cur.execute("PRAGMA table_info(agent_action_log)")
        columns = {row[1] for row in cur.fetchall()}
        if "command_id" not in columns:
            cur.execute("ALTER TABLE agent_action_log ADD COLUMN command_id TEXT")
        cur.execute("""CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_action_command_id
                        ON agent_action_log(command_id) WHERE command_id IS NOT NULL""")

        if command_id is not None:
            cur.execute(
                """SELECT host_id, action, status, delivery_attempts FROM defense_commands
                   WHERE command_id = ?""",
                (command_id,),
            )
            queued_command = cur.fetchone()
            if (queued_command is None or queued_command[0] != host_id
                    or queued_command[1] != command):
                raise ValueError("command_id does not match a command for this host and action")
            if queued_command[3] == 0:
                raise ValueError("command has not been delivered and cannot be acknowledged")

            cur.execute(
                "SELECT id FROM agent_action_log WHERE command_id = ?",
                (command_id,),
            )
            existing_report = cur.fetchone()
            if existing_report is not None:
                con.commit()
                return existing_report[0]

        cur.execute(
            """INSERT INTO agent_action_log
                (host_id, reported_at, command, status, details, command_id)
                VALUES (?, ?, ?, ?, ?, ?)""",
            (host_id, time.time(), command, status, details_json, command_id),
        )
        report_id = cur.lastrowid
        if command_id is not None:
            cur.execute(
                """UPDATE defense_commands
                   SET status = 'reported', reported_at = ?
                   WHERE command_id = ? AND host_id = ? AND action = ?
                     AND status IN ('pending', 'delivered', 'cancelled')
                     AND delivery_attempts > 0""",
                (time.time(), command_id, host_id, command),
            )
            if cur.rowcount != 1:
                raise ValueError("command is no longer awaiting an agent report")
        con.commit()
        return report_id
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


class CompromiseTracker:
    """Tracks compromised machines and escalates responses for persistent threats."""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self._init_compromise_table()
    
    def _init_compromise_table(self):
        """Create compromised_machines table if it doesn't exist."""
        try:
            con = sqlite3.connect(self.db_path)
            cur = con.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS compromised_machines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id TEXT UNIQUE,
                    first_compromise_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_threat_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    threat_count INTEGER DEFAULT 1,
                    threat_types TEXT,
                    status TEXT DEFAULT 'active',
                    isolation_reason TEXT,
                    notes TEXT
                )
            """)
            con.commit()
            con.close()
        except Exception as e:
            print(f"Error initializing compromise table: {e}")
    
    def check_compromise_history(self, host_id: str, threat_type: str) -> Tuple[bool, str]:
        """
        Check if host was previously compromised and determine if escalation needed.
        Returns: (is_compromised, escalation_reason)
        """
        try:
            con = sqlite3.connect(self.db_path)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute(
                'SELECT * FROM compromised_machines WHERE host_id = ?',
                (host_id,)
            )
            history = cur.fetchone()
            con.close()
            
            if not history:
                return False, ""
            
            threat_count = history['threat_count']
            previous_threats = history['threat_types'].split(',') if history['threat_types'] else []
            
            # Escalation logic
            if threat_count >= 2:
                return True, f"Persistent threat (detected {threat_count} times)"
            elif threat_type in previous_threats:
                return True, f"Same threat type reappeared: {threat_type}"
            
            return True, f"Host previously compromised (count: {threat_count})"
        except Exception as e:
            print(f"Error checking compromise history: {e}")
            return False, ""
    
    def log_compromise(self, host_id: str, threat_type: str, ai_confidence: float, 
                       ai_analysis: str = "") -> None:
        """Log a threat detection for a host."""
        try:
            con = sqlite3.connect(self.db_path)
            cur = con.cursor()
            
            # Check if host already in table
            cur.execute('SELECT threat_types FROM compromised_machines WHERE host_id = ?', (host_id,))
            result = cur.fetchone()
            
            if result:
                # Update existing entry
                existing_threats = result[0].split(',') if result[0] else []
                if threat_type not in existing_threats:
                    existing_threats.append(threat_type)
                new_threats = ','.join(existing_threats)
                
                cur.execute("""
                    UPDATE compromised_machines 
                    SET last_threat_time = CURRENT_TIMESTAMP,
                        threat_count = threat_count + 1,
                        threat_types = ?,
                        notes = ?
                    WHERE host_id = ?
                """, (new_threats, ai_analysis[:200], host_id))
            else:
                # Insert new entry
                cur.execute("""
                    INSERT INTO compromised_machines 
                    (host_id, threat_count, threat_types, notes)
                    VALUES (?, 1, ?, ?)
                """, (host_id, threat_type, ai_analysis[:200]))
            
            con.commit()
            con.close()
        except Exception as e:
            print(f"Error logging compromise: {e}")
    
    def mark_isolated(self, host_id: str, reason: str) -> None:
        """Mark a host as isolated."""
        try:
            con = sqlite3.connect(self.db_path)
            cur = con.cursor()
            cur.execute("""
                UPDATE compromised_machines 
                SET status = 'isolated', isolation_reason = ?
                WHERE host_id = ?
            """, (reason, host_id))
            con.commit()
            con.close()
        except Exception as e:
            print(f"Error marking host as isolated: {e}")
    
    def get_compromised_hosts(self) -> List[Dict]:
        """Get all compromised machines."""
        try:
            con = sqlite3.connect(self.db_path)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute('SELECT * FROM compromised_machines ORDER BY last_threat_time DESC')
            
            hosts = []
            for row in cur.fetchall():
                hosts.append(dict(row))
            con.close()
            return hosts
        except Exception as e:
            print(f"Error getting compromised hosts: {e}")
            return []


class ThreatAnalyzer:
    def __init__(self, db_path):
        self.db_path = db_path
        self.analysis_cache = {}  # Cache analyses to avoid redundant calls
        self.compromise_tracker = CompromiseTracker(db_path)
        
    def get_telemetry_context(self, host_id: str, limit: int = 10) -> List[Dict]:
        """Get recent telemetry for a host to understand patterns."""
        try:
            con = sqlite3.connect(self.db_path)
            cur = con.cursor()
            cur.execute("""
                SELECT ts, data FROM telemetry 
                WHERE host_id = ? 
                ORDER BY ts DESC LIMIT ?
            """, (host_id, limit))
            
            results = []
            for ts, data_json in cur.fetchall():
                data = json.loads(data_json)
                results.append({
                    'timestamp': ts,
                    'cpu': data.get('cpu', 0),
                    'ram_percent': data.get('ram', {}).get('percent', 0),
                    'processes': len(data.get('processes', [])),
                    'connections': len(data.get('net', [])),
                    'open_ports': len(data.get('open_ports', [])),
                    'strange_ips': data.get('strange_ips', [])
                })
            con.close()
            return results
        except Exception as e:
            print(f"Error getting telemetry context: {e}")
            return []
    
    def analyze_threat_with_ai(self, host_id: str, current_telemetry: Dict, 
                               anomaly_reason: str) -> Dict:
        """
        Use LLM to deeply analyze what's happening and why.
        Returns: {
            'threat_type': 'ransomware'|'cryptominer'|'ddos_agent'|'unknown_malware'|'compromised_account'|'unusual_load',
            'confidence': 0.85,
            'root_cause': 'Explanation of what is actually happening',
            'recommendation': 'What action to take',
            'severity': 'critical'|'high'|'medium'|'low'
        }
        """
        
        # Build context from recent history
        history = self.get_telemetry_context(host_id, limit=5)
        
        # Create analysis prompt
        prompt = f"""You are an expert cybersecurity threat analyst. Analyze this suspicious activity and determine what's actually happening.

HOST: {host_id}
CURRENT STATUS:
- CPU Usage: {current_telemetry.get('cpu', 0)}%
- RAM Usage: {current_telemetry.get('ram', {}).get('percent', 0)}%
- Disk Usage: {current_telemetry.get('disk', {}).get('percent', 0)}%
- Running Processes: {len(current_telemetry.get('processes', []))}
- Network Connections: {len(current_telemetry.get('net', []))}
- Open Ports: {len(current_telemetry.get('open_ports', []))}
- Strange IPs: {current_telemetry.get('strange_ips', [])}

HISTORICAL PATTERN (last 5 measurements):
{json.dumps(history, indent=2)}

ANOMALY DETECTED: {anomaly_reason}

Analyze this and provide:
1. THREAT_TYPE: What kind of attack/malware is this? (ransomware, cryptominer, ddos_agent, data_exfil, compromised_account, unusual_load, unknown)
2. CONFIDENCE: How confident are you? (0.0 to 1.0)
3. ROOT_CAUSE: What is ACTUALLY happening on this system?
4. SUSPICIOUS_PROCESSES: List any suspicious process names visible
5. SUSPICIOUS_CONNECTIONS: Any suspicious IP addresses or ports?
6. RECOMMENDED_ACTION: What should be done? (kill_process, block_ip, isolate_machine, investigate_further)
7. SEVERITY: How severe? (critical, high, medium, low)

Respond in JSON format only."""

        try:
            print(f"🤖 AI Analyzing threat on {host_id}...")
            
            response = requests.post(
                OLLAMA_API,
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": 0.3  # Low temperature for consistent analysis
                },
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                ai_response = result.get('response', '{}')
                
                # Try to parse JSON from response
                try:
                    analysis = json.loads(ai_response)
                except json.JSONDecodeError:
                    # If response isn't pure JSON, try to extract it
                    import re
                    json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
                    if json_match:
                        analysis = json.loads(json_match.group())
                    else:
                        analysis = self._parse_text_analysis(ai_response)
                
                return {
                    'threat_type': analysis.get('threat_type', 'unknown').lower().replace(' ', '_'),
                    'confidence': float(analysis.get('confidence', analysis.get('CONFIDENCE', 0.5))),
                    'root_cause': analysis.get('root_cause', analysis.get('ROOT_CAUSE', 'Unknown')),
                    'suspicious_processes': analysis.get('suspicious_processes', analysis.get('SUSPICIOUS_PROCESSES', [])),
                    'suspicious_connections': analysis.get('suspicious_connections', analysis.get('SUSPICIOUS_CONNECTIONS', [])),
                    'recommendation': analysis.get('recommended_action', analysis.get('RECOMMENDED_ACTION', 'investigate_further')),
                    'severity': analysis.get('severity', analysis.get('SEVERITY', 'medium')).lower()
                }
            else:
                print(f"AI API error: {response.status_code}")
                return self._default_analysis(current_telemetry, anomaly_reason)
                
        except requests.exceptions.ConnectionError:
            print("⚠️  Ollama not running. Install: ollama pull llama2")
            return self._default_analysis(current_telemetry, anomaly_reason)
        except Exception as e:
            print(f"Error in AI analysis: {e}")
            return self._default_analysis(current_telemetry, anomaly_reason)
    
    def _parse_text_analysis(self, text: str) -> Dict:
        """Fallback: Parse text response from AI."""
        analysis = {}
        
        # Extract threat type
        if 'ransomware' in text.lower():
            analysis['threat_type'] = 'ransomware'
        elif 'cryptominer' in text.lower() or 'crypto' in text.lower():
            analysis['threat_type'] = 'cryptominer'
        elif 'ddos' in text.lower():
            analysis['threat_type'] = 'ddos_agent'
        elif 'unusual' in text.lower() or 'high load' in text.lower():
            analysis['threat_type'] = 'unusual_load'
        else:
            analysis['threat_type'] = 'unknown_malware'
        
        # Extract confidence
        analysis['confidence'] = 0.65
        
        # Extract recommendation
        if 'kill' in text.lower() or 'terminate' in text.lower():
            analysis['recommended_action'] = 'kill_process'
        elif 'block' in text.lower() or 'firewall' in text.lower():
            analysis['recommended_action'] = 'block_ip'
        elif 'isolate' in text.lower() or 'disconnect' in text.lower():
            analysis['recommended_action'] = 'isolate_machine'
        else:
            analysis['recommended_action'] = 'investigate_further'
        
        analysis['severity'] = 'high'
        analysis['root_cause'] = text[:200] + "..."
        
        return analysis
    
    def _default_analysis(self, telemetry: Dict, reason: str) -> Dict:
        """Default analysis when AI is unavailable."""
        cpu = telemetry.get('cpu', 0)
        ram = telemetry.get('ram', {}).get('percent', 0)
        num_procs = len(telemetry.get('processes', []))
        
        # Simple heuristics
        if cpu > 80 and num_procs > 200:
            threat_type = 'cryptominer'
            rec = 'kill_process'
            severity = 'high'
        elif cpu > 90:
            threat_type = 'high_cpu_anomaly'
            rec = 'investigate_further'
            severity = 'medium'
        elif len(telemetry.get('strange_ips', [])) > 5:
            threat_type = 'ddos_agent'
            rec = 'isolate_machine'
            severity = 'critical'
        else:
            threat_type = 'unusual_load'
            rec = 'investigate_further'
            severity = 'low'
        
        return {
            'threat_type': threat_type,
            'confidence': 0.45,
            'root_cause': reason,
            'suspicious_processes': [],
            'suspicious_connections': [],
            'recommendation': rec,
            'severity': severity
        }


class AutonomousResponseEngine:
    """
    Authorizes deterministic process mitigation and evidence-backed isolation;
    LLM output is informational only.
    """
    
    def __init__(self, db_path):
        self.db_path = db_path
    
    def decide_response(self, analysis: Dict, host_id: str, telemetry: Dict = None) -> Dict:
        """
        Process termination requires an exact observed suspicious process identity.
        Isolation requires two independent deterministic telemetry signals and an
        explicit operator opt-in. Analysis recommendations never authorize actions.
        """
        decision = {
            'action': 'alert_only',
            'targets': [],
            'execute': False,
            'reason': 'No observed process matched an automatic mitigation rule.'
        }
        if not defense_actions_enabled():
            decision['reason'] = 'Defense actions are disabled or safe mode is active.'
            return decision

        processes = telemetry.get('processes', []) if isinstance(telemetry, dict) else []
        if not isinstance(processes, list):
            return decision
        evidence = assess_isolation_evidence(telemetry)
        if (defense_isolation_enabled() and len(evidence) >= 2
                and any(item['signal'] == 'external_connection_burst' for item in evidence)):
            summary = "; ".join(
                f"{item['signal']}={json.dumps(item, sort_keys=True)}"
                for item in evidence
            )
            return {
                'action': 'isolate_machine',
                'targets': [host_id],
                'execute': True,
                'reason': f'Isolation authorized by {len(evidence)} independent telemetry signals: {summary}',
                'evidence': evidence,
            }

        targets = []
        seen_pids = set()
        for process in processes:
            if not isinstance(process, dict):
                continue
            pid = process.get('pid')
            name = process.get('name')
            created_at = process.get('create_time_us')
            if (isinstance(pid, int) and not isinstance(pid, bool) and pid > 0
                    and pid not in {1, 4}
                    and isinstance(name, str) and name.strip()
                    and name.casefold() not in PROTECTED_PROCESS_NAMES
                    and isinstance(created_at, int) and not isinstance(created_at, bool)
                    and created_at > 0
                    and any(marker in name.casefold() for marker in SUSPICIOUS_PROCESS_MARKERS)
                    and pid not in seen_pids):
                targets.append({
                    'pid': pid,
                    'name': name,
                    'create_time_us': created_at
                })
                seen_pids.add(pid)
                if len(targets) == MAX_PROCESSES_PER_RESPONSE:
                    break

        if targets:
            decision = {
                'action': 'kill_process',
                'targets': targets,
                'execute': True,
                'reason': 'Observed process name matched a configured threat marker.'
            }
        return decision

    @staticmethod
    def _valid_process_targets(targets: List[Dict]) -> bool:
        return (
            isinstance(targets, list)
            and 0 < len(targets) <= MAX_PROCESSES_PER_RESPONSE
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
    
    def execute_response(self, decision: Dict, host_id: str, telemetry: Dict = None) -> Dict:
        """
        Revalidate authorization before producing an agent command.
        """
        result = {
            'action': decision.get('action', 'alert_only'),
            'authorized': False,
            'executed': False,
            'result': 'Not executed',
            'timestamp': time.time()
        }
        if not decision.get('execute'):
            result['result'] = 'Skipped (response policy did not authorize an action).'
            return result

        action = decision.get('action')
        targets = decision.get('targets')
        reason = decision.get('reason', '')
        if not defense_actions_enabled():
            result['result'] = 'Skipped (defense actions are disabled or safe mode is active).'
        elif action != 'kill_process':
            if action == 'isolate_machine':
                evidence = assess_isolation_evidence(telemetry)
                expected_evidence = decision.get('evidence')
                if (not defense_isolation_enabled() or len(evidence) < 2
                        or not any(item['signal'] == 'external_connection_burst'
                                   for item in evidence)
                        or evidence != expected_evidence
                        or decision.get('targets') != [host_id]):
                    result['result'] = 'Rejected (isolation evidence or opt-in validation failed).'
                else:
                    result = self._authorize_isolate_machine(host_id, evidence, reason)
            else:
                result['result'] = 'Rejected (action is not authorized by the automatic response policy).'
        elif not self._valid_process_targets(targets):
            result['result'] = 'Rejected (process targets failed identity validation).'
        else:
            result = self._authorize_kill_process(host_id, targets, reason)
        return result
    
    def _authorize_kill_process(self, host_id: str, processes: List[Dict], reason: str) -> Dict:
        """Authorize an exact process command for agent-side execution."""
        print(f"   📋 Command: KILL_PROCESS")
        print(f"   🖥️  Host: {host_id}")
        print(f"   ⚙️  Processes: {processes}")
        print(f"   ✅ Authorized for agent delivery")
        
        return {
            'action': 'kill_process',
            'authorized': True,
            'executed': False,
            'result': f'Process termination command authorized for {host_id}; awaiting agent execution.',
            'timestamp': time.time()
        }

    def _authorize_isolate_machine(self, host_id: str, evidence: List[Dict], reason: str) -> Dict:
        """Authorize network isolation after telemetry evidence validation."""
        print(f"   📋 Command: ISOLATE_MACHINE")
        print(f"   🖥️  Host: {host_id}")
        print(f"   🔎 Evidence: {evidence}")
        return {
            'action': 'isolate_machine',
            'authorized': True,
            'executed': False,
            'result': f'Isolation command authorized for {host_id}; awaiting agent execution.',
            'timestamp': time.time()
        }


def log_response_action(db_path: str, host_id: str, analysis: Dict, 
                       decision: Dict, execution_result: Dict) -> None:
    """Log all threat analysis and response actions for audit trail."""
    con = None
    try:
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        
        # Ensure response_log table exists
        cur.execute("""CREATE TABLE IF NOT EXISTS response_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id TEXT,
            ts REAL,
            threat_type TEXT,
            confidence REAL,
            root_cause TEXT,
            decision_reason TEXT,
            action_taken TEXT,
            execution_result TEXT
        )""")
        cur.execute("PRAGMA table_info(response_log)")
        columns = {row[1] for row in cur.fetchall()}
        if {'ts', 'decision_reason', 'action_taken', 'execution_result'} <= columns:
            timestamp_column = 'ts'
            decision_column = 'decision_reason'
            action_column = 'action_taken'
            result_column = 'execution_result'
        elif {'timestamp', 'decision', 'action_executed', 'result'} <= columns:
            timestamp_column = 'timestamp'
            decision_column = 'decision'
            action_column = 'action_executed'
            result_column = 'result'
        else:
            raise sqlite3.DatabaseError("response_log has an unsupported schema")

        cur.execute(
            f"""INSERT INTO response_log
                (host_id, {timestamp_column}, threat_type, confidence, root_cause,
                 {decision_column}, {action_column}, {result_column})
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (host_id, time.time(), analysis['threat_type'], analysis['confidence'],
             analysis['root_cause'], decision['reason'], decision['action'],
             execution_result['result'])
        )
        
        con.commit()
    except Exception as e:
        print(f"Error logging response: {e}")
    finally:
        if con is not None:
            con.close()

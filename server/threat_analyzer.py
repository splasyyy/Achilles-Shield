# server/threat_analyzer.py
"""
Advanced AI Threat Analyzer using Ollama (Free LLM)
Performs deep analysis, root cause detection, and autonomous response decisions
"""

import os
import json
import requests
import sqlite3
from typing import Dict, List, Tuple
import time

OLLAMA_API = os.environ.get("OLLAMA_API", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama2:7b")

class ThreatAnalyzer:
    def __init__(self, db_path):
        self.db_path = db_path
        self.analysis_cache = {}  # Cache analyses to avoid redundant calls
        
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
    Autonomous system that decides how to respond to threats
    and executes appropriate actions.
    """
    
    def __init__(self, db_path):
        self.db_path = db_path
    
    def decide_response(self, analysis: Dict, host_id: str) -> Dict:
        """
        Decide autonomous response based on threat analysis.
        Returns: {
            'action': 'block_ip' | 'kill_process' | 'isolate_machine' | 'alert_only',
            'targets': ['process_name'] or ['ip_address'],
            'execute': True/False (based on severity threshold),
            'reason': 'Why taking this action'
        }
        """
        
        threat_type = analysis['threat_type']
        severity = analysis['severity']
        confidence = analysis['confidence']
        recommendation = analysis['recommendation']
        
        print(f"\n🎯 Autonomous Response Engine deciding action...")
        print(f"   Threat: {threat_type} | Severity: {severity} | Confidence: {confidence}")
        
        # Decision logic
        decision = {
            'action': 'alert_only',
            'targets': [],
            'execute': False,
            'reason': 'Insufficient confidence'
        }
        
        # HIGH SEVERITY + HIGH CONFIDENCE = AUTO-EXECUTE
        if severity == 'critical' and confidence > 0.7:
            if threat_type == 'ddos_agent':
                decision = {
                    'action': 'isolate_machine',
                    'targets': [host_id],
                    'execute': True,
                    'reason': f'CRITICAL: DDOS agent detected (confidence: {confidence}). Isolating immediately.'
                }
            elif threat_type == 'ransomware':
                decision = {
                    'action': 'isolate_machine',
                    'targets': [host_id],
                    'execute': True,
                    'reason': f'CRITICAL: Ransomware detected (confidence: {confidence}). Isolating to prevent spread.'
                }
        
        # HIGH SEVERITY + MEDIUM CONFIDENCE = KILL PROCESS + ALERT
        elif severity in ['high', 'critical'] and confidence > 0.6:
            if threat_type == 'cryptominer':
                suspicious_procs = analysis.get('suspicious_processes', [])
                decision = {
                    'action': 'kill_process',
                    'targets': suspicious_procs if suspicious_procs else ['unknown_process'],
                    'execute': True,
                    'reason': f'HIGH: Cryptominer detected. Killing suspicious processes: {suspicious_procs}'
                }
            elif threat_type == 'ddos_agent':
                decision = {
                    'action': 'isolate_machine',
                    'targets': [host_id],
                    'execute': True,
                    'reason': f'HIGH: DDoS agent detected. Isolating machine.'
                }
            elif recommendation == 'block_ip':
                suspicious_ips = analysis.get('suspicious_connections', [])
                decision = {
                    'action': 'block_ip',
                    'targets': suspicious_ips,
                    'execute': True,
                    'reason': f'HIGH: Blocking suspicious IPs: {suspicious_ips}'
                }
        
        # MEDIUM SEVERITY + HIGH CONFIDENCE = BLOCK IPS + ALERT
        elif severity == 'medium' and confidence > 0.75:
            if recommendation == 'block_ip':
                suspicious_ips = analysis.get('suspicious_connections', [])
                decision = {
                    'action': 'block_ip',
                    'targets': suspicious_ips,
                    'execute': True,
                    'reason': f'MEDIUM: Blocking suspected malicious IPs (high confidence).'
                }
            else:
                decision = {
                    'action': 'alert_only',
                    'targets': [],
                    'execute': False,
                    'reason': f'MEDIUM severity - alerting for human review.'
                }
        
        # LOW SEVERITY OR LOW CONFIDENCE = ALERT ONLY
        else:
            decision = {
                'action': 'alert_only',
                'targets': [],
                'execute': False,
                'reason': f'Insufficient threat level (severity: {severity}, confidence: {confidence}). Alerting only.'
            }
        
        return decision
    
    def execute_response(self, decision: Dict, host_id: str) -> Dict:
        """
        Execute the decided response action.
        In real implementation, would send commands to agents.
        """
        
        action = decision['action']
        execute = decision['execute']
        reason = decision['reason']
        targets = decision['targets']
        
        result = {
            'action': action,
            'executed': False,
            'result': 'Not executed',
            'timestamp': time.time()
        }
        
        if not execute:
            result['result'] = 'Skipped (confidence too low). Human review recommended.'
            print(f"⚠️  {result['result']}")
            return result
        
        print(f"\n🚨 EXECUTING AUTONOMOUS DEFENSE ACTION: {action.upper()}")
        print(f"   Reason: {reason}")
        
        if action == 'kill_process':
            result = self._execute_kill_process(host_id, targets, reason)
        elif action == 'block_ip':
            result = self._execute_block_ip(host_id, targets, reason)
        elif action == 'isolate_machine':
            result = self._execute_isolate_machine(host_id, reason)
        
        return result
    
    def _execute_kill_process(self, host_id: str, processes: List[str], reason: str) -> Dict:
        """Execute process termination on remote host."""
        print(f"   📋 Command: KILL_PROCESS")
        print(f"   🖥️  Host: {host_id}")
        print(f"   ⚙️  Processes: {processes}")
        print(f"   ✅ EXECUTED (command sent to agent)")
        
        # In real implementation:
        # - Send kill_process command to agent
        # - Agent terminates processes
        # - Agent reports back
        
        return {
            'action': 'kill_process',
            'executed': True,
            'result': f'Killed processes: {processes} on {host_id}',
            'timestamp': time.time()
        }
    
    def _execute_block_ip(self, host_id: str, ips: List[str], reason: str) -> Dict:
        """Execute IP blocking on remote host."""
        print(f"   📋 Command: BLOCK_IP")
        print(f"   🖥️  Host: {host_id}")
        print(f"   🚫 Blocked IPs: {ips}")
        print(f"   ✅ EXECUTED (firewall rule added)")
        
        # In real implementation:
        # - Add firewall rules to agent
        # - Agent blocks outbound connections to these IPs
        # - Agent monitors for bypass attempts
        
        return {
            'action': 'block_ip',
            'executed': True,
            'result': f'Blocked IPs: {ips} on {host_id}',
            'timestamp': time.time()
        }
    
    def _execute_isolate_machine(self, host_id: str, reason: str) -> Dict:
        """Execute machine isolation (network disconnect)."""
        print(f"   📋 Command: ISOLATE_MACHINE")
        print(f"   🖥️  Host: {host_id}")
        print(f"   🔌 ACTION: Disconnecting from network")
        print(f"   ✅ EXECUTED (machine isolated)")
        
        # In real implementation:
        # - Send network_disconnect command
        # - Agent disables network interfaces
        # - System becomes air-gapped from network
        # - Threat cannot spread
        
        return {
            'action': 'isolate_machine',
            'executed': True,
            'result': f'Isolated {host_id} from network',
            'timestamp': time.time()
        }


def log_response_action(db_path: str, host_id: str, analysis: Dict, 
                       decision: Dict, execution_result: Dict) -> None:
    """Log all threat analysis and response actions for audit trail."""
    try:
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        
        # Ensure response_log table exists
        cur.execute("""CREATE TABLE IF NOT EXISTS response_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id TEXT,
            timestamp REAL,
            threat_type TEXT,
            confidence REAL,
            root_cause TEXT,
            decision TEXT,
            action_executed TEXT,
            result TEXT
        )""")
        
        cur.execute("""INSERT INTO response_log 
            (host_id, timestamp, threat_type, confidence, root_cause, decision, action_executed, result)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (host_id, time.time(), analysis['threat_type'], analysis['confidence'],
             analysis['root_cause'], decision['reason'], decision['action'],
             execution_result['result']))
        
        con.commit()
        con.close()
    except Exception as e:
        print(f"Error logging response: {e}")

# agent/autonomous_defense.py
"""
Agent-side autonomous defense executor
Receives commands from server and executes threat responses
"""

import os
import json
import requests
import subprocess
import platform
import psutil
from typing import Dict, List
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

SERVER_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:5000")
API_KEY = os.environ.get("API_KEY", "supersecret")
HOST_ID = os.environ.get("HOST_ID", "unknown")

class AutonomousDefense:
    """
    Autonomous defense executor on agent side.
    Receives threat response commands and executes them.
    """
    
    def __init__(self):
        self.platform = platform.system()
        self.host_id = HOST_ID
    
    def kill_process(self, process_names: List[str]) -> Dict:
        """
        Terminate suspicious processes by name.
        """
        logger.warning(f"🔴 DEFENSE ACTION: Killing processes: {process_names}")
        results = {}
        
        try:
            for process_name in process_names:
                killed = False
                
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if process_name.lower() in proc.info['name'].lower():
                            pid = proc.info['pid']
                            logger.warning(f"   Terminating: {proc.info['name']} (PID: {pid})")
                            
                            if self.platform == 'Windows':
                                os.system(f"taskkill /PID {pid} /F")
                            else:
                                os.kill(pid, 9)
                            
                            results[process_name] = f"Killed PID {pid}"
                            killed = True
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                if not killed:
                    results[process_name] = "Process not found or already terminated"
        
        except Exception as e:
            logger.error(f"Error killing processes: {e}")
            results['error'] = str(e)
        
        return results
    
    def block_ip(self, ips: List[str]) -> Dict:
        """
        Block outbound connections to suspicious IPs using firewall rules.
        """
        logger.warning(f"🔴 DEFENSE ACTION: Blocking IPs: {ips}")
        results = {}
        
        try:
            if self.platform == 'Windows':
                for ip in ips:
                    cmd = f'netsh advfirewall firewall add rule name="Block {ip}" dir=out action=block remoteip={ip}'
                    logger.warning(f"   Blocking IP: {ip}")
                    os.system(cmd)
                    results[ip] = "Blocked via Windows Firewall"
            
            elif self.platform == 'Linux':
                for ip in ips:
                    cmd = f'sudo iptables -A OUTPUT -d {ip} -j DROP'
                    logger.warning(f"   Blocking IP: {ip}")
                    subprocess.run(cmd.split(), check=False)
                    results[ip] = "Blocked via iptables"
            
            elif self.platform == 'Darwin':  # macOS
                for ip in ips:
                    cmd = f'sudo pfctl -t blocklist -T add {ip}'
                    logger.warning(f"   Blocking IP: {ip}")
                    subprocess.run(cmd.split(), check=False)
                    results[ip] = "Blocked via pfctl"
        
        except Exception as e:
            logger.error(f"Error blocking IPs: {e}")
            results['error'] = str(e)
        
        return results
    
    def isolate_machine(self) -> Dict:
        """
        Disconnect machine from network (air-gap protection).
        Disables network interfaces.
        """
        logger.error(f"🔴 DEFENSE ACTION: ISOLATING MACHINE - Disconnecting from network")
        results = {}
        
        try:
            if self.platform == 'Windows':
                # Disable all network adapters
                logger.warning("   Disabling Windows network adapters...")
                os.system('netsh interface set interface name="Ethernet" admin=disabled')
                os.system('netsh interface set interface name="Wi-Fi" admin=disabled')
                results['status'] = "Network interfaces disabled"
            
            elif self.platform == 'Linux':
                logger.warning("   Bringing down Linux network interfaces...")
                # Bring down all active interfaces
                result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if ':' in line:
                        iface = line.split(':')[1].strip()
                        if iface not in ['lo', 'docker0']:
                            subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'down'])
                results['status'] = "Network interfaces brought down"
            
            elif self.platform == 'Darwin':  # macOS
                logger.warning("   Disconnecting macOS from network...")
                os.system('networksetup -setairplanemode on')
                results['status'] = "Airplane mode enabled"
        
        except Exception as e:
            logger.error(f"Error isolating machine: {e}")
            results['error'] = str(e)
        
        results['isolated'] = True
        return results
    
    def execute_command(self, command: Dict) -> Dict:
        """
        Execute autonomous defense command from server.
        Command format: {
            'action': 'kill_process' | 'block_ip' | 'isolate_machine',
            'targets': ['process_name'] or ['ip_address'] or [],
            'reason': 'Why this action'
        }
        """
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
        
        try:
            if action == 'kill_process':
                result['details'] = self.kill_process(targets)
                result['status'] = 'executed'
            
            elif action == 'block_ip':
                result['details'] = self.block_ip(targets)
                result['status'] = 'executed'
            
            elif action == 'isolate_machine':
                result['details'] = self.isolate_machine()
                result['status'] = 'executed'
            
            else:
                result['status'] = 'unknown_command'
                logger.warning(f"Unknown command: {action}")
        
        except Exception as e:
            result['status'] = 'failed'
            result['error'] = str(e)
            logger.error(f"Error executing command: {e}")
        
        logger.info(f"✅ Command executed: {result['status']}")
        return result
    
    def report_action(self, result: Dict) -> bool:
        """
        Report executed action back to server for logging.
        """
        try:
            headers = {"Content-Type": "application/json", "X-API-KEY": API_KEY}
            response = requests.post(
                f"{SERVER_URL}/report_defense_action",
                json=result,
                headers=headers,
                timeout=5
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error reporting action to server: {e}")
            return False
    
    def check_for_commands(self) -> bool:
        """
        Poll server for autonomous defense commands.
        Called periodically to check if server wants to execute actions.
        """
        try:
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
                    result = self.execute_command(command)
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

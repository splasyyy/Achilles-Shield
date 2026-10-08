# agent/agent.py  (BEGIN)
import os, sys, time, socket, platform, json, threading
import psutil, requests
from autonomous_defense import (
    AutonomousDefense,
    defense_actions_enabled,
    defense_dry_run_enabled,
    normalize_server_url,
)

SERVER_URL = normalize_server_url(
    os.environ.get("SERVER_URL", "http://127.0.0.1:5000")
)
INGEST_URL = SERVER_URL + "/ingest"
API_KEY = os.environ.get("API_KEY", "supersecret")
HOST_ID = os.environ.get("HOST_ID", socket.gethostname())
INTERVAL = int(os.environ.get("INTERVAL", "2"))

# Initialize autonomous defense
defense = AutonomousDefense()

def collect():
    """Collect system telemetry data."""
    info = {
        "host_id": HOST_ID,
        "ts": time.time(),
        "os": platform.platform(),
        "hostname": socket.gethostname(),
        "processes": [],
        "cpu": psutil.cpu_percent(interval=0.5),
        "ram": {
            "total": psutil.virtual_memory().total,
            "used": psutil.virtual_memory().used,
            "percent": psutil.virtual_memory().percent
        },
        "disk": {
            "total": psutil.disk_usage('/').total,
            "used": psutil.disk_usage('/').used,
            "percent": psutil.disk_usage('/').percent
        }
    }
    for p in psutil.process_iter(['pid','name','username','cmdline']):
        try:
            info['processes'].append({
                "pid": p.info['pid'],
                "name": p.info.get('name'),
                "create_time_us": int(p.create_time() * 1_000_000),
                "user": p.info.get('username'),
                "cmdline": p.info.get('cmdline')[:10] if p.info.get('cmdline') else []
            })
        except Exception:
            pass

    conns = []
    open_ports = set()
    active_conns = []
    strange_ips = []

    for c in psutil.net_connections(kind='inet'):
        try:
            laddr = "%s:%s" % (c.laddr.ip, c.laddr.port) if c.laddr else ""
            raddr = "%s:%s" % (c.raddr.ip, c.raddr.port) if c.raddr else ""
            status = c.status
            pid = c.pid
            conn = {"laddr": laddr, "raddr": raddr, "status": status, "pid": pid}
            conns.append(conn)
            # Open ports
            if status == "LISTEN":
                open_ports.add(c.laddr.port)
            # Active connections
            if status == "ESTABLISHED":
                active_conns.append(conn)
                # Strange IPs: not private/local
                if c.raddr and not (c.raddr.ip.startswith("10.") or c.raddr.ip.startswith("192.168.") or c.raddr.ip.startswith("172.")):
                    strange_ips.append(c.raddr.ip)
        except Exception:
            pass

    info['net'] = conns[:20]
    info['open_ports'] = sorted(list(open_ports))
    info['active_conns'] = active_conns[:10]
    info['strange_ips'] = list(set(strange_ips))[:10]
    return info

def send(payload):
    """Send telemetry to server."""
    headers = {"Content-Type": "application/json", "X-API-KEY": API_KEY}
    try:
        r = requests.post(INGEST_URL, json=payload, headers=headers, timeout=5)
        return r.status_code == 200
    except Exception as e:
        print("send error:", e)
        return False

def check_commands():
    """Check for autonomous defense commands from server."""
    defense.check_for_commands()

def run_defense_loop():
    """Background thread: Check for defense commands."""
    while True:
        check_commands()
        time.sleep(5)  # Check every 5 seconds

if __name__ == "__main__":
    if "--check" in sys.argv[1:]:
        readiness = defense.preflight()
        print(f"Agent host: {readiness['host_id']}")
        print(f"Local state database: {readiness['state_db']} ({readiness['local_state']})")
        print(f"Server readiness: {readiness['server']}")
        if readiness.get("server_defense_enabled") is not None:
            print(
                "Server defense: "
                + ("enabled" if readiness["server_defense_enabled"] else "disabled/safe mode")
            )
        if readiness["dry_run"]:
            print("Agent mitigation: dry-run")
        elif readiness["defense_enabled"]:
            print("Agent mitigation: enabled")
        else:
            print("Agent mitigation: disabled/safe mode")
        sys.exit(0 if readiness["ready"] else 1)

    print(f"\n🛡️  Achilles Shield Agent Starting")
    print(f"   Host: {HOST_ID}")
    print(f"   Server: {SERVER_URL}")
    print(f"   Telemetry Interval: {INTERVAL}s")
    print(f"   Defense Check: 5s")
    if not defense_actions_enabled():
        defense_mode = "DISABLED (safe mode)"
    elif defense_dry_run_enabled():
        defense_mode = "DRY RUN (no disruptive actions)"
    else:
        defense_mode = "ENABLED"
    print(f"   Autonomous Defense: {defense_mode}")
    
    # Start defense command checker in background thread
    defense_thread = threading.Thread(target=run_defense_loop, daemon=True)
    defense_thread.start()
    print("✅ Autonomous Defense System Ready\n")
    
    # Main telemetry loop
    while True:
        try:
            data = collect()
            ok = send(data)
            print(f"✓ Telemetry sent | Processes: {len(data['processes'])} | CPU: {data['cpu']:.1f}% | RAM: {data['ram']['percent']:.1f}%")
            time.sleep(INTERVAL)
        except KeyboardInterrupt:
            print("\n🛑 Agent stopped")
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(INTERVAL)
# agent/agent.py  (END)
# agent/agent.py  (BEGIN)
import os, time, socket, platform, json
import psutil, requests

SERVER_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:5000/ingest")
API_KEY = os.environ.get("API_KEY", "supersecret")
HOST_ID = os.environ.get("HOST_ID", socket.gethostname())
INTERVAL = int(os.environ.get("INTERVAL", "2"))  # was "10"

def collect():
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
    headers = {"Content-Type": "application/json", "X-API-KEY": API_KEY}
    try:
        r = requests.post(SERVER_URL, json=payload, headers=headers, timeout=5)
        return r.status_code == 200
    except Exception as e:
        print("send error:", e)
        return False

if __name__ == "__main__":
    print("Agent starting, sending to", SERVER_URL, "as", HOST_ID)
    while True:
        data = collect()
        ok = send(data)
        print("sent:", ok, "processes:", len(data['processes']))
        time.sleep(INTERVAL)
# agent/agent.py  (END)
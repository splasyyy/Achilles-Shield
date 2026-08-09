import os
import requests

ABUSEIPDB_KEY_ENV = "ABUSEIPDB_KEY"


def check_ip_abuse(ip: str) -> bool:
    """Query AbuseIPDB for an IP reputation. Returns True if score > 50.
    Falls back to False if API key not configured or error occurs."""
    key = os.environ.get(ABUSEIPDB_KEY_ENV)
    if not key:
        return False

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {"Key": key, "Accept": "application/json"}

    try:
        r = requests.get(url, headers=headers, params=params, timeout=5)
        if r.status_code != 200:
            return False
        data = r.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        return int(score) >= 50
    except Exception as e:
        print(f"Error querying AbuseIPDB: {e}")
        return False

import requests
import json
from datetime import datetime

# Uses free OTX AlienVault API (replace with your key)
OTX_API_KEY = "YOUR_OTX_API_KEY"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

def fetch_threat_intel(indicator_type="IPv4", indicator="8.8.8.8"):
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = f"{OTX_BASE_URL}/indicators/{indicator_type}/{indicator}/general"
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        print(f"[*] Threat Intel for {indicator} ({indicator_type})")
        print(f"    Pulse Count (threat reports): {pulse_count}")
        print(f"    Reputation: {data.get('reputation', 'N/A')}")
        print(f"    Country: {data.get('country_name', 'N/A')}")
        return data
    except requests.RequestException as e:
        print(f"[-] Sync failed: {e}")
        return None

def sync_latest_pulses(limit=5):
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = f"{OTX_BASE_URL}/pulses/subscribed?limit={limit}"
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        pulses = resp.json().get("results", [])
        print(f"\n[*] Latest {len(pulses)} Threat Intel Pulses synced at {datetime.now()}")
        for p in pulses:
            print(f"  - {p['name']} | Tags: {', '.join(p.get('tags', []))}")
        return pulses
    except requests.RequestException as e:
        print(f"[-] Pulse sync failed: {e}")
        return []

if __name__ == "__main__":
    fetch_threat_intel("IPv4", "8.8.8.8")
    sync_latest_pulses(5)

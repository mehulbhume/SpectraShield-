from collections import defaultdict
from datetime import datetime
import random  # simulating traffic; replace with real packet capture

# Simulate network connection logs: (src_ip, dst_ip, timestamp)
def simulate_connections(n=100):
    suspicious_ip = "185.220.101.45"  # simulated C2 server
    logs = []
    base_time = datetime.now().timestamp()
    for i in range(n):
        # Inject regular beaconing every ~30s from one host
        logs.append(("10.0.0.5", suspicious_ip, base_time + i * 30 + random.uniform(-2, 2)))
        # Add random noise
        logs.append((f"10.0.0.{random.randint(1,20)}",
                      f"93.{random.randint(1,255)}.{random.randint(1,255)}.1",
                      base_time + random.uniform(0, 3000)))
    return logs

def detect_beaconing(logs, interval_threshold=5, min_connections=5):
    traffic = defaultdict(list)
    for src, dst, ts in logs:
        traffic[(src, dst)].append(ts)

    print("[*] C2 Beaconing Detection Report\n")
    beacons = []
    for (src, dst), timestamps in traffic.items():
        if len(timestamps) < min_connections:
            continue
        timestamps.sort()
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)

        # Low variance = regular = beaconing pattern
        if variance < interval_threshold ** 2:
            print(f"  [!] BEACON DETECTED: {src} -> {dst}")
            print(f"      Connections: {len(timestamps)} | Avg Interval: {avg_interval:.1f}s | Variance: {variance:.2f}")
            beacons.append({"src": src, "dst": dst, "avg_interval": avg_interval, "variance": variance})

    if not beacons:
        print("  [OK] No beaconing patterns detected.")
    return beacons

if __name__ == "__main__":
    logs = simulate_connections(100)
    detect_beaconing(logs)

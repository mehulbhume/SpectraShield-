import psutil
import os
import time

CPU_LIMIT = 1.0      # percent
RAM_LIMIT = 80.0     # MB

process = psutil.Process(os.getpid())

print("Low Footprint Monitor Started...")
print(f"CPU Limit: {CPU_LIMIT}%")
print(f"RAM Limit: {RAM_LIMIT} MB")
print("-" * 40)

while True:
    cpu = process.cpu_percent(interval=1)

    ram_mb = process.memory_info().rss / (1024 * 1024)

    status = "PASS"

    if cpu > CPU_LIMIT:
        status = "CPU_LIMIT_EXCEEDED"

    if ram_mb > RAM_LIMIT:
        status = "RAM_LIMIT_EXCEEDED"

    print(
        f"CPU={cpu:.2f}% | "
        f"RAM={ram_mb:.2f} MB | "
        f"STATUS={status}"
    )

    time.sleep(5)
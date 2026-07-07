import platform
import socket
import uuid
import psutil
import json

def get_asset_info():

    asset_data = {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "cpu_cores": psutil.cpu_count(logical=False),
        "logical_cpus": psutil.cpu_count(logical=True),
        "ram_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        "mac_address": ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                        for elements in range(0, 2*6, 2)][::-1]),
        "ip_address": socket.gethostbyname(socket.gethostname())
    }

    return asset_data


if __name__ == "__main__":
    print(json.dumps(get_asset_info(), indent=4))
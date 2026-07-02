import subprocess

def check_bitlocker():
    result = subprocess.run(["manage-bde", "-status"], capture_output=True, text=True)
    return "Protection On" in result.stdout

def block_usb():
    # Example using Windows registry policy (simplified)
    subprocess.run(["reg", "add", r"HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR", 
                    "/v", "Start", "/t", "REG_DWORD", "/d", "4", "/f"])

def enforce_security():
    if not check_bitlocker():
        print("⚠️ BitLocker not enabled!")
    else:
        print("✅ BitLocker active")
    block_usb()
    print("🔒 USB devices blocked")

if __name__ == "__main__":
    enforce_security()


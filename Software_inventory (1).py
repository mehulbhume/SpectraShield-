import winreg
import json

def get_installed_software():

    software_list = []

    registry_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    ]

    for reg_path in registry_paths:

        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)

            for i in range(0, winreg.QueryInfoKey(reg_key)[0]):

                try:
                    subkey_name = winreg.EnumKey(reg_key, i)
                    subkey = winreg.OpenKey(reg_key, subkey_name)

                    software = {
                        "name": winreg.QueryValueEx(subkey, "DisplayName")[0]
                        if True else "Unknown",

                        "version": winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                        if True else "Unknown",

                        "publisher": winreg.QueryValueEx(subkey, "Publisher")[0]
                        if True else "Unknown"
                    }

                    software_list.append(software)

                except:
                    continue

        except:
            continue

    return software_list


if __name__ == "__main__":
    print(json.dumps(get_installed_software(), indent=4))
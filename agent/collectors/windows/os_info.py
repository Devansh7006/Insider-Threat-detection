import platform
import os

def collect_os_info():
    return {
        "os_family": platform.system(),
        "os_name": platform.platform(),
        "architecture": platform.machine(),
        "is_admin": os.name == "nt" and os.environ.get("USERNAME") == "Administrator"
    }

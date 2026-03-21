# agent/os_detect.py
import platform
import os

def detect_os():
    info = {}
    pf = platform.system()
    info["os_family"] = pf
    info["platform"] = platform.platform()
    info["os_name"] = info["platform"]
    if pf == "Windows":
        # Prefer Windows product name from registry (e.g. Windows 11 Pro)
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            )
            product_name, _ = winreg.QueryValueEx(key, "ProductName")
            display_version = ""
            try:
                display_version, _ = winreg.QueryValueEx(key, "DisplayVersion")
            except Exception:
                display_version = ""
            release_id = ""
            try:
                release_id, _ = winreg.QueryValueEx(key, "ReleaseId")
            except Exception:
                release_id = ""
            version_label = display_version or release_id
            info["os_name"] = f"{product_name} {version_label}".strip()
        except Exception:
            # Fallback: use platform text if registry is unavailable
            info["os_name"] = info["platform"]
    try:
        info["username"] = os.environ.get("USERNAME") or os.environ.get("USER") or ""
        if not info["username"]:
            try:
                import getpass
                info["username"] = getpass.getuser() or ""
            except Exception:
                info["username"] = ""
    except Exception:
        info["username"] = ""
    try:
        if pf == "Windows":
            # quick admin detection
            try:
                import ctypes
                info["is_admin"] = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                info["is_admin"] = False
        else:
            info["is_admin"] = (os.geteuid() == 0)
    except Exception:
        info["is_admin"] = False
    return info

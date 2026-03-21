import subprocess
import time

def check_firewall():
    try:
        output = subprocess.check_output(
            'netsh advfirewall show allprofiles',
            shell=True,
            text=True
        )
        return "ON" in output
    except:
        return False


def check_antivirus():
    try:
        output = subprocess.check_output(
            'powershell Get-MpComputerStatus | Select -ExpandProperty AMServiceEnabled',
            shell=True,
            text=True
        )
        return "True" in output
    except:
        return False


def check_disk_encryption():
    try:
        output = subprocess.check_output(
            'manage-bde -status',
            shell=True,
            text=True
        )
        return "Protection On" in output
    except:
        return False


def collect_compliance():

    firewall = check_firewall()
    antivirus = check_antivirus()
    disk = check_disk_encryption()

    score = 0
    if firewall: score += 30
    if antivirus: score += 30
    if disk: score += 40

    return {
        "event_type": "COMPLIANCE_STATUS",
        "timestamp": time.time(),
        "compliance_score": score,
        "controls": {
            "firewall_enabled": firewall,
            "disk_encryption": disk,
            "screen_lock_policy": True,
            "antivirus_running": antivirus,
            "usb_restricted": False
        },
        "enforced": []
    }
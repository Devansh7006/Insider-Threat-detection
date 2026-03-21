import psutil

def collect_vpn_status():
    interfaces = psutil.net_if_addrs().keys()
    vpn_keywords = ["tun", "tap", "vpn", "wireguard"]

    detected = any(
        any(k in iface.lower() for k in vpn_keywords)
        for iface in interfaces
    )

    return {
        "status": "active" if detected else "inactive",
        "interfaces": list(interfaces)
    }

"""
Network Volume Collector (Windows).

Tracks aggregated bytes sent/received and connection counts as a behavioral signal.
Privacy: NO packet inspection, NO IPs, NO domains/URLs/ports, NO content — metadata only.
"""
import time

try:
    import psutil
except ImportError:
    psutil = None

POLL_INTERVAL = 5.0
AGGREGATION_WINDOW = 30.0
BYTES_5_MB = 5 * 1024 * 1024
BYTES_50_MB = 50 * 1024 * 1024


def _is_private_ip(ip: str) -> bool:
    """Return True if IP is private (LAN). We do NOT store or log the IP."""
    if not ip or not isinstance(ip, str):
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b, c, d = (int(p) & 0xFF for p in parts)
    except ValueError:
        return False
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    return False


def _get_io_delta(last):
    """
    Return (bytes_sent_delta, bytes_recv_delta) since last (sent, recv).
    Uses psutil.net_io_counters(); no packet inspection.
    """
    if not psutil:
        return None, None, None
    try:
        c = psutil.net_io_counters()
        if c is None:
            return None, None, None
        cur_sent = getattr(c, "bytes_sent", 0) or 0
        cur_recv = getattr(c, "bytes_recv", 0) or 0
        if last is None:
            return 0, 0, (cur_sent, cur_recv)
        last_sent, last_recv = last
        return (cur_sent - last_sent), (cur_recv - last_recv), (cur_sent, cur_recv)
    except Exception:
        return None, None, None


def _get_connection_counts():
    """
    Return (total_connections, local_count, external_count).
    We only count; we never store IPs, ports, or addresses.
    """
    if not psutil:
        return 0, 0, 0
    total = 0
    local = 0
    external = 0
    try:
        for conn in psutil.net_connections(kind="inet"):
            status = getattr(conn, "status", None)
            if status and status != "ESTABLISHED" and status != "SYN_SENT":
                continue
            raddr = getattr(conn, "raddr", None)
            total += 1
            if raddr is not None:
                ip = getattr(raddr, "ip", None) or ""
                if _is_private_ip(ip):
                    local += 1
                else:
                    external += 1
    except (psutil.AccessDenied, psutil.Error, Exception):
        pass
    return total, local, external


class NetworkActivityCollector:
    """
    Polls system network I/O counters and connection counts (no packet capture).
    Aggregates deltas over a window; emits NETWORK_ACTIVITY_SUMMARY.
    """

    def __init__(self, config):
        cfg = config.get("network_activity", {}) or {}
        self.poll_interval = float(cfg.get("poll_interval_sec", POLL_INTERVAL))
        self.interval = float(cfg.get("aggregation_sec", AGGREGATION_WINDOW))
        self.last_poll = time.time()
        self.last_flush = time.time()
        self._last_io = None
        self._bytes_sent = 0
        self._bytes_received = 0
        self._connections_sum = 0
        self._connections_count = 0
        self._local_connections_sum = 0
        self._external_connections_sum = 0

    def start(self):
        self.last_poll = time.time()
        self.last_flush = time.time()
        try:
            if psutil:
                c = psutil.net_io_counters()
                if c:
                    self._last_io = (
                        getattr(c, "bytes_sent", 0) or 0,
                        getattr(c, "bytes_recv", 0) or 0,
                    )
        except Exception:
            self._last_io = None
        self._bytes_sent = 0
        self._bytes_received = 0
        self._connections_sum = 0
        self._connections_count = 0
        self._local_connections_sum = 0
        self._external_connections_sum = 0

    def _poll_once(self):
        now = time.time()
        if now - self.last_poll < self.poll_interval:
            return
        self.last_poll = now
        ds, dr, new_io = _get_io_delta(self._last_io)
        if new_io is not None:
            self._last_io = new_io
        if ds is not None and ds >= 0:
            self._bytes_sent += ds
        if dr is not None and dr >= 0:
            self._bytes_received += dr
        conn_total, local, external = _get_connection_counts()
        self._connections_sum += conn_total
        self._connections_count += 1
        self._local_connections_sum += local
        self._external_connections_sum += external

    def flush_if_needed(self):
        self._poll_once()
        now = time.time()
        if now - self.last_flush < self.interval:
            return None
        self.last_flush = now
        if self._bytes_sent == 0 and self._bytes_received == 0 and self._connections_sum == 0:
            return None
        conn_avg = self._connections_sum // max(1, self._connections_count) if self._connections_count else 0
        direction = self._direction(self._bytes_sent, self._bytes_received)
        summary = {
            "bytes_sent": self._bytes_sent,
            "bytes_received": self._bytes_received,
            "connections": conn_avg,
            "direction": direction,
        }
        if self._local_connections_sum > 0 or self._external_connections_sum > 0:
            summary["local_connections"] = self._local_connections_sum // max(1, self._connections_count)
            summary["external_connections"] = self._external_connections_sum // max(1, self._connections_count)
        self._bytes_sent = 0
        self._bytes_received = 0
        self._connections_sum = 0
        self._connections_count = 0
        self._local_connections_sum = 0
        self._external_connections_sum = 0
        severity = self._severity(summary)
        return {
            "event_type": "NETWORK_ACTIVITY_SUMMARY",
            "summary": summary,
            "severity": severity,
            "timestamp": now,
        }

    def _direction(self, sent, recv):
        if sent > 2 * recv and recv >= 0:
            return "UPLOAD_HEAVY"
        if recv > 2 * sent and sent >= 0:
            return "DOWNLOAD_HEAVY"
        return "BALANCED"

    def _severity(self, summary):
        sent = summary.get("bytes_sent", 0)
        direction = summary.get("direction", "BALANCED")
        if sent > BYTES_50_MB:
            return "HIGH"
        if direction == "UPLOAD_HEAVY" and sent > BYTES_5_MB:
            return "HIGH"
        if sent >= BYTES_5_MB:
            return "MEDIUM"
        return "LOW"

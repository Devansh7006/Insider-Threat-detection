"""
Process Activity Collector (Windows).

Aggregates process names and counts as a behavioral signal for insider threat analysis.
Privacy: only process NAMES and COUNTS; no paths, cmdline, env, window titles, usernames.
"""
import time
from collections import defaultdict

try:
    import psutil
except ImportError:
    psutil = None
    import warnings
    warnings.warn("psutil not installed; process activity collector will not report any processes.", UserWarning)

POLL_INTERVAL = 5.0
AGGREGATION_WINDOW = 30.0


def _collect_process_names():
    """Return a set of process names seen in this snapshot (name only, no path)."""
    if not psutil:
        return set()
    seen = set()
    try:
        for p in psutil.process_iter(["name"]):
            try:
                name = p.info.get("name")
                if name and isinstance(name, str):
                    name = name.strip()
                    if name:
                        seen.add(name)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass
    return seen


class ProcessActivityCollector:
    """
    Polls process list periodically and aggregates by process name (count of
    poll appearances). Emits PROCESS_ACTIVITY_SUMMARY every aggregation window.
    """

    def __init__(self, config):
        fm = config.get("process_activity", {}) or {}
        self.poll_interval = float(fm.get("poll_interval_sec", POLL_INTERVAL))
        self.interval = float(fm.get("aggregation_sec", AGGREGATION_WINDOW))
        self.last_poll = time.time()
        self.last_flush = time.time()
        # name -> count of polls in which this name appeared (debounced per poll)
        self._counts = defaultdict(int)

    def start(self):
        self.last_poll = time.time()
        self.last_flush = time.time()
        self._counts.clear()

    def _poll_once(self):
        now = time.time()
        if now - self.last_poll < self.poll_interval:
            return
        self.last_poll = now
        names = _collect_process_names()
        for name in names:
            self._counts[name] += 1

    def flush_if_needed(self):
        self._poll_once()
        now = time.time()
        if now - self.last_flush < self.interval:
            return None
        self.last_flush = now
        summary = dict(self._counts)
        self._counts.clear()
        total = sum(summary.values())
        if total == 0:
            return None
        severity = self._severity(total)
        return {
            "event_type": "PROCESS_ACTIVITY_SUMMARY",
            "summary": summary,
            "severity": severity,
            "timestamp": now,
        }

    def _severity(self, total):
        if total < 20:
            return "LOW"
        if total <= 50:
            return "MEDIUM"
        return "HIGH"

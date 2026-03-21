import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .debounce import DebounceTracker
from .file_correlator import FileEventCorrelator
from collections import defaultdict

# ---------------------------
# Internal event handler
# ---------------------------
class _FileEventHandler(FileSystemEventHandler):
    def __init__(self, stats, debounce_sec=0.5):
        self.stats = stats
        self.debounce_sec = debounce_sec
        self.last_seen = defaultdict(float)
        self.recent_deletes = {}

    def _debounced(self, path):
        now = time.time()
        if now - self.last_seen[path] < self.debounce_sec:
            return True
        self.last_seen[path] = now
        return False

    def on_modified(self, event):
        if event.is_directory:
            return
        if self._debounced(event.src_path):
            return
        self.stats["write"] += 1

    def on_deleted(self, event):
        if event.is_directory:
            return
        self.stats["delete"] += 1
        self.recent_deletes[event.src_path] = time.time()

    def on_created(self, event):
        if event.is_directory:
            return

        # Rename / move inference
        now = time.time()
        for old_path, ts in list(self.recent_deletes.items()):
            if now - ts < 2:
                self.stats["rename"] += 1
                del self.recent_deletes[old_path]
                return

        self.stats["write"] += 1


# ---------------------------
# Public collector
# ---------------------------
class FileActivityCollector:
    def __init__(self, config):
        self.paths = config.get("file_monitor", {}).get(
            "paths", ["C:/Users"]
        )
        self.interval = config.get("file_monitor", {}).get(
            "aggregation_sec", 60
        )

        self.debouncer = DebounceTracker(window_ms=500)
        self.correlator = FileEventCorrelator(window_sec=2)


        self.stats = {"write": 0, "delete": 0, "rename": 0}
        self.last_flush = time.time()

        self.observer = Observer()
        self.handler = _FileEventHandler(self.stats)

    def start(self):
        for path in self.paths:
            self.observer.schedule(self.handler, path, recursive=True)
        self.observer.start()

    def flush_if_needed(self):
        now = time.time()
        if now - self.last_flush < self.interval:
            return None

        total = sum(self.stats.values())
        self.last_flush = now

        if total == 0:
            return None

        event = {
            "event_type": "FILE_ACTIVITY_SUMMARY",
            "summary": self.stats.copy(),
            "severity": self._severity(total),
            "timestamp": now,
        }

        # reset counters
        self.stats["write"] = 0
        self.stats["delete"] = 0
        self.stats["rename"] = 0

        return event

    def _severity(self, total):
        if total > 200:
            return "HIGH"
        if total > 50:
            return "MEDIUM"
        return "LOW"

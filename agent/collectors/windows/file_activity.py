import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import defaultdict

# ---------------------------
# Paths we never count. Used only locally; never logged or sent.
# We count: user dirs (Desktop, Documents, etc.) and app writes there; not OS.
# ---------------------------
# Pure OS locations (writes/renames/deletes here are not counted)
_SYSTEM_PREFIXES = (
    os.path.normpath("C:/Windows/").lower(),
    os.path.normpath("C:/Program Files/").lower(),
    os.path.normpath("C:/Program Files (x86)/").lower(),
    os.path.normpath("C:/ProgramData/").lower(),
)
# Noisy or non-user locations within any watched path
_NOISE_SUBSTRINGS = (
    "AppData",
    "\\Temp\\", "\\Tmp\\", "/Temp/", "/tmp/",
    ".cache",
    "$Recycle.Bin",
    ".git\\", ".git/",
    "node_modules",
    "__pycache__",
    ".vs\\", ".idea\\",
)


def _is_noise(path):
    """True if path is OS system or known noise (we do not count these)."""
    p = os.path.normpath(path).replace("/", os.sep).lower()
    if not p.endswith(os.sep):
        p += os.sep
    # Skip pure OS paths (Windows, Program Files, ProgramData)
    for prefix in _SYSTEM_PREFIXES:
        if p.startswith(prefix):
            return True
    # Skip caches, temp, IDE metadata, etc.
    return any(s.lower() in p for s in _NOISE_SUBSTRINGS)


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

    def _skip(self, path):
        return self._debounced(path) or _is_noise(path)

    def on_modified(self, event):
        if event.is_directory:
            return
        if self._skip(event.src_path):
            return
        self.stats["write"] += 1

    def on_deleted(self, event):
        if event.is_directory:
            return
        if _is_noise(event.src_path):
            return
        self.stats["delete"] += 1
        self.recent_deletes[event.src_path] = time.time()

    def on_moved(self, event):
        """Windows often reports renames as move events (src_path -> dest_path)."""
        if event.is_directory:
            return
        if _is_noise(event.src_path) or _is_noise(event.dest_path):
            return
        if self._debounced(event.dest_path):
            return
        self.stats["rename"] += 1

    def on_created(self, event):
        if event.is_directory:
            return
        if self._skip(event.src_path):
            return

        # Rename / move inference (when OS sends delete + create instead of moved)
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
        configured = config.get("file_monitor", {}).get("paths")
        if configured:
            self.paths = list(configured)
        else:
            # Default: C:/Users and cwd (so running from project dir picks up edits)
            self.paths = ["C:/Users"]
            cwd = os.getcwd()
            if cwd and os.path.isdir(cwd) and cwd not in self.paths:
                self.paths.append(cwd)
        self.interval = config.get("file_monitor", {}).get(
            "aggregation_sec", 60
        )

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

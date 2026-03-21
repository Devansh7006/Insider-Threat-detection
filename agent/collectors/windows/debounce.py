import time
from collections import defaultdict

class DebounceTracker:
    def __init__(self, window_ms=500):
        self.window = window_ms / 1000.0
        self.last_seen = defaultdict(float)

    def allow(self, key: str) -> bool:
        now = time.time()
        last = self.last_seen[key]
        if now - last < self.window:
            return False
        self.last_seen[key] = now
        return True

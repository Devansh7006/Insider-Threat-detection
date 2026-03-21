"""
Clipboard Activity Collector (Windows).

Tracks clipboard usage patterns as a behavioral signal (counts and size categories only).
Privacy: NO content is captured, stored, or transmitted — only metadata and counts.
"""
import time
import sys

# Size category thresholds (bytes)
SIZE_SMALL = 1024          # < 1 KB
SIZE_MEDIUM = 1024 * 1024  # 1 MB
POLL_INTERVAL = 1.5
AGGREGATION_WINDOW = 30.0

# Windows constants
CF_UNICODETEXT = 13
CF_TEXT = 1
CF_HDROP = 15

_windows_available = False
_user32 = _kernel32 = None


def _init_windows_api():
    global _windows_available, _user32, _kernel32
    if sys.platform != "win32":
        return
    try:
        import ctypes
        _user32 = ctypes.windll.user32
        _kernel32 = ctypes.windll.kernel32
        # GetClipboardSequenceNumber exists on Vista+
        if not hasattr(_user32, "GetClipboardSequenceNumber"):
            return
        _windows_available = True
    except Exception:
        pass


def _get_clipboard_metadata():
    """
    Returns (sequence_number, size_bytes) for current clipboard.
    Does NOT read any content; uses sequence number and GlobalSize(handle) only.
    On failure returns (None, None). Fails silently.
    """
    if not _windows_available or not _user32 or not _kernel32:
        return None, None
    try:
        if not _user32.OpenClipboard(0):
            return None, None
        try:
            seq = _user32.GetClipboardSequenceNumber()
            if seq == 0:
                # May indicate no access
                return None, None
            size = None
            for fmt in (CF_UNICODETEXT, CF_TEXT, CF_HDROP):
                h = _user32.GetClipboardData(fmt)
                if h:
                    sz = _kernel32.GlobalSize(h)
                    if sz and sz != 0:
                        size = sz
                        break
            return seq, size
        finally:
            _user32.CloseClipboard()
    except Exception:
        return None, None


def _size_category(size_bytes):
    """Return 'small', 'medium', or 'large' from byte size. None -> 'medium' (unknown)."""
    if size_bytes is None:
        return "medium"
    if size_bytes < SIZE_SMALL:
        return "small"
    if size_bytes <= SIZE_MEDIUM:
        return "medium"
    return "large"


_init_windows_api()


class ClipboardActivityCollector:
    """
    Polls clipboard sequence number and optional size (metadata only).
    Counts copy events and size categories per window. No content is ever read.
    """

    def __init__(self, config):
        cfg = config.get("clipboard_activity", {}) or {}
        self.poll_interval = float(cfg.get("poll_interval_sec", POLL_INTERVAL))
        self.interval = float(cfg.get("aggregation_sec", AGGREGATION_WINDOW))
        self.last_poll = time.time()
        self.last_flush = time.time()
        self._last_seq = None
        self._copy_events = 0
        self._small = 0
        self._medium = 0
        self._large = 0

    def start(self):
        self.last_poll = time.time()
        self.last_flush = time.time()
        self._last_seq = None
        self._copy_events = 0
        self._small = 0
        self._medium = 0
        self._large = 0

    def _poll_once(self):
        now = time.time()
        if now - self.last_poll < self.poll_interval:
            return
        self.last_poll = now
        seq, size = _get_clipboard_metadata()
        if seq is None:
            return
        if self._last_seq is not None and seq != self._last_seq:
            self._copy_events += 1
            cat = _size_category(size)
            if cat == "small":
                self._small += 1
            elif cat == "medium":
                self._medium += 1
            else:
                self._large += 1
        self._last_seq = seq

    def flush_if_needed(self):
        self._poll_once()
        now = time.time()
        if now - self.last_flush < self.interval:
            return None
        self.last_flush = now
        if self._copy_events == 0 and self._small == 0 and self._medium == 0 and self._large == 0:
            return None
        summary = {
            "copy_events": self._copy_events,
            "small": self._small,
            "medium": self._medium,
            "large": self._large,
        }
        self._copy_events = 0
        self._small = 0
        self._medium = 0
        self._large = 0
        severity = self._severity(summary)
        return {
            "event_type": "CLIPBOARD_ACTIVITY_SUMMARY",
            "summary": summary,
            "severity": severity,
            "timestamp": now,
        }

    def _severity(self, summary):
        copy_events = summary.get("copy_events", 0)
        large = summary.get("large", 0)
        if copy_events > 30 or large > 0:
            return "HIGH"
        if copy_events >= 10:
            return "MEDIUM"
        return "LOW"

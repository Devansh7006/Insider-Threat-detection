import time

class FileEventCorrelator:
    def __init__(self, window_sec=2):
        self.window = window_sec
        self.deletes = {}

    def record_delete(self, path: str):
        self.deletes[path] = time.time()

    def record_create(self, path: str) -> bool:
        now = time.time()
        for old_path, ts in list(self.deletes.items()):
            if now - ts <= self.window:
                del self.deletes[old_path]
                return True  # rename/move inferred
--        return False

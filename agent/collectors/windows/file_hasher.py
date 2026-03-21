import hashlib

def hash_file(path: str, max_bytes=5 * 1024 * 1024):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            data = f.read(max_bytes)
            h.update(data)
        return h.hexdigest()
    except Exception:
        return None

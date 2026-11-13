"""CWE-362: locking the read and write separately does not make an update atomic."""

import threading


class VulnerableCounter:
    def __init__(self):
        self.value = 0
        self._lock = threading.Lock()

    def increment(self, after_read=None):
        with self._lock:
            previous = self.value
        if after_read is not None:
            after_read()
        with self._lock:
            self.value = previous + 1  # RACE: PY-RACE-004


class SafeCounter:
    def __init__(self):
        self.value = 0
        self._lock = threading.Lock()

    def increment(self):
        with self._lock:
            self.value = self.value + 1  # SAFE: PY-RACE-004

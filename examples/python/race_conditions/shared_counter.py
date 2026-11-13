"""CWE-362: an unprotected read-modify-write loses a concurrent increment."""

import threading


class VulnerableCounter:
    def __init__(self):
        self.value = 0

    def increment(self, after_read=None):
        previous = self.value
        if after_read is not None:
            after_read()
        self.value = previous + 1  # RACE: PY-RACE-001


class SafeCounter:
    def __init__(self):
        self.value = 0
        self._lock = threading.Lock()

    def increment(self):
        with self._lock:
            self.value = self.value + 1  # SAFE: PY-RACE-001

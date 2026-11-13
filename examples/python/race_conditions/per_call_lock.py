"""CWE-362: a newly allocated lock in each call does not protect shared data."""

import threading


class VulnerableCounter:
    def __init__(self):
        self.value = 0

    def increment(self, after_read=None):
        lock = threading.Lock()  # Each caller gets a DIFFERENT lock.
        with lock:
            previous = self.value
            if after_read is not None:
                after_read()
            self.value = previous + 1  # RACE: PY-RACE-003


class SafeCounter:
    def __init__(self):
        self.value = 0
        self._lock = threading.Lock()

    def increment(self):
        with self._lock:
            self.value = self.value + 1  # SAFE: PY-RACE-003

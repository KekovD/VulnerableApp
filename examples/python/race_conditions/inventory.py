"""CWE-367: two threads can both reserve the last item after checking stock."""

import threading


class VulnerableInventory:
    def __init__(self):
        self.stock = {"widget": 1}

    def reserve(self, product, after_check=None):
        if self.stock.get(product, 0) <= 0:
            return False
        if after_check is not None:
            after_check()
        self.stock[product] -= 1  # RACE: PY-RACE-002
        return True


class SafeInventory:
    def __init__(self):
        self.stock = {"widget": 1}
        self._lock = threading.Lock()

    def reserve(self, product):
        with self._lock:
            if self.stock.get(product, 0) <= 0:
                return False
            self.stock[product] -= 1  # SAFE: PY-RACE-002
            return True

"""CWE-362: a check and debit separated by await can overdraw a shared account."""

import asyncio


class VulnerableAccount:
    def __init__(self, balance=100):
        self.balance = balance

    async def withdraw(self, amount, authorize=None):
        if amount <= 0:
            raise ValueError("amount must be positive")
        if self.balance < amount:
            return False
        if authorize is None:
            await asyncio.sleep(0)  # Simulates an asynchronous authorization call.
        else:
            await authorize()
        self.balance -= amount  # RACE: PY-RACE-005
        return True


class SafeAccount:
    def __init__(self, balance=100):
        self.balance = balance
        self._lock = asyncio.Lock()

    async def withdraw(self, amount, authorize=None):
        if amount <= 0:
            raise ValueError("amount must be positive")
        async with self._lock:
            if self.balance < amount:
                return False
            if authorize is None:
                await asyncio.sleep(0)
            else:
                await authorize()
            self.balance -= amount  # SAFE: PY-RACE-005
            return True

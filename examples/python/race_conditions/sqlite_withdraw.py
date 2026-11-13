"""CWE-362: a SELECT followed by a separate UPDATE can overdraw an account."""

from contextlib import closing
import sqlite3


def withdraw_vulnerable(database, amount, after_check=None):
    if amount <= 0:
        raise ValueError("amount must be positive")
    # Autocommit leaves the SELECT and UPDATE in different transactions.
    with closing(sqlite3.connect(database, isolation_level=None, timeout=5)) as connection:
        balance = connection.execute("SELECT balance FROM accounts WHERE id = 1").fetchone()[0]
        if balance < amount:
            return False
        if after_check is not None:
            after_check()
        connection.execute(  # RACE: PY-RACE-007
            "UPDATE accounts SET balance = balance - ? WHERE id = 1", (amount,)
        )
        return True


def withdraw_safe(database, amount):
    if amount <= 0:
        raise ValueError("amount must be positive")
    # The database serializes the conditional update, including between processes.
    with closing(sqlite3.connect(database, isolation_level=None, timeout=5)) as connection:
        cursor = connection.execute(  # SAFE: PY-RACE-007
            "UPDATE accounts SET balance = balance - ? WHERE id = 1 AND balance >= ?",
            (amount, amount),
        )
        return cursor.rowcount == 1

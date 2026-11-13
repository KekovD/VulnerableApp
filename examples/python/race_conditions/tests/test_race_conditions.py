"""Reproduce each race and check the corresponding fixed variant using stdlib only."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import multiprocessing
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest

CASE_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CASE_DIRECTORY))

import async_balance
import file_create
import inventory
import per_call_lock
import process_counter
import shared_counter
import split_lock
import sqlite_withdraw


def run_two_threads(worker):
    start = threading.Barrier(2, timeout=5)

    def run():
        start.wait()
        return worker()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(run) for _ in range(2)]
        return [future.result(timeout=10) for future in futures]


class ThreadRaceTests(unittest.TestCase):
    def check_lost_increment(self, counter):
        both_read = threading.Barrier(2, timeout=5)
        run_two_threads(lambda: counter.increment(both_read.wait))
        self.assertEqual(counter.value, 1, "Two increments lost one update")

    def check_atomic_increment(self, counter):
        run_two_threads(counter.increment)
        self.assertEqual(counter.value, 2)

    def test_unprotected_update_loses_increment(self):
        self.check_lost_increment(shared_counter.VulnerableCounter())

    def test_shared_lock_preserves_increment(self):
        self.check_atomic_increment(shared_counter.SafeCounter())

    def test_local_lock_does_not_synchronize_callers(self):
        self.check_lost_increment(per_call_lock.VulnerableCounter())

    def test_reused_lock_synchronizes_callers(self):
        self.check_atomic_increment(per_call_lock.SafeCounter())

    def test_split_critical_section_loses_increment(self):
        self.check_lost_increment(split_lock.VulnerableCounter())

    def test_single_critical_section_preserves_increment(self):
        self.check_atomic_increment(split_lock.SafeCounter())

    def test_inventory_sells_last_item_twice(self):
        stock = inventory.VulnerableInventory()
        both_checked = threading.Barrier(2, timeout=5)
        results = run_two_threads(lambda: stock.reserve("widget", both_checked.wait))
        self.assertEqual(results, [True, True])
        self.assertLessEqual(stock.stock["widget"], 0)

    def test_inventory_lock_prevents_overselling(self):
        stock = inventory.SafeInventory()
        results = run_two_threads(lambda: stock.reserve("widget"))
        self.assertEqual(sorted(results), [False, True])
        self.assertEqual(stock.stock["widget"], 0)


class AsyncRaceTests(unittest.IsolatedAsyncioTestCase):
    async def test_await_between_check_and_debit_overdraws(self):
        account = async_balance.VulnerableAccount()
        both_checked = asyncio.Event()
        arrivals = 0

        async def authorize():
            nonlocal arrivals
            arrivals += 1
            if arrivals == 2:
                both_checked.set()
            await both_checked.wait()

        results = await asyncio.wait_for(
            asyncio.gather(account.withdraw(80, authorize), account.withdraw(80, authorize)),
            timeout=5,
        )
        self.assertEqual(results, [True, True])
        self.assertEqual(account.balance, -60)

    async def test_async_lock_prevents_overdraft(self):
        account = async_balance.SafeAccount()
        results = await asyncio.wait_for(
            asyncio.gather(account.withdraw(80), account.withdraw(80)), timeout=5
        )
        self.assertEqual(sorted(results), [False, True])
        self.assertEqual(account.balance, 20)


class FileRaceTests(unittest.TestCase):
    def test_check_then_open_allows_two_creators(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "claim.txt"
            both_checked = threading.Barrier(2, timeout=5)
            results = run_two_threads(
                lambda: file_create.create_vulnerable(path, "claimed", both_checked.wait)
            )
            self.assertEqual(results, [True, True])
            self.assertEqual(path.read_text(encoding="utf-8"), "claimed")

    def test_exclusive_creation_allows_one_creator(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "claim.txt"
            results = run_two_threads(lambda: file_create.create_safe(path, "claimed"))
            self.assertEqual(sorted(results), [False, True])
            self.assertEqual(path.read_text(encoding="utf-8"), "claimed")


class DatabaseRaceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.database = str(Path(self.directory.name) / "accounts.sqlite")
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance INTEGER)")
            connection.execute("INSERT INTO accounts VALUES (1, 100)")
            connection.commit()

    def balance(self):
        with closing(sqlite3.connect(self.database)) as connection:
            return connection.execute("SELECT balance FROM accounts WHERE id = 1").fetchone()[0]

    def test_select_then_update_overdraws_account(self):
        both_checked = threading.Barrier(2, timeout=5)
        results = run_two_threads(
            lambda: sqlite_withdraw.withdraw_vulnerable(self.database, 80, both_checked.wait)
        )
        self.assertEqual(results, [True, True])
        self.assertEqual(self.balance(), -60)

    def test_atomic_update_prevents_overdraft(self):
        results = run_two_threads(lambda: sqlite_withdraw.withdraw_safe(self.database, 80))
        self.assertEqual(sorted(results), [False, True])
        self.assertEqual(self.balance(), 20)


class ProcessRaceTests(unittest.TestCase):
    def run_workers(self, vulnerable):
        # spawn works on Linux, macOS and Windows; no dependency on fork semantics.
        context = multiprocessing.get_context("spawn")
        counter = context.Value("i", 0)
        barrier = context.Barrier(2, timeout=10)
        worker = process_counter.increment_vulnerable if vulnerable else process_counter.increment_safe
        args = (counter, barrier.wait) if vulnerable else (counter,)
        processes = [context.Process(target=worker, args=args) for _ in range(2)]
        started = []
        try:
            for process in processes:
                process.start()
                started.append(process)
            for process in started:
                process.join(timeout=15)
                self.assertFalse(process.is_alive(), "Worker did not finish")
                self.assertEqual(process.exitcode, 0)
            return counter.value
        finally:
            for process in started:
                if process.is_alive():
                    process.terminate()
                process.join(timeout=5)

    def test_value_property_lock_does_not_protect_update(self):
        self.assertEqual(self.run_workers(vulnerable=True), 1)

    def test_explicit_value_lock_protects_update(self):
        self.assertEqual(self.run_workers(vulnerable=False), 2)


if __name__ == "__main__":
    unittest.main()

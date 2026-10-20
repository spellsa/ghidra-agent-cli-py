import threading
import unittest
from unittest.mock import patch
from ghidra_inline.decompiler import DecompilerPool

class Interface:
    def __init__(self):
        self.disposed = threading.Event()
    def dispose(self):
        self.disposed.set()

class PoolTests(unittest.TestCase):
    def setUp(self):
        self.pool = DecompilerPool(None, idle_seconds=.1)
        self.factory = patch.object(self.pool, '_create', side_effect=Interface)
        self.factory.start()
        self.addCleanup(self.factory.stop)
        self.addCleanup(self.pool.clear, close=True)

    def test_reuse_and_independent_leases(self):
        with self.pool.lease() as first:
            with self.pool.lease() as second:
                self.assertIsNot(first, second)
                self.assertFalse(first.disposed.is_set())
        with self.pool.lease() as reused:
            self.assertIs(reused, first)

    def test_idle_expiration_and_new_checkout(self):
        with self.pool.lease() as first:
            pass
        self.assertTrue(first.disposed.wait(2))
        with self.pool.lease() as second:
            self.assertIsNot(first, second)

    def test_checkout_cancels_old_expiration(self):
        with self.pool.lease() as first:
            pass
        with self.pool.lease() as reused:
            self.assertIs(first, reused)
            self.assertFalse(first.disposed.wait(.2))
        self.assertTrue(first.disposed.wait(2))

    def test_failed_lease_and_uncached_write_lease(self):
        with self.assertRaisesRegex(RuntimeError, 'cancelled'):
            with self.pool.lease() as failed:
                raise RuntimeError('cancelled')
        self.assertTrue(failed.disposed.is_set())
        with self.pool.lease(reuse=False) as fresh:
            pass
        self.assertTrue(fresh.disposed.is_set())

    def test_clear_and_shutdown(self):
        with self.pool.lease() as first:
            pass
        self.pool.clear()
        self.assertTrue(first.disposed.is_set())
        with self.pool.lease() as second:
            self.pool.clear(close=True)
        self.assertTrue(second.disposed.is_set())
        with self.assertRaisesRegex(RuntimeError, 'closed'):
            with self.pool.lease():
                pass

if __name__ == '__main__':
    unittest.main()

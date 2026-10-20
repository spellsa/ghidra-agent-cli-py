"""Program-local decompilers, exclusively borrowed and retired after idle time."""
import threading
from contextlib import contextmanager

class DecompilerPool:
    def __init__(self, program, idle_seconds=60):
        self.program = program
        self.idle_seconds = idle_seconds
        self._lock = threading.Lock()
        self._idle = {}
        self._closed = False

    def _create(self):
        from ghidra.app.decompiler import DecompInterface
        interface = DecompInterface()
        try:
            if not interface.openProgram(self.program):
                raise RuntimeError('Cannot initialize decompiler')
            return interface
        except BaseException:
            interface.dispose()
            raise

    @contextmanager
    def lease(self, reuse=True):
        with self._lock:
            if self._closed:
                raise RuntimeError('Decompiler pool is closed')
            if reuse and self._idle:
                interface, timer = self._idle.popitem()
                timer.cancel()
            else:
                interface = None
        if interface is None:
            interface = self._create()
        try:
            yield interface
        except BaseException:
            interface.dispose()
            raise
        else:
            if reuse:
                self._release(interface)
            else:
                interface.dispose()

    def _release(self, interface):
        with self._lock:
            if not self._closed:
                timer = threading.Timer(self.idle_seconds, lambda: self._expire(interface, timer))
                timer.daemon = True
                self._idle[interface] = timer
                timer.start()
                return
        interface.dispose()

    def _expire(self, interface, timer):
        with self._lock:
            if self._idle.get(interface) is not timer:
                return
            del self._idle[interface]
        interface.dispose()

    def clear(self, close=False):
        with self._lock:
            self._closed |= close
            idle = list(self._idle.items())
            self._idle.clear()
            for interface, timer in idle:
                timer.cancel()
        for interface, timer in idle:
            interface.dispose()

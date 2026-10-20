"""Execution primitives: bounded job metadata, fair per-program access and routed IO."""
import contextvars
import hashlib
import io
import queue
import threading
import time
import uuid
from contextlib import contextmanager

current_job = contextvars.ContextVar('ghidra_job', default=None)

class Cancelled(Exception):
    pass

class RoutedIO(io.TextIOBase):
    def __init__(self, original, channel):
        self.original, self.channel = original, channel
    def write(self, text):
        job = current_job.get()
        if job is None:
            return self.original.write(text)
        if text:
            job.emit(self.channel, text)
        return len(text)
    def flush(self):
        if current_job.get() is None:
            self.original.flush()
    @property
    def encoding(self):
        return 'utf-8'
    def isatty(self):
        return False

class Access:
    """FIFO for writers; readers already ahead of a writer can run together."""
    def __init__(self):
        self.cv = threading.Condition()
        self.readers = 0
        self.writer = None
        self.waiting = []
        self.active = set()
    @contextmanager
    def enter(self, job):
        with self.cv:
            self.waiting.append(job)
            try:
                while True:
                    job.check()
                    ahead = self.waiting[:self.waiting.index(job)]
                    allowed = (self.writer is None and
                        (not self.readers and not ahead if job.write else not any(j.write for j in ahead)))
                    if allowed:
                        break
                    job.blocked_by = sorted(self.active | {j.id for j in ahead if j.write or job.write})
                    self.cv.wait(.05)
                self.waiting.remove(job)
                if job.write:
                    self.writer = job.id
                else:
                    self.readers += 1
                self.active.add(job.id)
                job.blocked_by = []
                job.state = 'running'
                job.started = time.time()
            except BaseException:
                self.waiting.remove(job)
                self.cv.notify_all()
                raise
        try:
            yield
        finally:
            with self.cv:
                self.active.remove(job.id)
                if job.write:
                    self.writer = None
                else:
                    self.readers -= 1
                self.cv.notify_all()

class Job:
    def __init__(self, target, code, write, monitor):
        self.id = 'J' + uuid.uuid4().hex[:16]
        self.target, self.code, self.write = target, code, write
        self.sha256 = hashlib.sha256(code.encode('utf-8')).hexdigest()
        self.monitor = monitor
        self.cancelled = threading.Event()
        self.disconnected = threading.Event()
        self.events = queue.Queue(maxsize=128)
        self.state, self.blocked_by = 'queued', []
        self.created, self.started, self.finished = time.time(), None, None
        self.tail = {'stdout': '', 'stderr': ''}
    def check(self):
        if self.cancelled.is_set():
            raise Cancelled('Execution cancelled')
    def cancel(self):
        if self.state not in ('success', 'error', 'cancelled'):
            self.state = 'cancel_requested'
            self.cancelled.set()
            self.monitor.cancel()
    def emit(self, channel, text):
        self.check()
        self.tail[channel] = (self.tail[channel] + text)[-16000:]
        for offset in range(0, len(text), 32768):
            self.send({'event': channel, 'text': text[offset:offset + 32768]})
    def send(self, event):
        while not self.disconnected.is_set():
            try:
                self.events.put(event, timeout=.1)
                return
            except queue.Full:
                if self.cancelled.is_set() and event['event'] not in ('error', 'done'):
                    raise Cancelled('Execution cancelled')
    def info(self):
        return {k: getattr(self, k) for k in ('id', 'target', 'write', 'state', 'blocked_by', 'created', 'started', 'finished')}

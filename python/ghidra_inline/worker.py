"""One project, one resident JVM, independent program handles and access queues."""
import argparse
import collections
import hashlib
import json
import queue
import select
import signal
import socket
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from .runtime import Access, Cancelled, Job, RoutedIO, current_job
from .helpers import Helpers
from .decompiler import DecompilerPool

class Failure(Exception):
    def __init__(self, code, message, next_action=''):
        super().__init__(message)
        self.code, self.next_action = code, next_action

def error_detail(exc, **context):
    return dict(code=getattr(exc, 'code', 'RUNTIME_ERROR'), message=str(exc),
                next_action=getattr(exc, 'next_action', 'read traceback and correct the script'),
                traceback=traceback.format_exc(), **context)

class Worker:
    def __init__(self, path):
        import pyghidra
        pyghidra.start()
        self.path = Path(path).resolve()
        self.project = pyghidra.open_project(str(self.path.parent), self.path.stem)
        self.guard = threading.RLock()
        self.programs, self.targets = {}, {}
        self.jobs = collections.OrderedDict()
        self.pool = ThreadPoolExecutor(max_workers=32, thread_name_prefix='ghidra')
        self.epoch = __import__('uuid').uuid4().hex[:12]
        sys.stdout, sys.stderr = RoutedIO(sys.stdout, 'stdout'), RoutedIO(sys.stderr, 'stderr')
    def use(self, path):
        import pyghidra
        path = '/' + path.lstrip('/')
        with self.guard:
            if path not in self.programs:
                if self.project.getProjectData().getFile(path) is None:
                    raise Failure('PROGRAM_NOT_FOUND', f'Program not found: {path}', 'select an existing program path')
                program, consumer = pyghidra.consume_program(self.project, path)
                self.programs[path] = (program, consumer, Access(), DecompilerPool(program))
            target = 'T' + self.epoch + hashlib.sha256(path.encode()).hexdigest()[:12]
            self.targets[target] = path
            return target
    def entry(self, target):
        with self.guard:
            if target not in self.targets:
                raise Failure('TARGET_UNAVAILABLE', f'Target unavailable: {target}', 'use --project ... --program ...')
            path = self.targets[target]
            return path, self.programs[path]
    def submit(self, request):
        from ghidra.util.task import TaskMonitorAdapter
        self.entry(request['target'])
        code = request.get('code', '')
        digest = hashlib.sha256(code.encode('utf-8')).hexdigest()
        if digest != request.get('sha256'):
            raise Failure('SOURCE_MISMATCH', 'The received code hash differs from the client code hash', 'resend the unchanged source')
        job = Job(request['target'], code, request.get('write', False), TaskMonitorAdapter(True))
        job.args = request.get('args', [])
        with self.guard:
            self.jobs[job.id] = job
            finished = [k for k, v in self.jobs.items() if v.finished]
            for key in finished[:-100]:
                self.jobs.pop(key)
        self.pool.submit(self.run, job)
        return job
    def run(self, job):
        path, (program, consumer, access, decompilers) = self.entry(job.target)
        token = current_job.set(job)
        filename = '<ghidra:' + job.id + '>'
        job.committed, job.phase = False, 'execute'
        try:
            with access.enter(job):
                try:
                    self.execute(job, program, filename, decompilers)
                except BaseException:
                    decompilers.clear()
                    raise
                job.state = 'success'
        except BaseException as exc:
            cancelled = isinstance(exc, Cancelled) or job.cancelled.is_set()
            job.state = 'cancelled' if cancelled else 'error'
            code = ('SAVE_ERROR' if job.phase == 'save' else 'CANCELLED' if cancelled else
                    'SYNTAX_ERROR' if isinstance(exc, SyntaxError) else 'RUNTIME_ERROR')
            detail = error_detail(exc, job=job.id, target=job.target, project=str(self.path),
                program=path, source=job.code, source_sha256=job.sha256,
                received_sha256=job.sha256, committed=job.committed, phase=job.phase,
                stdout_tail=job.tail['stdout'], stderr_tail=job.tail['stderr'])
            detail['code'] = code
            job.send({'event': 'error', 'detail': detail})
        finally:
            sys.settrace(None)
            job.finished = time.time()
            job.send({'event': 'done', 'status': job.state, 'job': job.id})
            job.code = None
            job.tail.clear()
            current_job.reset(token)
    def execute(self, job, program, filename, decompilers):
        """Commit, save or rollback while the program access lock is still held."""
        job.check()
        compiled = compile(job.code, filename, 'exec')
        if job.write:
            decompilers.clear()
        transaction = program.startTransaction('ghidra-cli ' + job.id) if job.write else None
        def trace(frame, event, arg):
            if frame.f_code.co_filename == filename:
                job.check()
                return trace
            return None
        try:
            scope = {'__name__': '__ghidra_inline__', '__file__': filename,
                     'program': program, 'gh': Helpers(program, job.monitor, job.check, decompilers, job.write),
                     'monitor': job.monitor, 'args': job.args, 'check_cancelled': job.check}
            sys.settrace(trace)
            try:
                exec(compiled, scope, scope)
                job.check()
            finally:
                sys.settrace(None)
                scope.clear()
            if transaction is not None:
                program.endTransaction(transaction, True)
                transaction = None
                job.committed = True
                job.phase = 'save'
                program.save('ghidra-cli ' + job.id, job.monitor)
        finally:
            try:
                if transaction is not None:
                    program.endTransaction(transaction, False)
            finally:
                if job.write:
                    decompilers.clear()

    def dispatch(self, request):
        command, target = request['command'], request.get('target')
        if command == 'use':
            return self.use(request['program'])
        self.entry(target)
        with self.guard:
            if command == 'jobs':
                return [j.info() for j in self.jobs.values() if j.target == target and
                        (not request.get('job') or j.id == request['job'])]
            if command == 'cancel':
                job = self.jobs.get(request['job'])
                if job is None or job.target != target:
                    raise Failure('JOB_NOT_FOUND', 'Job not found for this target', 'jobs')
                job.cancel()
                return job.info()
        raise Failure('UNKNOWN_COMMAND', command)
    def close(self):
        with self.guard:
            for job in self.jobs.values():
                job.cancel()
        self.pool.shutdown(wait=True)
        for program, consumer, access, decompilers in self.programs.values():
            decompilers.clear(close=True)
            program.release(consumer)
        self.project.close()

class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    def log_message(self, *args):
        pass
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK\n')
    def send_event(self, event):
        self.wfile.write((json.dumps(event, ensure_ascii=False) + '\n').encode())
        self.wfile.flush()
    def do_POST(self):
        job = None
        request = {}
        self.send_response(200)
        self.send_header('Content-Type', 'application/x-ndjson')
        self.end_headers()
        try:
            request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            if request['command'] != 'exec':
                self.send_event({'event': 'result', 'data': self.server.worker.dispatch(request)})
                return
            job = self.server.worker.submit(request)
            self.send_event({'event': 'job', 'job': job.id})
            while True:
                try:
                    event = job.events.get(timeout=.1)
                except queue.Empty:
                    readable, _, _ = select.select([self.connection], [], [], 0)
                    if readable and not self.connection.recv(1, socket.MSG_PEEK):
                        raise ConnectionResetError('Client disconnected')
                    continue
                self.send_event(event)
                if event['event'] == 'done':
                    break
        except (BrokenPipeError, ConnectionResetError):
            if job:
                job.disconnected.set()
                job.cancel()
        except BaseException as exc:
            self.send_event({'event': 'error', 'detail': error_detail(exc, connected=True,
                project=str(self.server.worker.path), target=request.get('target'),
                requested_program=request.get('program'), open_programs=list(self.server.worker.programs))})

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--project', required=True)
    parser.add_argument('--port', type=int, required=True)
    options = parser.parse_args()
    worker = Worker(options.project)
    server = ThreadingHTTPServer(('127.0.0.1', options.port), Handler)
    server.daemon_threads = True
    server.worker = worker
    def stop(*args):
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever(poll_interval=.1)
    finally:
        worker.close()
        server.server_close()

if __name__ == '__main__':
    main()

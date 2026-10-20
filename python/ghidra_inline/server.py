"""Small control service. Project processes own their JVMs and state."""
import argparse
import hashlib
import json
import os
import queue
import select
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from .worker import Failure, error_detail

class Service:
    def __init__(self):
        self.lock = threading.Lock()
        self.workers, self.targets = {}, {}
        self.aliases = json.loads(os.environ.get('GHIDRA_PROJECT_ALIASES', '{}'))
    def project_path(self, name):
        name = self.aliases.get(name, name)
        path = Path(name)
        if not path.suffix:
            path = path.with_suffix('.gpr')
        if not path.is_absolute():
            for root in os.environ.get('GHIDRA_PROJECT_DIRS', '/projects:/data').split(':'):
                candidate = Path(root) / path
                if candidate.exists():
                    path = candidate
                    break
        if not path.exists():
            raise Failure('NO_PROJECT_OPEN', f'Project not found: {path}', 'use --project /absolute/path/project.gpr --program /program')
        return str(path.resolve())
    def use(self, request):
        path = self.project_path(request['project'])
        with self.lock:
            worker = self.workers.get(path)
            if worker is None or worker['process'].poll() is not None:
                sock = socket.socket()
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
                sock.close()
                env = os.environ.copy()
                env.setdefault('JAVA_HOME', '/opt/java/openjdk')
                process = subprocess.Popen([sys.executable, '-m', 'ghidra_inline.worker', '--project', path, '--port', str(port)], env=env,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                worker = dict(port=port, process=process, startup=[])
                def drain(w):
                    for line in w['process'].stdout:
                        w['startup'].append(line)
                        w['startup'] = w['startup'][-80:]
                        sys.stderr.write(line)
                        sys.stderr.flush()
                threading.Thread(target=drain, args=(worker,), daemon=True).start()
                deadline = time.monotonic() + 120
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise Failure('PROJECT_OPEN_ERROR', ''.join(worker['startup']), 'check project ownership and startup diagnostics')
                    try:
                        with urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=.5) as response:
                            response.read()
                        break
                    except OSError:
                        time.sleep(.1)
                else:
                    process.terminate()
                    raise Failure('PROJECT_OPEN_TIMEOUT', ''.join(worker['startup']), 'check startup diagnostics')
                self.workers[path] = worker
            events = self.forward(worker['port'], dict(command='use', program=request['program']))
            result = None
            for event in events:
                if event['event'] == 'error':
                    return event
                if event['event'] == 'result':
                    result = event['data']
            if result is None:
                raise RuntimeError('Worker returned no target')
            self.targets[result] = worker
            return {'event': 'result', 'data': result}
    def forward(self, port, request, outer=None):
        req = urllib.request.Request(f'http://127.0.0.1:{port}/call', data=json.dumps(request).encode(), headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=None) as response:
            if outer is None:
                for line in response:
                    yield json.loads(line)
                return
            events = queue.Queue(maxsize=128)
            disconnected = threading.Event()
            def pump():
                try:
                    for line in response:
                        while not disconnected.is_set():
                            try:
                                events.put(json.loads(line), timeout=.1)
                                break
                            except queue.Full:
                                pass
                finally:
                    if not disconnected.is_set():
                        events.put(None)
            inner = response.fp.raw._sock
            threading.Thread(target=pump, daemon=True).start()
            try:
                while True:
                    try:
                        event = events.get(timeout=.1)
                    except queue.Empty:
                        readable, _, _ = select.select([outer], [], [], 0)
                        if readable and not outer.recv(1, socket.MSG_PEEK):
                            raise ConnectionResetError('Client disconnected')
                        continue
                    if event is None:
                        break
                    yield event
            finally:
                disconnected.set()
                try:
                    inner.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
    def close(self):
        for worker in self.workers.values():
            worker['process'].terminate()
        for worker in self.workers.values():
            try:
                worker['process'].wait(timeout=90)
            except subprocess.TimeoutExpired:
                worker['process'].kill()
                worker['process'].wait()

class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    def log_message(self, *args):
        pass
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK\n')
    def do_POST(self):
        request = {}
        self.send_response(200)
        self.send_header('Content-Type', 'application/x-ndjson')
        self.end_headers()
        try:
            request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            if request['command'] == 'use':
                events = [self.server.service.use(request)]
            else:
                target = request.get('target')
                if not target:
                    raise Failure('TARGET_REQUIRED', 'Every execution requires --target', 'use and specify --target')
                worker = self.server.service.targets.get(target)
                if worker is None or worker['process'].poll() is not None:
                    raise Failure('TARGET_UNAVAILABLE', f'Target unavailable: {target}', 'use to acquire a new target')
                events = self.server.service.forward(worker['port'], request, self.connection)
            try:
                for event in events:
                    self.wfile.write((json.dumps(event, ensure_ascii=False) + '\n').encode())
                    self.wfile.flush()
            finally:
                if hasattr(events, 'close'):
                    events.close()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except BaseException as exc:
            try:
                self.wfile.write((json.dumps({'event': 'error', 'detail': error_detail(exc, connected=True, project=request.get('project'),
                    requested_program=request.get('program'), target=request.get('target'))}) + '\n').encode())
            except OSError:
                pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8089)
    options = parser.parse_args()
    service = Service()
    server = ThreadingHTTPServer((options.host, options.port), Handler)
    server.daemon_threads = True
    server.service = service
    def stop(*args):
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever(poll_interval=.1)
    finally:
        service.close()
        server.server_close()

if __name__ == '__main__':
    main()

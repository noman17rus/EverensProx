import argparse
import collections
import http.server
import json
import os
import threading
import time
import urllib.parse

from backend import Invalid, Manager, NotFound, Unavailable


class RateLimiter:
    def __init__(self, limit=60, window=60, capacity=10000):
        self.limit, self.window, self.capacity = limit, window, capacity
        self.entries = collections.OrderedDict()
        self.lock = threading.Lock()

    def allow(self, key):
        now = time.monotonic()
        with self.lock:
            while self.entries and next(iter(self.entries.values()))[-1] <= now - self.window:
                self.entries.popitem(last=False)
            if key not in self.entries and len(self.entries) >= self.capacity:
                return False
            timestamps = self.entries.setdefault(key, collections.deque())
            while timestamps and timestamps[0] <= now - self.window:
                timestamps.popleft()
            if len(timestamps) >= self.limit:
                return False
            timestamps.append(now)
            self.entries.move_to_end(key)
            return True


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, address, manager):
        self.manager = manager
        self.limiter = RateLimiter()
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(address, Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass


class Handler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(120)

    def log_message(self, *args):
        pass

    def reply(self, status, body):
        raw = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Connection', 'close')
        if status == 429:
            self.send_header('Retry-After', '60')
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def do_POST(self):
        self.dispatch(True)

    def do_GET(self):
        self.dispatch(False)

    def dispatch(self, post):
        try:
            path = urllib.parse.urlsplit(self.path).path
            if not post and path == '/health':
                self.reply(200, {'ok': True})
                return
            # Only the loopback reverse proxy can supply a client address.
            address = self.headers.get('X-Real-IP', self.client_address[0])
            if not self.server.limiter.allow(address):
                self.reply(429, {'code': 'rate_limited', 'message': 'Повторите запрос через минуту.'})
                return
            if post and path == '/api/v1/provision':
                if self.headers.get('Transfer-Encoding') or self.headers.get_content_type() != 'application/json':
                    raise Invalid('Ожидается JSON.')
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 4096:
                    raise Invalid('Недопустимый размер запроса.')
                value = json.loads(self.rfile.read(length))
                if not isinstance(value, dict):
                    raise Invalid('Ожидается объект JSON.')
                self.reply(200, self.server.manager.provision(value.get('login')))
                return
            prefix = '/api/v1/subscriptions/'
            if not post and path.startswith(prefix):
                tail = path[len(prefix):].split('/')
                if len(tail) == 1 or len(tail) == 2 and tail[1] == 'metadata':
                    features = {part.strip().lower() for part in
                                self.headers.get('X-EverensProx-Features', '').split(',')
                                if part.strip()}
                    self.reply(200, self.server.manager.subscription(
                        tail[0], metadata=len(tail) == 2, features=features))
                    return
            self.reply(404, {'code': 'not_found'})
        except (Invalid, ValueError, UnicodeError):
            self.reply(400, {'code': 'invalid_request', 'message': 'Проверьте имя или email (1–254 символа).'})
        except NotFound:
            self.reply(404, {'code': 'not_found'})
        except Unavailable as error:
            self.reply(503, {'code': 'upstream_unavailable', 'message': str(error)})
        except Exception:
            self.reply(503, {'code': 'unavailable', 'message': 'Сервис временно недоступен.'})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='/etc/everensprox-provisioning/config.json')
    args = parser.parse_args()
    os.umask(0o077)
    with open(args.config, encoding='utf-8') as source:
        config = json.load(source)
    if not config['public_url'].startswith('https://'):
        raise SystemExit('public_url must use HTTPS')
    Server(('127.0.0.1', config.get('port', 19091)), Manager(config)).serve_forever()


if __name__ == '__main__':
    main()

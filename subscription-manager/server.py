#!/usr/bin/env python3
"""LAN admin UI and a separate loopback-only subscription feed."""
import argparse
import base64
import hashlib
import hmac
import http.cookies
import http.server
import ipaddress
import json
import pathlib
import secrets
import threading
import time
import urllib.parse

from backend import Manager
from formats import Invalid
from wdtt import WdttUsers

SESSION_COOKIE = 'everensprox_subscription_session'


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 310000).hex()


def prepare_html(raw):
    # HTML parsing normalizes line endings before checking inline-script hashes.
    html = raw.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
    script = html.split(b'<script>')[1].split(b'</script>')[0]
    script_hash = base64.b64encode(hashlib.sha256(script).digest()).decode()
    csp = "default-src 'none'; script-src 'sha256-" + script_hash + "'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    return html, csp


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler):
        self.slots = threading.BoundedSemaphore(24)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            request.settimeout(15)
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass  # Never print requests, URL secrets, or exception text.


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'EverensProx'
    sys_version = ''

    def log_message(self, *args):
        pass

    def reply(self, code, body, content_type='application/json; charset=utf-8', cookie=None):
        if isinstance(body, dict):
            body = json.dumps(body, ensure_ascii=False).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', self.server.csp if hasattr(self.server, 'csp') else "default-src 'none'")
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        if self.headers.get('Transfer-Encoding') or self.headers.get_content_type() != 'application/json':
            raise Invalid('Ожидается JSON.')
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 16384:
                raise ValueError()
            value = json.loads(self.rfile.read(length))
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except ValueError as exc:
            raise Invalid('Некорректный запрос.') from exc


class Feed(Handler):
    def do_GET(self):
        if not ipaddress.ip_address(self.client_address[0]).is_loopback:
            return self.reply(403, {})
        manager = self.server.manager
        if self.path == '/subscription':
            self.reply(200, manager.active['body'], 'text/plain; charset=utf-8')
        elif self.path == '/health':
            self.reply(200, {'cached': True, 'recovery': manager.recovery_needed})
        elif self.path.startswith('/candidate/'):
            body = manager.staged.get(self.path[len('/candidate/'):])
            self.reply(200 if body else 404, body or b'', 'text/plain; charset=utf-8')
        else:
            self.reply(404, {})


class Admin(Handler):
    def allowed(self):
        config = self.server.manager.config
        address = ipaddress.ip_address(self.client_address[0])
        if address not in ipaddress.ip_network(config['lan_subnet']):
            return False
        return self.headers.get('Host') == config['admin_host']

    def session(self):
        try:
            # Cookies are shared across ports. Ignore unrelated panels' cookies,
            # including malformed values that would invalidate SimpleCookie's jar.
            parts = [part.strip() for part in self.headers.get('Cookie', '').split(';')
                     if part.strip().partition('=')[0] == SESSION_COOKIE]
            if len(parts) != 1:
                return None
            cookie = http.cookies.SimpleCookie(parts[0])
            token = cookie[SESSION_COOKIE].value
        except (KeyError, http.cookies.CookieError):
            return None
        with self.server.auth_lock:
            entry = self.server.sessions.get(token)
            if entry and entry['expires'] > time.time():
                return entry
            self.server.sessions.pop(token, None)
        return None

    def do_GET(self):
        if not self.allowed():
            return self.reply(403, {'error': 'Доступ только по локальному адресу из домашней сети.'})
        if urllib.parse.urlsplit(self.path).path == '/':
            return self.reply(200, self.server.html, 'text/html; charset=utf-8')
        session = self.session()
        if not session:
            return self.reply(401, {'error': 'Войдите в панель.'})
        if self.path == '/api/status':
            result = self.server.manager.state()
            result['csrf'] = session['csrf']
            return self.reply(200, result)
        if self.path == '/api/wdtt/users':
            try:
                return self.reply(200, self.server.wdtt.listing())
            except Invalid as exc:
                return self.reply(400, {'error': str(exc)})
        self.reply(404, {})

    def do_POST(self):
        config = self.server.manager.config
        if not self.allowed() or self.headers.get('Origin') != 'http://' + config['admin_host']:
            return self.reply(403, {'error': 'Недопустимый источник запроса.'})
        try:
            args = self.read_json()
            if self.path == '/api/login':
                return self.login(args)
            session = self.session()
            if not session:
                return self.reply(401, {'error': 'Войдите в панель.'})
            if not hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), session['csrf']):
                return self.reply(403, {'error': 'Обновите страницу и повторите запрос.'})
            if self.path == '/api/logout':
                with self.server.auth_lock:
                    self.server.sessions = {k: v for k, v in self.server.sessions.items() if v is not session}
                return self.reply(200, {}, cookie=SESSION_COOKIE + '=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0')
            if self.path == '/api/wdtt/user':
                return self.reply(200, self.server.wdtt.execute(args))
            if self.path not in ('/api/check', '/api/apply', '/api/rollback', '/api/ping', '/api/select', '/api/settings', '/api/refresh-free', '/api/save-source', '/api/delete-source'):
                return self.reply(404, {})
            if self.path == '/api/settings' and type(args.get('enabled')) is not bool:
                raise Invalid('Укажите, включён ли бесплатный резерв.')
            if self.path in ('/api/ping', '/api/select'):
                if 'source' in args and (not isinstance(args['source'], str) or args['source'] not in self.server.manager.source_ids()):
                    raise Invalid('Неизвестный источник подписки.')
                node_id = args.get('id')
                if node_id is not None and (not isinstance(node_id, str) or len(node_id) != 64 or any(c not in '0123456789abcdef' for c in node_id)):
                    raise Invalid('Некорректный идентификатор узла.')
                if self.path == '/api/select' and 'id' not in args:
                    raise Invalid('Укажите узел или автоматический режим.')
            if self.path == '/api/check':
                if not isinstance(args.get('url'), str) or not 1 <= len(args['url']) <= 8192:
                    raise Invalid('Вставьте ссылку на подписку.')
                if args.get('profile') is not None and type(args['profile']) is not int:
                    raise Invalid('Некорректный номер профиля.')
            if self.path == '/api/apply' and not isinstance(args.get('id'), str):
                raise Invalid('Повторите проверку подписки.')
            if self.path in ('/api/refresh-free', '/api/delete-source', '/api/save-source'):
                source = args.get('source')
                if source is not None and (not isinstance(source, str) or source not in self.server.manager.catalog()):
                    raise Invalid('Неизвестный бесплатный источник.')
                if self.path == '/api/delete-source' and source is None:
                    raise Invalid('Укажите источник.')
            self.server.manager.submit(self.path.rsplit('/', 1)[1], args)
            self.reply(202, {'accepted': True})
        except Invalid as exc:
            self.reply(400, {'error': str(exc)})

    def login(self, args):
        address = self.client_address[0]
        with self.server.auth_lock:
            until, count = self.server.failures.get(address, (0, 0))
            if until > time.time() and count >= 5:
                return self.reply(429, {'error': 'Слишком много попыток. Подождите 5 минут.'})
            if until <= time.time():
                count = 0
            password = args.get('password', '')
            config = self.server.manager.config
            valid = isinstance(password, str) and hmac.compare_digest(password_hash(password, config['password_salt']), config['password_hash'])
            if not valid:
                self.server.failures[address] = (time.time() + 300, count + 1)
                return self.reply(401, {'error': 'Неверный пароль.'})
            self.server.failures.pop(address, None)
            now = time.time()
            self.server.sessions = {k: v for k, v in self.server.sessions.items() if v['expires'] > now}
            if len(self.server.sessions) >= 32:
                self.server.sessions.pop(next(iter(self.server.sessions)))
            token = secrets.token_urlsafe(32)
            self.server.sessions[token] = {'expires': now + 8 * 3600, 'csrf': secrets.token_urlsafe(32)}
        self.reply(200, {}, cookie=SESSION_COOKIE + '=' + token + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='/etc/everensprox-subscription/config.json')
    args = parser.parse_args()
    config = json.loads(pathlib.Path(args.config).read_text())
    address, port = config['admin_host'].rsplit(':', 1)
    ip = ipaddress.ip_address(address)
    if not ip.is_private or ip.is_unspecified or ip not in ipaddress.ip_network(config['lan_subnet']):
        raise SystemExit('Configure an exact private LAN address and subnet')
    manager = Manager(config)
    feed_url = urllib.parse.urlsplit(config['feed_url'])
    if feed_url.hostname != '127.0.0.1' or feed_url.path != '/subscription':
        raise SystemExit('Feed must use loopback /subscription')
    feed = Server(('127.0.0.1', feed_url.port), Feed)
    feed.manager = manager
    admin = Server((address, int(port)), Admin)
    admin.manager = manager
    admin.wdtt = WdttUsers(config)
    admin.sessions, admin.failures = {}, {}
    admin.auth_lock = threading.Lock()
    admin.html, admin.csp = prepare_html(pathlib.Path(__file__).with_name('index.html').read_bytes())
    threading.Thread(target=feed.serve_forever, daemon=True).start()
    threading.Thread(target=manager.maintenance, daemon=True).start()
    admin.serve_forever()


if __name__ == '__main__':
    main()

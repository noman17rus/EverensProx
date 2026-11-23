import copy
import contextlib
import ipaddress
import json
import pathlib
import secrets
import socket
import sqlite3
import threading
import time
import unicodedata
import urllib.parse
import urllib.request
import uuid


class Invalid(Exception):
    pass


class Unavailable(Exception):
    pass


class NotFound(Exception):
    pass


WDTT_PASSWORD_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789'


def new_wdtt_password():
    return ''.join(secrets.choice(WDTT_PASSWORD_CHARS) for _ in range(16))


def normalize_login(value):
    if not isinstance(value, str):
        raise Invalid('Введите имя или email.')
    display = value.strip()
    if not display or len(display) > 254 or any(unicodedata.category(c).startswith('C') for c in display):
        raise Invalid('Логин должен содержать от 1 до 254 символов без управляющих символов.')
    return display.lower(), display


def object_value(value):
    return json.loads(value) if isinstance(value, str) else value


class Panel:
    def __init__(self, config):
        self.config = config

    def call(self, path, data=None, json_body=False):
        auth = json.loads(pathlib.Path(self.config['panel_auth_file']).read_text())
        raw = None if data is None else (json.dumps(data).encode() if json_body else urllib.parse.urlencode(data).encode())
        request = urllib.request.Request(
            self.config['panel_url'].rstrip('/') + '/panel/api/' + path,
            data=raw, headers={'Authorization': 'Bearer ' + auth['token'],
                               'Content-Type': 'application/json' if json_body else 'application/x-www-form-urlencoded'})
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=30) as response:
                result = json.load(response)
            if result.get('success') is not True:
                raise Unavailable('3x-ui отклонила запрос.')
            return result.get('obj')
        except Unavailable:
            raise
        except Exception:
            raise Unavailable('API 3x-ui недоступен.') from None

    def inbounds(self):
        return self.call('inbounds/list')

    def add(self, inbound, client, existing=False):
        if self.config.get('client_api', 'universal') == 'universal':
            if existing:
                email = urllib.parse.quote(client['email'], safe='')
                self.call('clients/' + email + '/attach', {'inboundIds': [inbound['id']]}, json_body=True)
            else:
                payload = dict(client)
                payload['tgId'] = int(payload.get('tgId') or 0)
                payload.setdefault('limitHwid', 0)
                self.call('clients/add', {'client': payload, 'inboundIds': [inbound['id']]}, json_body=True)
        elif self.config['client_api'] == 'legacy':
            self.call('inbounds/addClient', {'id': inbound['id'], 'settings': json.dumps({'clients': [client]})})
        else:
            raise Unavailable('Неизвестная версия API клиентов 3x-ui.')


class Wdtt:
    def __init__(self, config):
        self.config = config

    def call(self, args):
        password = pathlib.Path(self.config['wdtt_password_file']).read_text().strip()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(90)
                connection.connect(self.config.get('wdtt_socket', '/run/wdtt/admin.sock'))
                connection.sendall(json.dumps({'main_password': password, 'args': args}).encode() + b'\n')
                with connection.makefile('rb') as stream:
                    raw = stream.readline(8 * 1024 * 1024 + 1)
                if len(raw) > 8 * 1024 * 1024:
                    raise Unavailable('Ответ WDTT слишком большой.')
                result = json.loads(raw)
            if result.get('ok') is not True:
                raise Unavailable('WDTT отклонил запрос.')
            return result
        except Unavailable:
            raise
        except Exception:
            raise Unavailable('Административный интерфейс WDTT недоступен.') from None

    def listing(self):
        return self.call(['list'])

    def create(self, password, label):
        return self.call(['create', '--days', '0', '--shared', '--label', label,
                          '--client-password', password,
                          '--vk-hash', self.config['wdtt_hashes']])['password']


def client_node(inbound, client, host, port=None, reality_mlkem=False):
    stream = object_value(inbound.get('streamSettings') or {})
    network = stream.get('network', 'tcp')
    security = stream.get('security', 'none')
    if network not in ('tcp', 'raw', 'ws', 'grpc', 'xhttp') or security not in ('none', 'tls', 'reality'):
        raise Unavailable('Неподдерживаемый транспорт VLESS: проверьте выбранные инбаунды.')
    node = {'name': 'VLESS ' + str(inbound['id']), 'type': 'vless', 'server': host,
            'port': port if port is not None else inbound['port'], 'uuid': client['id'], 'udp': True,
            'network': 'tcp' if network == 'raw' else network}
    if client.get('flow'):
        node['flow'] = client['flow']
    if security != 'none':
        node['tls'] = True
        options = stream.get(security + 'Settings', {})
        settings = options.get('settings', {})
        names = options.get('serverNames') or []
        name = settings.get('serverName') or options.get('serverName') or (names[0] if names else host)
        node['servername'] = name
        node['client-fingerprint'] = settings.get('fingerprint') or 'chrome'
        if security == 'reality':
            public_key = settings.get('publicKey') or options.get('publicKey')
            if not public_key:
                raise Unavailable('Для Reality отсутствует публичный ключ.')
            short_ids = options.get('shortIds') or ['']
            node['reality-opts'] = {'public-key': public_key, 'short-id': short_ids[0]}
            if reality_mlkem:
                node['reality-opts']['support-x25519mlkem768'] = True
        elif options.get('alpn'):
            node['alpn'] = options['alpn']
    transport = stream.get(network + 'Settings', {})
    if network in ('tcp', 'raw') and transport.get('header', {}).get('type', 'none') != 'none':
        raise Unavailable('TCP HTTP-маскировка не поддерживается этой подпиской.')
    if network == 'ws':
        node['ws-opts'] = {'path': transport.get('path', '/'), 'headers': transport.get('headers', {})}
    elif network == 'grpc':
        node['grpc-opts'] = {'grpc-service-name': transport.get('serviceName', '')}
        if transport.get('authority'):
            node['grpc-opts']['grpc-authority'] = transport['authority']
    elif network == 'xhttp':
        node['xhttp-opts'] = {'path': transport.get('path', '/'), 'host': transport.get('host', ''),
                              'mode': transport.get('mode', 'auto')}
        extra = dict(transport.get('extra') or {})
        extra.update({key: value for key, value in transport.items()
                      if key not in ('path', 'host', 'mode', 'extra')})
        mapping = {'headers': 'headers', 'noGRPCHeader': 'no-grpc-header',
                   'xPaddingBytes': 'x-padding-bytes', 'xPaddingObfsMode': 'x-padding-obfs-mode',
                   'xPaddingKey': 'x-padding-key', 'xPaddingHeader': 'x-padding-header',
                   'xPaddingPlacement': 'x-padding-placement', 'xPaddingMethod': 'x-padding-method',
                   'uplinkHTTPMethod': 'uplink-http-method', 'sessionPlacement': 'session-placement',
                   'sessionKey': 'session-key', 'sessionTable': 'session-table',
                   'sessionLength': 'session-length', 'seqPlacement': 'seq-placement', 'seqKey': 'seq-key',
                   'uplinkDataPlacement': 'uplink-data-placement', 'uplinkDataKey': 'uplink-data-key',
                   'uplinkChunkSize': 'uplink-chunk-size', 'scMaxEachPostBytes': 'sc-max-each-post-bytes',
                   'scMinPostsIntervalMs': 'sc-min-posts-interval-ms'}
        for key, value in extra.items():
            if key not in mapping:
                raise Unavailable('Неподдерживаемый параметр XHTTP; требуется настройка адаптера.')
            target = mapping[key]
            if key not in ('headers', 'noGRPCHeader', 'xPaddingObfsMode'):
                value = str(value)
            node['xhttp-opts'][target] = value
    return node


class Manager:
    def __init__(self, config, panel=None, wdtt=None):
        self.config = config
        self.panel = panel or Panel(config)
        self.wdtt = wdtt or Wdtt(config)
        self.lock = threading.Lock()
        self.path = config['database']
        pathlib.Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY, login TEXT NOT NULL UNIQUE, display TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE, uuid TEXT NOT NULL, sub_id TEXT NOT NULL,
                wdtt_password TEXT NOT NULL, wdtt_link TEXT NOT NULL DEFAULT '')''')

    @contextlib.contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=120)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def eligible(self, inbounds):
        configured = self.config.get('inbound_ids', [])
        selected = []
        for inbound in inbounds:
            if inbound.get('protocol') != 'vless' or not inbound.get('enable', True):
                continue
            if configured and inbound['id'] not in configured:
                continue
            listen = inbound.get('listen', '')
            try:
                local = bool(listen) and ipaddress.ip_address(listen).is_loopback
            except ValueError:
                local = listen == 'localhost'
            if not configured and local:
                continue
            selected.append(inbound)
        if not selected:
            raise Unavailable('Нет доступных клиентских VLESS-инбаундов.')
        return selected

    def provision(self, value):
        login, display = normalize_login(value)
        with self.lock, self.connect() as db:
            row = db.execute('SELECT * FROM accounts WHERE login=?', (login,)).fetchone()
            if row is None:
                inbounds = self.eligible(self.panel.inbounds())
                matches = [client for inbound in inbounds
                           for client in object_value(inbound['settings']).get('clients', [])
                           if str(client.get('email', '')).strip().lower() == login]
                identities = {(c['id'], c.get('subId', '')) for c in matches}
                if len(identities) > 1:
                    raise Unavailable('В 3x-ui несколько разных подписок с этим логином; требуется проверка владельцем сервера.')
                if matches and (not matches[0].get('enable', True) or not matches[0].get('subId')):
                    raise Unavailable('Существующая подписка отключена или не имеет subId.')
                account_id = uuid.uuid4().hex
                db.execute('INSERT INTO accounts (id,login,display,token,uuid,sub_id,wdtt_password) VALUES (?,?,?,?,?,?,?)',
                           (account_id, login, display, secrets.token_urlsafe(32),
                            matches[0]['id'] if matches else str(uuid.uuid4()),
                            matches[0]['subId'] if matches else secrets.token_hex(12),
                            new_wdtt_password()))
                db.commit()
                row = db.execute('SELECT * FROM accounts WHERE id=?', (account_id,)).fetchone()
            if not row['wdtt_link'] and (len(row['wdtt_password']) != 16 or
                    any(c not in WDTT_PASSWORD_CHARS for c in row['wdtt_password'])):
                db.execute('UPDATE accounts SET wdtt_password=? WHERE id=?', (new_wdtt_password(), row['id']))
                db.commit()
                row = db.execute('SELECT * FROM accounts WHERE id=?', (row['id'],)).fetchone()
            self.reconcile(db, row)
            return self.result(db.execute('SELECT * FROM accounts WHERE id=?', (row['id'],)).fetchone())

    def reconcile(self, db, row):
        inbounds = self.eligible(self.panel.inbounds())
        template = None
        for inbound in inbounds:
            for client in object_value(inbound['settings']).get('clients', []):
                if str(client.get('email', '')).strip().lower() == row['login']:
                    if client['id'] != row['uuid'] or client.get('subId') != row['sub_id']:
                        raise Unavailable('Существующая подписка изменилась; требуется проверка владельцем сервера.')
                    if not client.get('enable', True) or (client.get('expiryTime', 0) > 0 and client['expiryTime'] < time.time() * 1000):
                        raise Unavailable('Существующий доступ отключён или истёк.')
                    template = client
        nodes = []
        missing = []
        for inbound in inbounds:
            clients = object_value(inbound['settings']).get('clients', [])
            client = next((c for c in clients if str(c.get('email', '')).strip().lower() == row['login']), None)
            if client is None:
                client = copy.deepcopy(template) if template else {
                    'id': row['uuid'], 'email': row['display'], 'subId': row['sub_id'],
                    'enable': True, 'limitIp': 0, 'totalGB': 0, 'expiryTime': 0, 'tgId': '', 'reset': 0}
                stream = object_value(inbound.get('streamSettings') or {})
                client['flow'] = 'xtls-rprx-vision' if stream.get('security') == 'reality' and stream.get('network', 'tcp') in ('tcp', 'raw') else ''
                missing.append((inbound, client))
            host = self.config.get('inbound_hosts', {}).get(str(inbound['id']), self.config['public_host'])
            port = self.config.get('inbound_ports', {}).get(str(inbound['id']))
            if port is not None and (type(port) is not int or not 1 <= port <= 65535):
                raise Unavailable('Некорректный публичный порт VLESS.')
            reality_mlkem = inbound['id'] in self.config.get('reality_mlkem_inbound_ids', [])
            nodes.append(client_node(inbound, client, host, port, reality_mlkem=reality_mlkem))
        for inbound, client in missing:
            self.panel.add(inbound, client, existing=template is not None)
        listing = self.wdtt.listing()
        passwords = listing.get('passwords', [])
        entry = next((p for p in passwords if p['password'] == row['wdtt_password']), None)
        if entry is None and not row['wdtt_link']:
            entry = next((p for p in passwords if p.get('shared') and p.get('status') == 'active'
                          and str(p.get('label', '')).strip().lower() == row['login']), None)
            if entry:
                db.execute('UPDATE accounts SET wdtt_password=? WHERE id=?', (entry['password'], row['id']))
                db.commit()
        if entry is None:
            entry = self.wdtt.create(row['wdtt_password'], row['display'])
        if not entry.get('shared') or entry.get('status') != 'active':
            raise Unavailable('Связанный общий доступ WDTT отключён или несовместим.')
        ports = entry['ports'].split(',')
        hashes = entry.get('vk_hash') or self.config['wdtt_hashes']
        if len(ports) != 3 or not hashes:
            raise Unavailable('Проверьте порты и VK-хеши WDTT.')
        link = 'wdtt://connect?' + urllib.parse.urlencode({
            'v': '1', 'host': self.config.get('wdtt_host', self.config['public_host']),
            'dtls': ports[0], 'wg': ports[1], 'local': ports[2], 'password': entry['password'],
            'hashes': hashes, 'name': row['display']})
        db.execute('UPDATE accounts SET wdtt_link=? WHERE id=?', (link, row['id']))
        db.commit()
        return {'proxies': nodes, 'proxy-groups': [
            {'name': 'VLESS', 'type': 'fallback', 'proxies': [n['name'] for n in nodes],
             'url': 'https://www.gstatic.com/generate_204', 'interval': 300}], 'rules': ['MATCH,VLESS']}

    def result(self, row):
        return {'account_id': row['id'], 'login': row['login'],
                'subscription_url': self.config['public_url'].rstrip('/') + '/api/v1/subscriptions/' + row['token'],
                'wdtt_link': row['wdtt_link']}

    def subscription(self, token, metadata=False):
        with self.lock, self.connect() as db:
            row = db.execute('SELECT * FROM accounts WHERE token=?', (token,)).fetchone()
            if row is None:
                raise NotFound('Unknown subscription')
            config = self.reconcile(db, row)
            if metadata:
                return self.result(db.execute('SELECT * FROM accounts WHERE id=?', (row['id'],)).fetchone())
            return config

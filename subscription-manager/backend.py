"""Panel API integration, isolated probes and durable subscription transactions."""
import base64
import concurrent.futures
import contextlib
import copy
import hashlib
import ipaddress
import json
import os
import pathlib
import secrets
import select
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request

from formats import Invalid, LIMIT, import_body, free_batches

FREE_URL = 'https://parsabrg.github.io/free_sub/sub.txt'
FREE_INTERVAL = 12 * 3600
DEFAULT_FEEDS = [
    ('free', 'Parsabrg/free_sub', FREE_URL),
    ('free-mehrtat', 'VLESS Collector', 'https://raw.githubusercontent.com/mehrtat/vless-collector/main/sub.txt'),
    ('free-alirewa', 'Alirewa', 'https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/sub1.txt'),
    ('free-igareck', 'igareck / РФ', 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt'),
    ('free-radar', 'Nodes Radar', 'https://radarhub.top/v2ray.txt'),
]


class NoWorkingNodes(Invalid):
    """A completed network check, distinct from API/configuration failures."""


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def atomic(path, value):
    path = pathlib.Path(path)
    tmp = path.with_suffix('.new')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(value, f, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    if os.name != 'nt':
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def fetch(url):
    # The URL is an administrator-supplied subscription source, never a browser fetch.
    def validate(value):
        p = urllib.parse.urlsplit(value)
        if p.scheme != 'https' or not p.hostname or p.username or p.password or p.fragment:
            raise Invalid('Нужна HTTPS-ссылка на подписку без логина в адресе.')
        for entry in socket.getaddrinfo(p.hostname, p.port or 443, type=socket.SOCK_STREAM):
            if not ipaddress.ip_address(entry[4][0]).is_global:
                raise Invalid('Источник подписки должен иметь публичный адрес.')
    class Redirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            validate(newurl)
            return super().redirect_request(req, fp, code, msg, headers, newurl)
    validate(url)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirect())
    req = urllib.request.Request(url, headers={'User-Agent': 'Happ/2.0.0'})
    try:
        with opener.open(req, timeout=20) as r:
            raw = r.read(LIMIT + 1)
    except Exception as exc:
        raise Invalid('Не удалось загрузить подписку. Проверьте ссылку и доступность провайдера.') from exc
    if len(raw) > LIMIT:
        raise Invalid('Подписка превышает 2 МиБ.')
    return raw


class Panel:
    def __init__(self, config):
        self.config = config

    def call(self, path, data=None, method=None):
        auth = json.loads(pathlib.Path(self.config['panel_auth_file']).read_text())
        headers = {'Authorization': 'Bearer ' + auth['token'], 'Content-Type': 'application/x-www-form-urlencoded'}
        raw = None if data is None else urllib.parse.urlencode({k: str(v).lower() if isinstance(v, bool) else v for k, v in data.items()}).encode()
        req = urllib.request.Request(self.config['panel_url'].rstrip('/') + '/panel/api/' + path,
                                     data=raw, headers=headers, method=method)
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=60) as r:
                result = json.load(r)
            if result.get('success') is not True:
                raise Invalid('3x-ui отклонила запрос. Проверьте API и права токена.')
            return result.get('obj')
        except Invalid:
            raise
        except Exception as exc:
            raise Invalid('API 3x-ui недоступен. Рабочий кэш сохранён.') from exc

    def snapshot(self):
        xray = self.call('xray/', {}, 'POST')
        if isinstance(xray, str):
            xray = json.loads(xray)
        template = xray['xraySetting']
        if isinstance(template, str):
            template = json.loads(template)
        subs = self.call('xray/outbound-subs')
        # Ignore scheduling metadata, but include fetched nodes and all editable fields.
        volatile = {'lastUpdated', 'lastError', 'createdAt', 'updatedAt', 'outboundCount'}
        stable = [{k: v for k, v in s.items() if k not in volatile} for s in subs]
        inbounds = self.call('inbounds/list')
        inbound_fields = ('id', 'enable', 'listen', 'port', 'protocol', 'settings', 'streamSettings', 'sniffing', 'allocate')
        clients = [{k: i.get(k) for k in inbound_fields} for i in inbounds]
        return {'template': template, 'subs': stable, 'clients': clients}

    def preflight(self):
        snapshot = self.snapshot()
        sub = next((s for s in snapshot['subs'] if s['id'] == self.config['subscription_id']), None)
        expected = self.config['feed_url']
        if not sub or not sub['enabled'] or sub['url'] != expected or sub['tagPrefix'] != self.config['tag_prefix']:
            raise Invalid('Исходящая подписка 3x-ui не соответствует настройкам адаптера.')
        balancer = next((b for b in snapshot['template']['routing'].get('balancers', []) if b['tag'] == 'foreign-auto'), {})
        if balancer.get('selector') != [self.config['tag_prefix']] or balancer.get('fallbackTag') != 'block':
            raise Invalid('Неожиданная конфигурация foreign-auto; требуется проверка администратора.')
        live = json.loads(pathlib.Path(self.config['runtime']).read_text())
        tags = {i['tag'] for i in live['inbounds']}
        if 'wdtt-in' not in tags or not any(i['protocol'] == 'vless' for i in live['inbounds']):
            raise Invalid('Не найдены ожидаемые входы VLESS и WDTT.')
        if not any(r.get('balancerTag') == 'foreign-auto' and not r.get('inboundTag') for r in live['routing']['rules']):
            raise Invalid('Не подтверждён общий внешний маршрут VLESS и WDTT.')
        return snapshot

    def parse(self, feed):
        nodes = self.call('xray/outbound-subs/parse', {'url': feed, 'userAgent': 'EverensProx', 'allowPrivate': True, 'allowInsecure': False}, 'POST')
        if not isinstance(nodes, list) or not nodes or any(n.get('protocol') != 'vless' for n in nodes):
            raise Invalid('3x-ui не смогла импортировать узлы VLESS.')
        return nodes

    def refresh(self):
        self.call('xray/outbound-subs/' + str(self.config['subscription_id']) + '/refresh', {}, 'POST')

    def balancer(self):
        result = self.call('xray/balancerStatus', {'tags': 'foreign-auto'}, 'POST')
        status = result.get('foreign-auto', {}) if isinstance(result, dict) else {}
        if not status.get('running'):
            raise Invalid('Балансировщик Xray пока недоступен. Выбор сохранён и будет восстановлен.')
        return status

    def override(self, tag):
        self.call('xray/balancerOverride', {'tag': 'foreign-auto', 'target': tag or ''}, 'POST')


def node_signature(nodes):
    return sorted(digest({k: v for k, v in n.items() if k != 'tag'}) for n in nodes)


def runtime_guard(runtime):
    live = copy.deepcopy(runtime)
    for i in live['inbounds']:
        if i['protocol'] == 'socks':
            for account in i.get('settings', {}).get('accounts', []):
                account['pass'] = '<ephemeral>'
    return digest({k: live.get(k) for k in ('inbounds', 'routing', 'dns', 'observatory', 'policy')})


@contextlib.contextmanager
def proxy_header_relay(target_port):
    """Temporary loopback relay for an ingress behind a PROXY-protocol frontend."""
    stopped = threading.Event()
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                with socket.create_connection(('127.0.0.1', target_port), timeout=3) as upstream:
                    upstream.sendall(('PROXY TCP4 127.0.0.1 127.0.0.1 '
                                      + str(self.client_address[1]) + ' ' + str(target_port) + '\r\n').encode())
                    self.request.settimeout(3)
                    while not stopped.is_set():
                        readable, _, _ = select.select([self.request, upstream], [], [], .2)
                        for source in readable:
                            data = source.recv(65536)
                            if not data:
                                return
                            (upstream if source is self.request else self.request).sendall(data)
            except OSError:
                pass
    class Relay(socketserver.ThreadingTCPServer):
        daemon_threads = True
        def handle_error(self, *args):
            pass
    relay = Relay(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=lambda: relay.serve_forever(poll_interval=.1), daemon=True)
    thread.start()
    try:
        yield relay.server_address[1]
    finally:
        stopped.set()
        relay.shutdown()
        relay.server_close()
        thread.join()


class Probe:
    def __init__(self, config):
        self.config = config
        self.slots = threading.BoundedSemaphore(4)

    def validate(self, nodes):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / 'config.json'
            atomic(path, {'log': {'loglevel': 'none'}, 'inbounds': [], 'outbounds': nodes})
            try:
                p = subprocess.run([self.config['xray'], 'run', '-test', '-c', str(path)], cwd=self.config['xray_cwd'], capture_output=True, timeout=20)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise Invalid('Не удалось запустить проверку Xray.') from exc
            if p.returncode:
                raise Invalid('Установленный Xray не поддерживает параметры подписки.')

    def curl_latency(self, port, account=None):
        auth = '' if account is None else 'proxy-user = ' + json.dumps(account['user'] + ':' + account['pass']) + '\n'
        for url in self.config['test_urls']:
            try:
                p = subprocess.run(['curl', '-q', '--config', '-', '--noproxy', '', '--socks5-hostname', '127.0.0.1:' + str(port), '--connect-timeout', '5', '--max-time', '10', '-sS', '-o', os.devnull, '-w', '%{http_code} %{time_starttransfer}', url], input=auth, capture_output=True, text=True, timeout=12)
                # 401/403 still prove an HTTPS response through the tunnel; 5xx do not.
                parts = p.stdout.split()
                if p.returncode == 0 and len(parts) == 2 and 200 <= int(parts[0]) < 500:
                    return max(1, round(float(parts[1]) * 1000))
            except (OSError, ValueError, subprocess.TimeoutExpired):
                pass
        return None

    def curl(self, port, account=None):
        return self.curl_latency(port, account) is not None

    def one(self, node, timed=False):
        with self.slots:
            return self._one(node, timed)

    def _one(self, node, timed=False):
        with self.tunnel(node) as port:
            if port is None:
                return None if timed else False
            return self.curl_latency(port) if timed else self.curl(port)

    @contextlib.contextmanager
    def tunnel(self, node):
        """An isolated loopback proxy; never changes the production router."""
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / 'probe.json'
            atomic(path, {'log': {'loglevel': 'none'}, 'inbounds': [{'listen': '127.0.0.1', 'port': port, 'protocol': 'socks', 'settings': {'auth': 'noauth'}}], 'outbounds': [node]})
            proc = subprocess.Popen([self.config['xray'], 'run', '-c', str(path)], cwd=self.config['xray_cwd'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(50):
                    if proc.poll() is not None:
                        yield None
                        return
                    try:
                        with socket.create_connection(('127.0.0.1', port), .2):
                            break
                    except OSError:
                        time.sleep(.1)
                else:
                    yield None
                    return
                yield port
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

    def latency(self, node):
        return self.one(node, timed=True)

    @staticmethod
    def reality_public_key(private_key):
        # PKCS#8 X25519 input over stdin; never expose the private key in argv.
        try:
            raw = base64.urlsafe_b64decode(private_key + '=' * (-len(private_key) % 4))
            if len(raw) != 32:
                raise ValueError()
            result = subprocess.run(['openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'],
                input=bytes.fromhex('302e020100300506032b656e04220420') + raw,
                capture_output=True, timeout=5)
            prefix = bytes.fromhex('302a300506032b656e032100')
            if result.returncode or len(result.stdout) != len(prefix) + 32 or not result.stdout.startswith(prefix):
                raise ValueError()
            return base64.urlsafe_b64encode(result.stdout[len(prefix):]).decode().rstrip('=')
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            raise Invalid('Не удалось подготовить локальную проверку Reality. Проверьте наличие OpenSSL.') from exc

    def routed(self, runtime):
        socks = next((i for i in runtime['inbounds'] if i['protocol'] == 'socks'
                      and i.get('listen') == '127.0.0.1' and i.get('tag') != 'warp-probe-in'), None)
        if socks:
            return self.curl(socks['port'], next(iter(socks.get('settings', {}).get('accounts', [])), None))
        # Some home installations have no SOCKS inbound. Exercise their existing
        # loopback VLESS ingress instead, including its real foreign-auto route.
        inbound = next((i for i in runtime['inbounds'] if i['protocol'] == 'vless'
                        and i.get('listen') == '127.0.0.1'
                        and i.get('streamSettings', {}).get('security', 'none') in ('none', 'reality')
                        and i.get('settings', {}).get('clients')), None)
        if not inbound:
            raise Invalid('Не найден локальный вход для проверки общего внешнего маршрута.')
        user = inbound['settings']['clients'][0]
        stream = inbound.get('streamSettings', {})
        outbound = {'tag': 'home-route-probe', 'protocol': 'vless', 'settings': {'vnext': [{
            'address': '127.0.0.1', 'port': inbound['port'],
            'users': [{'id': user['id'], 'encryption': 'none', 'flow': user.get('flow', '')}],
        }]}, 'streamSettings': {'network': stream.get('network', 'tcp'), 'security': 'none'}}
        for key in ('tcpSettings', 'wsSettings', 'grpcSettings', 'xhttpSettings'):
            if key in stream:
                outbound['streamSettings'][key] = copy.deepcopy(stream[key])
        outbound['streamSettings'].get('tcpSettings', {}).pop('acceptProxyProtocol', None)
        if stream.get('security') == 'reality':
            reality = stream.get('realitySettings', {})
            if not reality.get('serverNames') or not reality.get('privateKey'):
                raise Invalid('Недостаточно параметров локального входа Reality для проверки.')
            outbound['streamSettings'].update(security='reality', realitySettings={
                'serverName': reality['serverNames'][0], 'fingerprint': 'chrome',
                'shortId': next(iter(reality.get('shortIds', [])), ''),
                'publicKey': self.reality_public_key(reality['privateKey']),
            })
        if stream.get('tcpSettings', {}).get('acceptProxyProtocol') or stream.get('sockopt', {}).get('acceptProxyProtocol'):
            with proxy_header_relay(inbound['port']) as port:
                outbound['settings']['vnext'][0]['port'] = port
                return self.one(outbound)
        return self.one(outbound)

    def candidates(self, nodes):
        self.validate(nodes)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            good = list(pool.map(self.one, nodes))
        count = sum(good)
        if not count:
            raise NoWorkingNodes('Ни один узел не прошёл проверку HTTPS. Рабочие настройки сохранены.')
        return count

    def wait(self, record, guard):
        for _ in range(45):
            runtime = json.loads(pathlib.Path(self.config['runtime']).read_text())
            nodes = [o for o in runtime['outbounds'] if o.get('tag', '').startswith(self.config['tag_prefix'])]
            if node_signature(nodes) == node_signature(record['nodes']):
                if runtime_guard(runtime) != guard:
                    raise Invalid('Изменились входы или маршрутизация 3x-ui.')
                return runtime
            time.sleep(2)
        raise Invalid('3x-ui не подтвердила загрузку сохранённых узлов.')

    def live(self, record, guard):
        runtime = self.wait(record, guard)
        for _ in range(6):
            if self.routed(runtime):
                return
            time.sleep(3)
        raise Invalid('После применения внешний маршрут не прошёл проверку.')


class Manager:
    def __init__(self, config, panel=None, probe=None):
        self.config = config
        self.directory = pathlib.Path(config['state_dir'])
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.panel = panel or Panel(config)
        self.probe = probe or Probe(config)
        self.lock = threading.Lock()
        self.candidate = None
        self.staged = {}
        self.status_lock = threading.Lock()
        self.status = {'busy': False, 'message': 'Готово к проверке.', 'profiles': [], 'candidate': None}
        self.active = json.loads((self.directory / 'active.json').read_text())
        selection_file = self.directory / 'selection.json'
        self.selection = json.loads(selection_file.read_text()) if selection_file.exists() else {'id': None}
        self.measurements = {}
        self.recovery_needed = (self.directory / 'pending.json').exists()
        if self.recovery_needed:
            # Serve the old cache immediately; API recovery needs our feed to be running.
            pending = json.loads((self.directory / 'pending.json').read_text())
            self.active = pending['old']
            atomic(self.directory / 'active.json', self.active)
            self.update(message='Восстанавливаем незавершённую операцию…')
        sources_file = self.directory / 'sources.json'
        self.sources = json.loads(sources_file.read_text()) if sources_file.exists() else {
            'enabled': False, 'primary': copy.deepcopy(self.active), 'free': None}
        if self.recovery_needed and 'sources' in pending:
            self.sources = pending['sources']
        if 'catalog' not in self.sources:
            self.sources['catalog'] = {key: {'name': name, 'url': address, 'enabled': True,
                                           'next_refresh': int(time.time()) + 60 * i}
                                       for i, (key, name, address) in enumerate(DEFAULT_FEEDS)}
            for key in self.sources['catalog']:
                self.sources.setdefault(key, None)
        atomic(sources_file, self.sources)
        self.source_status = {source: {} for source in self.source_ids()}
        self.health_result = None
        self.health_since = 0
        self.next_health = 0
        self.refresh_job = None
        from warp import Warp
        self.warp = Warp(self)

    def state(self):
        with self.status_lock:
            result = copy.deepcopy(self.status)
        active_source = self.active.get('source', 'primary')
        result.update(active={'source': active_source, 'nodes': len(self.active.get('nodes', [])), 'updated': self.active.get('updated'), 'working': self.active.get('working')}, previous=(self.directory / 'previous.json').exists())
        result['fallback_enabled'] = self.sources['enabled']
        result['sources'] = {source: {
            'nodes': len((record or {}).get('nodes', [])),
            'updated': (record or {}).get('updated'),
            'working': (record or {}).get('working'),
            'skipped': (record or {}).get('skipped', 0),
            'error': self.catalog().get(source, {}).get('last_error'),
            **copy.deepcopy(self.source_status.get(source, {})),
        } for source, record in self.sources.items() if source in self.source_ids()}
        result['catalog'] = {key: {'name': value['name'], 'enabled': value['enabled'],
                                   'kind': value.get('kind', 'free'), 'profile': value.get('profile'),
                                   'next_refresh': value.get('next_refresh')}
                             for key, value in self.catalog().items()}
        result['free_interval'] = FREE_INTERVAL
        try:
            nodes = self.available_nodes()
            with self.status_lock:
                measurements = copy.deepcopy(self.measurements)
            selected = result.get('connection', {}).get('selected', [])
            result['connections'] = [{
                'id': self.node_id(n), 'source': source, 'name': self.node_name(n),
                'transport': n.get('streamSettings', {}).get('network', 'tcp'),
                'selected': source == active_source and n.get('tag') in selected,
                'manual': self.selection.get('source', active_source) == source and self.selection.get('id') == self.node_id(n),
                **measurements.get(source + ':' + self.node_id(n), {}),
            } for source, n in nodes]
        except (OSError, ValueError):
            result['connections'] = []
        pinned = bool(self.selection.get('id'))
        suspended = bool(pinned and self.selection.get('suspended'))
        result['mode'] = 'manual' if pinned and not suspended else 'auto'
        result['pin_suspended'] = suspended
        result['pinned_missing'] = bool(pinned and not any(
            self.node_id(n) == self.selection['id'] for n in (self.sources.get(active_source) or {}).get('nodes', [])))
        result['egress'] = self.warp.state()
        return result

    @staticmethod
    def node_id(node):
        return digest({k: v for k, v in node.items() if k != 'tag'})

    def node_name(self, node):
        tag = node.get('tag', '').removeprefix(self.config.get('tag_prefix', 'pixel-'))
        settings = node.get('settings', {})
        host = settings.get('address') or settings.get('vnext', [{}])[0].get('address', '')
        return (tag + (' · ' + host if host else ''))[:180]

    def runtime_nodes(self):
        runtime = json.loads(pathlib.Path(self.config['runtime']).read_text())
        return [n for n in runtime.get('outbounds', []) if n.get('protocol') == 'vless' and n.get('tag', '').startswith(self.config.get('tag_prefix', 'pixel-'))]

    def available_nodes(self):
        active_source = self.active.get('source', 'primary')
        result = []
        for source in self.source_ids():
            nodes = list((self.sources.get(source) or {}).get('nodes', []))
            if source == active_source:
                live = self.runtime_nodes()
                live_ids = {self.node_id(n) for n in live}
                nodes = live + [n for n in nodes if self.node_id(n) not in live_ids]
            result.extend((source, n) for n in nodes)
        return result

    def save_selection(self, selection):
        atomic(self.directory / 'selection.json', selection)
        self.selection = selection

    def automatic_selection(self):
        # Keep a primary-node preference across an automatic source failover so
        # it can be restored as soon as that node is reachable again.
        selection = self.selection
        if selection.get('id') and selection.get('source', 'primary') == 'primary':
            return copy.deepcopy(selection)
        return {'id': None}

    def reconcile_selection(self):
        self.warp.recover()
        if self.warp.is_active:
            self.warp.reconcile()
            return
        self.reconcile_selection_without_warp()

    def reconcile_selection_without_warp(self):
        nodes = self.runtime_nodes()
        if not nodes:
            raise Invalid('Список узлов Xray пока недоступен.')
        pinned = self.selection.get('id')
        suspended = bool(pinned and self.selection.get('suspended'))
        target = next((n['tag'] for n in nodes if self.node_id(n) == pinned), '')
        if pinned and not suspended and not target:
            # Keep the preference instead of silently dropping it: the node may
            # be temporarily missing while Xray reloads or the source recovers.
            updated = copy.deepcopy(self.selection)
            updated['suspended'] = True
            updated['suspended_at'] = int(time.time())
            self.save_selection(updated)
            suspended = True
            self.update(message='Приоритетный узел временно отсутствует в Xray. Используется автовыбор; вернёмся на него, когда он появится.')
        desired = '' if suspended else target
        status = self.panel.balancer()
        if status.get('override', '') != desired:
            self.panel.override(desired)
            status = self.panel.balancer()
        if status.get('override', '') != desired:
            raise Invalid('Xray не подтвердил переключение. Повторите попытку.')
        # Xray's `selected` remains the strategy result even while an override is active.
        effective = [status['override']] if status.get('override') else status.get('selected', [])
        self.update(connection={'selected': effective, 'override': status.get('override', ''), 'checked': int(time.time())}, connection_error=None)

    def measure_nodes(self, node_id=None, source=None):
        nodes = self.available_nodes()
        if source:
            nodes = [(s, n) for s, n in nodes if s == source]
        if node_id:
            nodes = [(s, n) for s, n in nodes if self.node_id(n) == node_id and (source is None or s == source)]
        if not nodes:
            raise Invalid('Узел больше не найден. Обновите страницу.')
        def measure(item):
            source, node = item
            try:
                value = self.probe.latency(node)
            except (OSError, subprocess.SubprocessError):
                value = None
            with self.status_lock:
                self.measurements[source + ':' + self.node_id(node)] = {'latency': value, 'measured': int(time.time())}
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(measure, nodes))
        self.update(message='Проверка задержки завершена. Рабочее подключение не изменялось.')

    def select_node(self, node_id, source=None):
        if self.warp.is_active:
            raise Invalid('Сначала переключите внешний выход с WARP на подписки.')
        self.panel.preflight()
        active_source = self.active.get('source', 'primary')
        source = source or active_source
        personal_mode = bool(self.personal_ids()) or self.catalog().get(active_source, {}).get('kind') == 'personal'
        if node_id and source != 'primary' and personal_mode:
            order = self.priority_ids()
            if source not in order:
                raise Invalid('Сначала включите этот резервный источник и автоматический бесплатный резерв, если он нужен.')
            for higher in order[:order.index(source)]:
                if self.sources.get(higher) and self.check_source_health(higher):
                    raise Invalid('Подписка с более высоким приоритетом работает. Можно проверить резерв, но переключать выход пока нельзя.')
            if source != active_source and (self.health_result != 'priority-dead:' + active_source or time.time() - self.health_since < 60):
                raise Invalid('Отказ текущей подписки ещё не подтверждён двумя проверками.')
        elif node_id and source != 'primary':
            if not self.catalog().get(source, {}).get('enabled', False):
                raise Invalid('Сначала включите этот резервный источник.')
            if self.check_source_health('primary'):
                raise Invalid('Основная подписка работает. Бесплатный узел можно проверить, но включить можно только после отказа всех основных.')
            if active_source == 'primary' and (self.health_result != 'primary-dead' or time.time() - self.health_since < 60):
                raise Invalid('Отказ основной подписки ещё не подтверждён двумя проверками. Дождитесь автоматической проверки.')
        if node_id and (source != active_source or not any(self.node_id(n) == node_id for n in self.runtime_nodes())):
            record = self.sources.get(source)
            chosen = next((n for n in (record or {}).get('nodes', []) if self.node_id(n) == node_id), None)
            if chosen is None:
                raise Invalid('Узел больше не найден. Обновите страницу.')
            if self.probe.latency(chosen) is None:
                raise Invalid('Узел не отвечает через HTTPS. Текущий режим сохранён.')
            self.apply(record, self.panel.preflight(), source=source, remember_previous=False,
                       selection={'id': node_id, 'source': source}, update_source=False)
            self.reset_health()
            return
        if node_id is None:
            if personal_mode:
                # Removing a pin must not bypass failure/recovery confirmation.
                self.save_selection({'id': None})
                self.reconcile_selection()
                self.reset_health()
                self.update(message='Включён автоматический выбор. Приоритет подписок проверяется автоматически.')
                return
            # Explicitly leaving manual mode may return immediately to a verified primary.
            try:
                self.probe.candidates(self.sources['primary']['nodes'])
                target = 'primary'
            except NoWorkingNodes:
                target = self.reserve_target() if self.sources['enabled'] and active_source != 'primary' else active_source
                target = target or active_source
            if target != active_source or node_signature((self.sources.get(target) or {}).get('nodes', [])) != node_signature(self.active['nodes']):
                record = self.sources.get(target)
                if not record:
                    raise Invalid('Бесплатный резерв ещё не загружен. Обновите его перед выбором.')
                self.probe.candidates(record['nodes'])
                self.apply(record, self.panel.preflight(), source=target, remember_previous=False,
                           selection={'id': None}, update_source=False)
                self.reset_health()
                return
        nodes = self.runtime_nodes()
        chosen = next((n for n in nodes if self.node_id(n) == node_id), None) if node_id else None
        if node_id and not chosen:
            raise Invalid('Узел больше не найден. Обновите страницу.')
        if chosen:
            latency = self.probe.latency(chosen)
            with self.status_lock:
                self.measurements[source + ':' + node_id] = {'latency': latency, 'measured': int(time.time())}
            if latency is None:
                raise Invalid('Узел не отвечает через HTTPS. Текущий режим сохранён.')
            if not any(self.node_id(n) == node_id for n in self.runtime_nodes()):
                raise Invalid('Подписка изменилась во время проверки. Выберите узел заново.')
        old = copy.deepcopy(self.selection)
        guard = runtime_guard(json.loads(pathlib.Path(self.config['runtime']).read_text()))
        self.save_selection({'id': node_id or None, 'source': source})
        try:
            self.reconcile_selection()
            if chosen:
                self.probe.live(self.active, guard)
        except Exception as exc:
            self.save_selection(old)
            try:
                self.reconcile_selection()
            except Exception:
                raise Invalid('Переключение не подтверждено. Предыдущий выбор сохранён; служба повторит восстановление.') from exc
            raise Invalid('Узел не заработал. Предыдущий режим восстановлен.') from exc
        self.update(message='Узел выбран вручную. Для автовыбора нажмите «Автоматически».' if chosen else 'Включён автоматический выбор лучшего доступного узла.')
        self.reset_health()

    def update(self, **values):
        with self.status_lock:
            self.status.update(values)

    def submit(self, action, args):
        with self.status_lock:
            busy = self.status['busy']
        # Let a short background status poll finish instead of rejecting a button click.
        if busy or not self.lock.acquire(timeout=2):
            raise Invalid('Другая операция ещё выполняется.')
        if self.recovery_needed or self.warp.journal.exists():
            self.lock.release()
            raise Invalid('Восстановление предыдущей операции ещё не завершено.')
        messages = {'check': 'Проверяем подписку…', 'ping': 'Проверяем задержку узлов…', 'select': 'Переключаем подключение…'}
        self.update(busy=True, message=messages.get(action, 'Применяем настройки…'), profiles=[])
        threading.Thread(target=self.run, args=(action, args), daemon=True).start()

    def run(self, action, args):
        try:
            if action == 'check':
                self.check(args['url'], args.get('profile'))
            elif action == 'warp-check':
                self.warp.check()
            elif action == 'egress':
                self.warp.choose(args['mode'])
            elif action == 'warp-settings':
                self.warp.settings(args['enabled'])
            elif action == 'ping':
                self.measure_nodes(args.get('id'), args.get('source'))
            elif action == 'select':
                self.select_node(args.get('id'), args.get('source'))
            elif action == 'settings':
                updated = copy.deepcopy(self.sources)
                updated['enabled'] = args['enabled']
                self.save_sources(updated)
                self.reset_health()
                self.update(message='Автоматический бесплатный резерв включён.' if args['enabled'] else 'Автоматический бесплатный резерв выключен.')
                # Maintenance loads enabled feeds independently, without holding a request open.
            elif action == 'refresh-free':
                self.schedule_free(args.get('source'))
                self.update(message='Обновление бесплатных подписок поставлено в очередь.')
            elif action == 'save-source':
                self.save_feed(args)
            elif action == 'delete-source':
                self.delete_feed(args.get('source'))
            elif action == 'move-source':
                self.move_feed(args.get('source'), args.get('direction'))
            elif action == 'apply':
                if not self.candidate or not secrets.compare_digest(args.get('id', ''), self.candidate['id']) or time.time() - self.candidate['checked'] > 900:
                    raise Invalid('Повторите проверку подписки: результат устарел или уже использован.')
                candidate, self.candidate = self.candidate, None
                self.update(candidate=None)
                self.apply(candidate['record'], candidate['baseline'])
            elif action == 'rollback':
                previous = self.directory / 'previous.json'
                if not previous.exists():
                    raise Invalid('Предыдущая версия ещё не сохранена.')
                self.candidate = None
                self.update(candidate=None)
                record = json.loads(previous.read_text())
                try:
                    self.probe.candidates(record['nodes'])
                except Invalid as exc:
                    raise Invalid('Предыдущая подписка также недоступна. Действующие настройки сохранены.') from exc
                self.apply(record, self.panel.preflight())
                self.update(message='Предыдущая подписка восстановлена. Внешний маршрут работает.')
            else:
                raise Invalid('Неизвестная операция.')
        except Invalid as exc:
            from formats import ChooseProfile
            self.update(message=str(exc), profiles=exc.profiles if isinstance(exc, ChooseProfile) else [])
        except Exception:
            # Do not serialize exception text: HTTP errors and Xray output can contain credentials.
            self.update(message='Операция не завершена. Проверьте доступность 3x-ui и состояние служб.')
        finally:
            self.update(busy=False)
            self.lock.release()

    def check(self, source, profile):
        self.candidate = None
        self.update(candidate=None)
        body, original = import_body(fetch(source), profile)
        record, before = self.prepare_record(source, profile, body, original)
        self.candidate = {'id': secrets.token_urlsafe(24), 'record': record, 'baseline': before, 'checked': time.time()}
        self.update(candidate={'id': self.candidate['id'], 'nodes': len(record['nodes']), 'working': record['working']}, message='Подписка проверена. Можно применить.')

    def prepare_record(self, source, profile, body, original):
        before = self.panel.preflight()
        self.probe.validate(original)
        token = secrets.token_urlsafe(24)
        self.staged[token] = body
        try:
            nodes = self.panel.parse(self.config['feed_url'].rsplit('/', 1)[0] + '/candidate/' + token)
        finally:
            self.staged.pop(token, None)
        if len(nodes) != len(original):
            raise Invalid('3x-ui импортировала не все узлы; подписка не будет применена.')
        good = self.probe.candidates(nodes)
        if digest(self.panel.preflight()) != digest(before):
            raise Invalid('Настройки 3x-ui изменились во время проверки. Повторите проверку.')
        record = {'url': source, 'profile': profile, 'body': body.decode(), 'nodes': nodes, 'working': good, 'updated': int(time.time())}
        return record, before

    def apply(self, record, baseline, source='primary', remember_previous=True, selection=None, update_source=True):
        if digest(self.panel.preflight()) != digest(baseline):
            raise Invalid('Настройки 3x-ui изменились. Повторите проверку подписки.')
        guard = runtime_guard(json.loads(pathlib.Path(self.config['runtime']).read_text()))
        old = copy.deepcopy(self.active)
        record = copy.deepcopy(record)
        record['source'] = source
        if selection is None and old.get('source', 'primary') != source:
            selection = {'id': None}
        updated_sources = copy.deepcopy(self.sources)
        if update_source:
            updated_sources[source] = record
        pending = {'old': old, 'new': record, 'guard': guard, 'selection': self.selection,
                   'sources': copy.deepcopy(self.sources)}
        atomic(self.directory / 'pending.json', pending)
        self.recovery_needed = True
        try:
            atomic(self.directory / 'active.json', record)
            self.active = record
            if selection is not None:
                self.save_selection(selection)
            self.panel.refresh()
            self.probe.wait(record, guard)
            self.reconcile_selection()
            self.probe.live(record, guard)
            self.save_sources(updated_sources)
            if remember_previous:
                atomic(self.directory / 'previous.json', pending['sources']['primary'])
            (self.directory / 'pending.json').unlink()
            self.recovery_needed = False
            self.reset_health()
            self.update(message='Подписка применена. Внешний маршрут работает.')
        except Exception as original:
            try:
                self.restore(pending)
            except Exception:
                self.recovery_needed = True
                raise Invalid('Сбой применения. Старый кэш восстановлен, но 3x-ui не подтвердила откат. Служба повторит восстановление; проверьте 3x-ui.') from original
            raise Invalid('Новая подписка не заработала. Предыдущая восстановлена; ' + ('внешний маршрут работает.' if self.active.get('working') else 'предыдущий внешний выход также недоступен.')) from original

    def restore(self, pending):
        old = pending['old']
        atomic(self.directory / 'active.json', old)
        self.active = old
        if 'sources' in pending:
            self.save_sources(pending['sources'])
        self.panel.refresh()
        self.probe.wait(old, pending['guard'])
        if 'selection' in pending:
            self.save_selection(pending['selection'])
        self.reconcile_selection()
        # A dead old provider must not prevent restoring its configuration.
        try:
            self.probe.live(old, pending['guard'])
            old['working'] = max(1, old.get('working', 0))
        except Exception:
            old['working'] = 0
        atomic(self.directory / 'active.json', old)
        (self.directory / 'pending.json').unlink()
        self.recovery_needed = False

    def save_sources(self, sources):
        atomic(self.directory / 'sources.json', sources)
        self.sources = sources

    def catalog(self):
        # Compatibility with an old transaction journal and the single-feed state.
        return self.sources.get('catalog', {'free': {'name': 'Parsabrg/free_sub', 'url': FREE_URL, 'enabled': True}})

    def source_ids(self):
        return ['primary', *self.catalog()]

    def personal_ids(self):
        return [key for key, feed in self.catalog().items() if feed.get('kind') == 'personal' and feed['enabled']]

    def priority_ids(self):
        return ['primary', *self.personal_ids(), *[key for key, feed in self.catalog().items()
            if feed.get('kind', 'free') == 'free' and feed['enabled'] and self.sources['enabled']]]

    def feed_interval(self, source):
        return self.config.get('refresh_interval', 3600) if self.catalog()[source].get('kind') == 'personal' else FREE_INTERVAL

    def move_feed(self, source, direction):
        if source not in self.catalog() or self.catalog()[source].get('kind') != 'personal' or direction not in ('up', 'down'):
            raise Invalid('Укажите резервную подписку и направление перемещения.')
        keys = list(self.catalog())
        personal = [key for key in keys if self.catalog()[key].get('kind') == 'personal']
        index = personal.index(source)
        other = index + (-1 if direction == 'up' else 1)
        if not 0 <= other < len(personal):
            return
        a, b = keys.index(source), keys.index(personal[other])
        keys[a], keys[b] = keys[b], keys[a]
        updated = copy.deepcopy(self.sources)
        updated['catalog'] = {key: updated['catalog'][key] for key in keys}
        self.save_sources(updated)
        self.reset_health()
        self.update(message='Порядок резервных подписок сохранён.')

    def save_feed(self, args):
        key = args.get('source')
        if key is not None and key not in self.catalog():
            raise Invalid('Источник не найден.')
        name = args.get('name')
        enabled = args.get('enabled', True)
        address = args.get('url') or (self.catalog().get(key) or {}).get('url')
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100 or type(enabled) is not bool:
            raise Invalid('Укажите название до 100 символов и состояние источника.')
        if not isinstance(address, str) or len(address) > 8192:
            raise Invalid('Укажите HTTPS-ссылку.')
        parsed = urllib.parse.urlsplit(address)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise Invalid('Нужна HTTPS-ссылка без логина в адресе.')
        # Resolving and downloading remain in fetch(), with its public-address checks.
        if key is None and len(self.catalog()) >= 32:
            raise Invalid('Максимум 32 резервных источника.')
        if key is None:
            key = 'free-' + secrets.token_hex(8)
        old = self.catalog().get(key, {})
        kind = args.get('kind', old.get('kind', 'free'))
        profile = args.get('profile', old.get('profile'))
        if kind not in ('personal', 'free') or (profile is not None and (type(profile) is not int or profile < 0)):
            raise Invalid('Укажите тип подписки и корректный номер профиля.')
        if old and kind != old.get('kind', 'free'):
            raise Invalid('Тип сохранённой подписки менять нельзя. Создайте новый источник.')
        if (not enabled or old.get('url') != address or old.get('profile') != profile) and self.active.get('source') == key:
            raise Invalid('Источник сейчас используется. Сначала переключите выход.')
        if any(v['url'] == address for k, v in self.catalog().items() if k != key):
            raise Invalid('Эта ссылка уже есть в каталоге.')
        updated = copy.deepcopy(self.sources)
        updated['catalog'] = copy.deepcopy(self.catalog())
        updated['catalog'][key] = {'name': name.strip(), 'url': address, 'enabled': enabled,
                                    'kind': kind, 'profile': profile,
                                    'next_refresh': old.get('next_refresh', int(time.time()))}
        if old.get('url') != address or old.get('profile') != profile:
            updated[key] = None
            updated['catalog'][key]['next_refresh'] = int(time.time())
        updated.setdefault(key, None)
        self.save_sources(updated)
        self.source_status.setdefault(key, {})
        self.reset_health()
        self.update(message='Источник сохранён.')

    def delete_feed(self, source):
        if source not in self.catalog():
            raise Invalid('Источник не найден.')
        if self.active.get('source') == source:
            raise Invalid('Нельзя удалить действующий выход. Сначала переключите подключение.')
        updated = copy.deepcopy(self.sources)
        updated['catalog'] = copy.deepcopy(self.catalog())
        del updated['catalog'][source]
        updated.pop(source, None)
        self.save_sources(updated)
        self.source_status.pop(source, None)
        self.reset_health()
        self.update(message='Источник удалён.')

    def schedule_free(self, source=None):
        if source is not None and source not in self.catalog():
            raise Invalid('Источник не найден.')
        updated = copy.deepcopy(self.sources)
        updated['catalog'] = copy.deepcopy(self.catalog())
        for key, feed in updated['catalog'].items():
            if (source is None and feed['enabled'] and feed.get('kind', 'free') == 'free') or key == source:
                feed['next_refresh'] = int(time.time())
                feed['requested'] = True
        self.save_sources(updated)

    def reserve_target(self):
        for key in self.priority_ids()[1:]:
            if self.sources.get(key) and self.check_source_health(key):
                return key
        return None

    def reset_health(self):
        self.health_result = None
        self.health_since = 0
        self.next_health = 0

    def refresh_source(self, source):
        self.source_status.setdefault(source, {})
        try:
            if source == 'primary':
                current = self.sources['primary']
                body, nodes = import_body(fetch(current['url']), current.get('profile'))
                record, baseline = self.prepare_record(current['url'], current.get('profile'), body, nodes)
            else:
                record, baseline = self.build_free_record(source, self.catalog()[source]['url'])
            self.commit_refresh(source, record, baseline)
        except Exception as exc:
            message = str(exc) if isinstance(exc, Invalid) else 'Не удалось обновить подписку.'
            self.source_status[source].update(error=message + ' Последний проверенный кэш сохранён.', attempted=int(time.time()))
            raise
        finally:
            if not self.recovery_needed and source != 'primary' and source in self.catalog():
                updated = copy.deepcopy(self.sources)
                updated['catalog'] = copy.deepcopy(self.catalog())
                updated['catalog'][source]['next_refresh'] = int(time.time()) + self.feed_interval(source)
                updated['catalog'][source]['last_error'] = self.source_status.get(source, {}).get('error')
                updated['catalog'][source].pop('requested', None)
                self.save_sources(updated)

    def commit_refresh(self, source, record, baseline):
        record['source'] = source
        if self.active.get('source', 'primary') == source:
            pinned = self.selection.get('id')
            if pinned and not any(self.node_id(n) == pinned for n in record['nodes']):
                updated = copy.deepcopy(self.sources)
                updated[source] = record
                self.save_sources(updated)
                self.update(message='Закреплённый узел исчез из обновления. Его прежняя конфигурация сохранена до отмены ручного выбора.')
            else:
                self.apply(record, baseline, source=source, remember_previous=False)
        else:
            updated = copy.deepcopy(self.sources)
            updated[source] = record
            self.save_sources(updated)
        self.source_status[source].update(error=None, refreshed=int(time.time()),
                                          checked=int(time.time()), working=record['working'])

    def build_free_record(self, source, address):
        feed = self.catalog().get(source, {})
        if feed.get('kind') == 'personal':
            body, nodes = import_body(fetch(address), feed.get('profile'))
            return self.prepare_record(address, feed.get('profile'), body, nodes)
        batches, skipped = free_batches(fetch(address))
        self.source_status.setdefault(source, {}).update(skipped=skipped, candidates=sum(len(nodes) for _, nodes in batches))
        for body, nodes in batches:
            compatible = []
            for node in nodes:
                host = node['settings']['vnext'][0]['address']
                try:
                    # Public feeds must never introduce local proxy endpoints.
                    addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
                    if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
                        raise Invalid('Непубличный адрес узла.')
                    self.probe.validate([node])
                    compatible.append(node)
                except (Invalid, OSError):
                    skipped += 1
            self.source_status[source]['skipped'] = skipped
            if not compatible:
                continue
            from formats import encode_uri
            body, nodes = import_body(('\n'.join(encode_uri(n) for n in compatible)).encode())
            try:
                record, baseline = self.prepare_record(address, None, body, nodes)
                record['skipped'] = skipped
                return record, baseline
            except NoWorkingNodes:
                continue
        raise NoWorkingNodes('В бесплатной ленте не найдено работающих VLESS с этого сервера.')

    def free_worker(self, source, address):
        try:
            self.refresh_job['result'] = self.build_free_record(source, address)
        except Exception as exc:
            self.refresh_job['error'] = str(exc) if isinstance(exc, Invalid) else 'Не удалось обновить подписку.'
        finally:
            self.refresh_job['done'] = True

    def poll_free_refresh(self):
        job = self.refresh_job
        if job and job['done']:
            source = job['source']
            feed = self.catalog().get(source)
            try:
                # Ignore results for a removed, changed or rescheduled source.
                if feed and feed == job['feed']:
                    if 'result' in job:
                        record, baseline = job['result']
                        self.commit_refresh(source, record, baseline)
                    else:
                        self.source_status.setdefault(source, {})['error'] = job['error'] + ' Последний проверенный кэш сохранён.'
            except Exception:
                self.source_status.setdefault(source, {})['error'] = 'Результат обновления не применён. Последний проверенный кэш сохранён.'
            finally:
                if not self.recovery_needed and feed and feed == job['feed']:
                    updated = copy.deepcopy(self.sources)
                    updated['catalog'] = copy.deepcopy(self.catalog())
                    updated['catalog'][source]['next_refresh'] = int(time.time()) + self.feed_interval(source)
                    updated['catalog'][source]['last_error'] = self.source_status.get(source, {}).get('error')
                    updated['catalog'][source].pop('requested', None)
                    self.save_sources(updated)
                self.source_status.setdefault(source, {})['loading'] = False
                self.refresh_job = None
        if not self.refresh_job and not self.recovery_needed:
            due = next((key for key, feed in self.catalog().items()
                        if feed.get('next_refresh', 0) <= time.time()
                        and (feed['enabled'] or feed.get('requested'))), None)
            if due:
                feed = copy.deepcopy(self.catalog()[due])
                self.source_status.setdefault(due, {}).update(loading=True, attempted=int(time.time()))
                self.refresh_job = {'source': due, 'feed': feed, 'done': False}
                threading.Thread(target=self.free_worker, args=(due, feed['url']), daemon=True).start()

    def check_source_health(self, source):
        record = self.sources.get(source)
        if not record:
            raise Invalid('Источник ещё не загружен.')
        try:
            working = self.probe.candidates(record['nodes'])
        except NoWorkingNodes:
            working = 0
        self.source_status[source].update(checked=int(time.time()), working=working)
        return working > 0

    def suspend_pin(self, source):
        selection = self.selection
        active_source = self.active.get('source', 'primary')
        if (not selection.get('id') or selection.get('suspended')
                or selection.get('source', active_source) != source):
            return
        updated = copy.deepcopy(selection)
        updated['suspended'] = True
        updated['suspended_at'] = int(time.time())
        # Persist the preference before touching Xray: a failed switch must not
        # silently lose the user's priority node.
        self.save_selection(updated)
        record = self.sources.get(source) or {}
        try:
            if record and node_signature(record.get('nodes', [])) != node_signature(self.active.get('nodes', [])):
                self.apply(record, self.panel.preflight(), source=source, remember_previous=False,
                           selection=updated, update_source=False)
            else:
                self.reconcile_selection()
        finally:
            self.update(message='Приоритетный узел временно недоступен. Используется автовыбор; '
                                'вернёмся на него автоматически, когда он восстановится.')

    def restore_suspended_pin(self):
        selection = self.selection
        pinned = selection.get('id')
        if not pinned or not selection.get('suspended'):
            return False
        source = selection.get('source') or self.active.get('source', 'primary')
        if source != self.active.get('source', 'primary'):
            return False
        record = self.sources.get(source) or {}
        runtime_nodes = self.runtime_nodes()
        if not any(self.node_id(n) == pinned for n in runtime_nodes):
            return False
        node = next((n for n in record.get('nodes', []) if self.node_id(n) == pinned), None)
        if node is None:
            node = next((n for n in runtime_nodes if self.node_id(n) == pinned), None)
        if node is None or self.probe.latency(node) is None:
            return False
        updated = copy.deepcopy(selection)
        updated.pop('suspended', None)
        updated.pop('suspended_at', None)
        self.save_selection(updated)
        self.reconcile_selection()
        self.update(message='Приоритетный узел снова работает — возвращаемся на него.')
        return True

    def health_tick(self):
        """Called under the operation lock. Only completed probes count as evidence."""
        if self.warp.is_active:
            return self.warp.health_tick()
        if self.warp.fallback_enabled:
            return self.priority_health_tick()
        if self.personal_ids() or self.catalog().get(self.active.get('source'), {}).get('kind') == 'personal':
            return self.priority_health_tick()
        now = time.time()
        if now < self.next_health:
            return
        source = self.active.get('source', 'primary')
        if source == 'primary' and not self.sources['enabled'] and not self.selection.get('id'):
            return
        try:
            self.panel.preflight()
            if self.restore_suspended_pin():
                return
            if source == 'primary':
                runtime = json.loads(pathlib.Path(self.config['runtime']).read_text())
                if node_signature(self.runtime_nodes()) != node_signature(self.active['nodes']):
                    raise Invalid('Рабочая конфигурация Xray изменилась.')
                alive = self.probe.routed(runtime)
                if alive:
                    self.health_result = None
                    return
                if self.selection.get('id') and not self.selection.get('suspended'):
                    pinned = next((n for n in self.active['nodes'] if self.node_id(n) == self.selection['id']), None)
                    if pinned and self.probe.latency(pinned) is not None:
                        self.health_result = None
                        return
                if self.check_source_health('primary'):
                    if self.selection.get('id') and not self.selection.get('suspended'):
                        self.suspend_pin('primary')
                    self.health_result = None
                    return
                if not self.sources['enabled']:
                    return
                evidence, target = 'primary-dead', 'free'
            else:
                if not self.check_source_health('primary'):
                    self.health_result = None
                    if self.check_source_health(source):
                        if self.selection.get('id') and not self.selection.get('suspended'):
                            pinned = next((n for n in self.active['nodes'] if self.node_id(n) == self.selection['id']), None)
                            if not pinned or self.probe.latency(pinned) is None:
                                self.suspend_pin(source)
                    else:
                        target = self.reserve_target()
                        if target and target != source:
                            self.apply(self.sources[target], self.panel.preflight(), source=target, remember_previous=False,
                                       selection=self.automatic_selection(), update_source=False)
                            self.update(message='Действующий резерв недоступен; включён другой бесплатный источник.')
                        elif not target:
                            self.update(message='Рабочих резервных узлов нет. Текущая конфигурация сохранена.')
                    return
                evidence, target = 'primary-restored', 'primary'
            finished = time.time()
            if self.health_result != evidence:
                self.health_result, self.health_since = evidence, finished
                self.update(message='Основная подписка недоступна; ожидаем повторную проверку.' if target == 'free' else 'Основная подписка восстановилась; ожидаем повторную проверку.')
                return
            if finished - self.health_since < 60:
                return
            if target == 'free':
                target = self.reserve_target()
                if not target:
                    self.update(message='Рабочих резервных узлов нет. Текущая конфигурация сохранена; ожидаем обновления источников.')
                    return
                # Free probes can take minutes; do not switch on stale primary evidence.
                if self.check_source_health('primary'):
                    self.health_result = None
                    return
            self.apply(self.sources[target], self.panel.preflight(), source=target, remember_previous=False,
                       selection=self.automatic_selection(), update_source=False)
            self.update(message='Восстановлена основная подписка.' if target == 'primary' else 'Включён бесплатный резерв.')
        except Exception:
            self.health_result = None
            raise
        finally:
            self.next_health = time.time() + 60

    def priority_health_tick(self):
        now = time.time()
        if now < self.next_health:
            return
        source = self.active.get('source', 'primary')
        try:
            self.panel.preflight()
            runtime = json.loads(pathlib.Path(self.config['runtime']).read_text())
            if node_signature(self.runtime_nodes()) != node_signature(self.active['nodes']):
                raise Invalid('Рабочая конфигурация Xray изменилась.')
            if self.restore_suspended_pin():
                return
            order = self.priority_ids()
            if any(not self.sources.get(key) and not self.catalog()[key].get('last_error') for key in self.personal_ids()):
                self.update(message='Ожидаем первоначальной проверки резервной подписки.')
                return
            higher = order[:order.index(source)] if source in order else order
            target = next((key for key in higher if self.sources.get(key) and self.check_source_health(key)), None)
            if target is not None:
                evidence = 'priority-restored:' + target
            else:
                # With emergency WARP enabled, prove the subscription itself:
                # a successful routed URL may use an earlier direct/pilot rule.
                alive = source in order and not self.warp.fallback_enabled and self.probe.routed(runtime)
                if (source in order and not alive and self.selection.get('id')
                        and not self.selection.get('suspended')):
                    pinned = next((n for n in self.active['nodes'] if self.node_id(n) == self.selection['id']), None)
                    alive = bool(pinned and self.probe.latency(pinned) is not None)
                if source in order and not alive:
                    alive = self.check_source_health(source)
                    if alive and self.selection.get('id') and not self.selection.get('suspended'):
                        self.suspend_pin(source)
                if alive:
                    self.health_result = None
                    return
                evidence = 'priority-dead:' + source
            finished = time.time()
            if self.health_result != evidence:
                self.health_result, self.health_since = evidence, finished
                self.update(message='Изменилось состояние подписок; ожидаем повторную проверку перед переключением.')
                return
            if finished - self.health_since < 60:
                return
            # Scan in priority order again: long free-feed probes must not hide recovery.
            restored_target = target
            target = next((key for key in order if self.sources.get(key) and self.check_source_health(key)), None)
            if target is None:
                if self.warp.fallback_enabled:
                    self.warp.activate_automatic()
                    return
                self.update(message='Все доступные подписки отказали. Текущая конфигурация сохранена; ожидаем восстановления.')
                return
            if target == source:
                self.health_result = None
                return
            if restored_target is not None and target != restored_target:
                self.health_result = None
                return
            if restored_target is None and source in order and order.index(target) < order.index(source):
                self.health_result, self.health_since = 'priority-restored:' + target, time.time()
                return
            # Confirm higher sources once more after checking a lower-priority target.
            for key in order[:order.index(target)]:
                if self.sources.get(key) and self.check_source_health(key):
                    self.health_result = None
                    return
            self.apply(self.sources[target], self.panel.preflight(), source=target, remember_previous=False,
                       selection=self.automatic_selection(), update_source=False)
            label = 'основная подписка' if target == 'primary' else self.catalog()[target]['name']
            self.update(message='Автоматически включена подписка: ' + label + '.')
        except Exception:
            self.health_result = None
            raise
        finally:
            self.next_health = time.time() + 60

    def refresh_sources(self):
        for source in self.source_ids():
            if source != 'primary' and not self.catalog()[source]['enabled']:
                continue
            try:
                self.refresh_source(source)
            except Exception:
                self.update(message='Фоновое обновление источника не удалось. Последний проверенный кэш сохранён.')
            if self.recovery_needed:
                break

    def maintenance(self):
        next_refresh = time.time() + self.config.get('refresh_interval', 3600)
        while True:
            time.sleep(5)
            if self.lock.acquire(False):
                try:
                    if self.recovery_needed:
                        self.update(busy=True, message='Восстанавливаем предыдущую операцию…', candidate=None)
                        self.restore(json.loads((self.directory / 'pending.json').read_text()))
                        self.update(message='Предыдущая конфигурация восстановлена.')
                    else:
                        if self.candidate and time.time() - self.candidate['checked'] > 900:
                            self.candidate = None
                            self.update(candidate=None)
                        if self.candidate and not self.warp.is_active:
                            continue
                        try:
                            self.reconcile_selection()
                        except Exception:
                            self.update(connection_error='Не удалось получить состояние Xray. Сохранённый режим будет восстановлен при подключении.')
                            if self.warp.journal.exists():
                                continue
                        if self.candidate:
                            if self.warp.is_active:
                                self.warp.health_tick()
                            continue
                        if time.time() >= next_refresh:
                            self.update(busy=True)
                            next_refresh = time.time() + self.config.get('refresh_interval', 3600)
                            self.refresh_source('primary')
                        if not self.recovery_needed and time.time() >= self.next_health:
                            self.update(busy=True)
                            self.health_tick()
                        if not self.recovery_needed:
                            self.poll_free_refresh()
                except Exception:
                    self.candidate = None
                    self.update(candidate=None, message='Фоновое обновление не удалось. Последняя сохранённая подписка оставлена; проверьте внешний доступ.')
                finally:
                    self.update(busy=False)
                    self.lock.release()

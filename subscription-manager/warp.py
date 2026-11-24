"""Independent WARP probes and durable emergency-egress selection."""
import contextlib
import copy
import ipaddress
import json
import pathlib
import subprocess
import time

from backend import atomic, digest
from formats import Invalid

TAG = 'warp-emergency'
PROBE_TAG = 'warp-probe-in'
PROBE_PORT = 19089
TRACE_URL = 'https://1.1.1.1/cdn-cgi/trace'


class Warp:
    def __init__(self, manager):
        self.manager = manager
        self.path = manager.directory / 'egress.json'
        self.journal = manager.directory / 'egress-pending.json'
        self.value = json.loads(self.path.read_text()) if self.path.exists() else {
            'mode': 'subscriptions', 'origin': 'manual', 'fallback_enabled': False}
        if self.value.get('mode') not in ('subscriptions', 'warp'):
            raise Invalid('Некорректный сохранённый режим внешнего выхода.')
        self.result = {}
        self.next_health = 0
        self.recovered = None

    @property
    def is_active(self):
        return self.value['mode'] == 'warp'

    @property
    def fallback_enabled(self):
        return self.value['fallback_enabled']

    def outbound(self):
        runtime = json.loads(pathlib.Path(self.manager.config['runtime']).read_text())
        node = next((n for n in runtime.get('outbounds', []) if n.get('tag') == TAG), None)
        if not node or node.get('protocol') != 'wireguard':
            raise Invalid('WARP не настроен на сервере.')
        node = copy.deepcopy(node)
        # Isolated probes must not allocate a kernel interface or routing table.
        node.setdefault('settings', {})['noKernelTun'] = True
        return node

    def state(self):
        try:
            self.outbound()
            configured = True
        except (Invalid, OSError, ValueError):
            configured = False
        return {**self.value, 'configured': configured, 'warp': copy.deepcopy(self.result),
                'recovering': self.journal.exists()}

    def save(self, value):
        atomic(self.path, value)
        self.value = copy.deepcopy(value)

    def settings(self, enabled):
        self.save({**self.value, 'fallback_enabled': enabled})
        self.manager.reset_health()
        self.manager.update(message='Аварийный резерв WARP включён.' if enabled else 'Аварийный резерв WARP выключен.')

    def check(self):
        """Prove WARP identity AND real HTTPS reachability without switching users."""
        result = {'checked': int(time.time()), 'healthy': False}
        self.result = {**result, 'checking': True}
        try:
            node = self.outbound()
            probe = self.manager.probe
            with self.probe_tunnel(node) as (port, account):
                if port is None:
                    raise Invalid('Не удалось запустить проверочный туннель WARP.')
                started = time.monotonic()
                try:
                    auth = '' if account is None else 'proxy-user = ' + json.dumps(account['user'] + ':' + account['pass']) + '\n'
                    response = subprocess.run([
                        'curl', '-q', '--config', '-', '--noproxy', '', '--socks5-hostname', '127.0.0.1:' + str(port),
                        '--connect-timeout', '8', '--max-time', '15', '--retry', '2', '--retry-delay', '1',
                        '--retry-all-errors', '--max-filesize', '16384',
                        '--fail', '--silent', '--show-error', TRACE_URL],
                        input=auth, capture_output=True, text=True, timeout=50)
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise Invalid('Cloudflare не отвечает через WARP с этого сервера.') from exc
                if response.returncode:
                    raise Invalid('Cloudflare не отвечает через WARP с этого сервера.')
                fields = dict(line.split('=', 1) for line in response.stdout.splitlines() if '=' in line)
                if fields.get('warp') not in ('on', 'plus'):
                    raise Invalid('Cloudflare не подтвердил выход через WARP.')
                try:
                    address = str(ipaddress.ip_address(fields.get('ip', '')))
                except ValueError as exc:
                    raise Invalid('Cloudflare вернул некорректный выходной IP.') from exc
                latency = max(1, round((time.monotonic() - started) * 1000))
                if not probe.curl(port, account):
                    raise Invalid('WARP подключён, но контрольные ресурсы через него недоступны.')
            result.update(healthy=True, latency=latency, ip=address, warp=fields['warp'])
            self.result = result
            self.manager.update(message='WARP проверен на сервере: туннель и контрольный HTTPS-запрос работают.')
            return result
        except Invalid as exc:
            result['error'] = str(exc)
            self.result = result
            raise
        except Exception as exc:
            result['error'] = 'Не удалось проверить WARP на сервере.'
            self.result = result
            raise Invalid(result['error']) from exc

    @contextlib.contextmanager
    def probe_tunnel(self, node):
        runtime = json.loads(pathlib.Path(self.manager.config['runtime']).read_text())
        inbound = next((i for i in runtime.get('inbounds', []) if i.get('tag') == PROBE_TAG), None)
        if inbound is not None:
            rules = runtime.get('routing', {}).get('rules', [])
            probe_rule = {'type': 'field', 'inboundTag': [PROBE_TAG], 'outboundTag': TAG}
            index = next((i for i, rule in enumerate(rules) if rule == probe_rule), None)
            protected = index is not None and all(rule.get('inboundTag') and PROBE_TAG not in rule['inboundTag']
                                                 for rule in rules[:index])
            if (inbound.get('listen') != '127.0.0.1' or inbound.get('protocol') != 'socks'
                    or not protected):
                raise Invalid('Не подтверждён изолированный проверочный вход WARP.')
            account = next(iter(inbound.get('settings', {}).get('accounts', [])), None)
            yield inbound['port'], account
        else:
            if self.is_active:
                raise Invalid('Не найден проверочный вход WARP; требуется обновление настройки выхода.')
            probe = self.manager.probe
            # The real isolated process validates and exercises the profile.
            # Do not instantiate the same WireGuard key in a second test process.
            with probe.slots, probe.tunnel(node) as port:
                if port is not None:
                    # The SOCKS listener can open before the userspace WG stack.
                    time.sleep(1)
                yield port, None

    def override(self, tag):
        panel = self.manager.panel
        status = panel.balancer()
        if status.get('override', '') != tag:
            panel.override(tag)
            status = panel.balancer()
        if status.get('override', '') != tag:
            raise Invalid('Xray не подтвердил переключение внешнего выхода.')
        self.manager.update(connection={'selected': [tag] if tag else status.get('selected', []),
                                       'override': tag, 'checked': int(time.time())}, connection_error=None)

    def reconcile(self):
        self.outbound()
        self.override(TAG)

    def recover(self):
        if not self.journal.exists():
            return
        pending = json.loads(self.journal.read_text())
        self.save(pending['old'])
        if 'selection' in pending:
            self.manager.save_selection(pending['selection'])
        self.override(pending['override'])
        self.journal.unlink()

    def switch(self, mode, origin='manual'):
        if mode not in ('subscriptions', 'warp'):
            raise Invalid('Выберите подписки или WARP.')
        manager = self.manager
        self.recover()
        before = manager.panel.preflight()
        if mode == 'warp':
            self.check()
        else:
            manager.probe.candidates(manager.active.get('nodes', []))
        if digest(manager.panel.preflight()) != digest(before):
            raise Invalid('Настройки Xray изменились во время проверки. Повторите переключение.')
        previous_override = manager.panel.balancer().get('override', '')
        pending = {'old': copy.deepcopy(self.value), 'override': previous_override,
                   'selection': copy.deepcopy(manager.selection)}
        atomic(self.journal, pending)
        try:
            self.save({**self.value, 'mode': mode, 'origin': origin})
            if mode == 'warp':
                self.reconcile()
            else:
                if manager.selection.get('id'):
                    pinned = next((n for n in manager.runtime_nodes()
                                   if manager.node_id(n) == manager.selection['id']), None)
                    if pinned is None or manager.probe.latency(pinned) is None:
                        manager.save_selection({'id': None})
                manager.reconcile_selection_without_warp()
            runtime = json.loads(pathlib.Path(manager.config['runtime']).read_text())
            if not manager.probe.routed(runtime):
                raise Invalid('Общий маршрут VLESS/WDTT не прошёл проверку после переключения.')
            self.journal.unlink()
        except Exception as exc:
            try:
                self.recover()
            except Exception:
                raise Invalid('Переключение не подтверждено. Сохранён журнал; служба повторит восстановление.') from exc
            raise Invalid('Новый выход не заработал. Предыдущий режим восстановлен.') from exc
        self.recovered = None
        self.next_health = time.time() + 60
        manager.reset_health()
        manager.update(message='Включён аварийный WARP.' if mode == 'warp' else 'Внешний выход возвращён на подписки.')

    def first_working_source(self):
        pending = False
        for source in self.manager.priority_ids():
            if self.manager.sources.get(source) and self.manager.check_source_health(source):
                return source
            if source != 'primary' and not self.manager.sources.get(source):
                feed = self.manager.catalog()[source]
                if not feed.get('last_error'):
                    pending = True
        if pending:
            raise Invalid('Ожидаем первоначальной проверки подписок перед аварийным переключением.')
        return None

    def choose(self, mode):
        if mode == 'subscriptions':
            source = self.first_working_source()
            if source is None:
                raise Invalid('Рабочих подписок нет. Текущий внешний выход сохранён.')
            if source != self.manager.active.get('source', 'primary'):
                self.manager.apply(self.manager.sources[source], self.manager.panel.preflight(), source=source,
                                   remember_previous=False, selection={'id': None}, update_source=False)
        self.switch(mode)

    def activate_automatic(self):
        # A fresh priority scan prevents a long previous probe from hiding recovery.
        if self.first_working_source() is None:
            self.switch('warp', 'auto')

    def health_tick(self):
        if time.time() < self.next_health:
            return
        try:
            try:
                self.check()
            except Invalid as exc:
                self.manager.update(message=str(exc))
            if self.value['origin'] == 'manual':
                return
            self.manager.panel.preflight()
            target = self.first_working_source()
            if target is None:
                self.recovered = None
                return
            now = time.time()
            if self.recovered is None or self.recovered[0] != target:
                self.recovered = (target, now)
                self.manager.update(message='Подписка восстановилась; ожидаем повторную проверку перед возвратом с WARP.')
                return
            if now - self.recovered[1] < 60:
                return
            self.manager.apply(self.manager.sources[target], self.manager.panel.preflight(), source=target,
                               remember_previous=False, selection={'id': None}, update_source=False)
            self.switch('subscriptions', 'auto')
        except Exception:
            self.recovered = None
            raise
        finally:
            self.next_health = time.time() + 60

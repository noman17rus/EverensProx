import base64
import hashlib
import copy
import http.client
import json
import pathlib
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from backend import Manager, Panel, atomic, digest, fetch
from formats import ChooseProfile, Invalid, decode_uri, import_body
from server import Admin, Feed, Server, SESSION_COOKIE, password_hash, prepare_html

URI = 'vless://00000000-0000-4000-8000-000000000001@example.com:443?type=tcp&security=reality&pbk=abc&sni=example.com&fp=chrome#Node'


class FormatsTest(unittest.TestCase):
    def test_plain_base64_and_json(self):
        body, nodes = import_body(URI.encode())
        self.assertIn(b'#node-1', body)
        self.assertEqual(import_body(base64.b64encode(URI.encode()))[0], body)
        node = nodes[0]
        self.assertEqual(import_body(json.dumps({'outbounds': [node]}).encode())[0], body)

    def test_auto_and_profile_selection(self):
        node = decode_uri(URI)
        profiles = [{'remarks': 'A', 'outbounds': [node]}, {'remarks': 'B', 'outbounds': [node]}]
        with self.assertRaises(ChooseProfile) as cm:
            import_body(json.dumps(profiles).encode())
        self.assertEqual(len(cm.exception.profiles), 2)
        self.assertEqual(len(import_body(json.dumps(profiles).encode(), 1)[1]), 1)
        profiles[1]['remarks'] = 'Автовыбор'
        self.assertEqual(len(import_body(json.dumps(profiles).encode())[1]), 1)

    def test_transport_roundtrip(self):
        for transport in ['ws&host=cdn.example.com&path=%2Fws', 'grpc&serviceName=hello&mode=multi', 'xhttp&path=%2F&extra=%7B%22scMaxEachPostBytes%22%3A1000%7D']:
            body, nodes = import_body(URI.replace('type=tcp', 'type=' + transport).encode())
            self.assertEqual(import_body(body)[1], nodes)

    def test_reality_mlkem_hint_values(self):
        expected = import_body(URI.encode())
        for value in ('true', 'false', '1', '0'):
            with self.subTest(value=value):
                raw = URI.replace('#Node', '&support-x25519mlkem768=' + value + '#Node')
                self.assertEqual(import_body(raw.encode()), expected)

    def test_reality_mlkem_hint_three_transports(self):
        transports = [
            'tcp',
            'grpc&serviceName=example&authority=grpc.example.com&mode=multi',
            'xhttp&host=cdn.example.com&path=%2Ftest&mode=auto&extra=%7B%22mode%22%3A%22packet-up%22%7D',
        ]
        plain = '\n'.join(URI.replace('type=tcp', 'type=' + transport) for transport in transports)
        hinted = plain.replace('#Node', '&support-x25519mlkem768=true#Node')
        body, nodes = import_body(hinted.encode())
        self.assertEqual((body, nodes), import_body(plain.encode()))
        self.assertEqual(len(nodes), 3)
        self.assertEqual([n['streamSettings']['network'] for n in nodes], ['tcp', 'grpc', 'xhttp'])
        self.assertEqual(import_body(body), (body, nodes))
        self.assertEqual(import_body(base64.b64encode(hinted.encode())), (body, nodes))
        self.assertNotIn('support-x25519mlkem768', json.dumps(nodes))
        self.assertNotIn('supportX25519Mlkem768', json.dumps(nodes))

    def test_reality_mlkem_hint_rejects_invalid(self):
        for value in ('', 'yes', 'TRUE', '2'):
            with self.subTest(value=value), self.assertRaisesRegex(Invalid, 'должен быть true, false, 1 или 0'):
                import_body(URI.replace('#Node', '&support-x25519mlkem768=' + value + '#Node').encode())
        hinted = URI.replace('#Node', '&support-x25519mlkem768=true#Node')
        with self.assertRaisesRegex(Invalid, 'только для Reality'):
            import_body(hinted.replace('security=reality', 'security=tls').encode())
        with self.assertRaisesRegex(Invalid, 'Повторяющиеся'):
            import_body(hinted.replace('#Node', '&support-x25519mlkem768=false#Node').encode())
        with self.assertRaisesRegex(Invalid, 'неподдерживаемые параметры'):
            import_body(hinted.replace('#Node', '&unknown=true#Node').encode())

    def test_happ_default_session_resumption(self):
        node = decode_uri(URI.replace('security=reality', 'security=tls'))
        node['streamSettings']['tlsSettings']['enableSessionResumption'] = False
        self.assertEqual(len(import_body(json.dumps({'outbounds': [node]}).encode())[1]), 1)
        node['streamSettings']['tlsSettings']['enableSessionResumption'] = True
        with self.assertRaises(Invalid):
            import_body(json.dumps({'outbounds': [node]}).encode())

    def test_reject_unsupported(self):
        for raw in [b'', b'{}', b'not a subscription', URI.replace('vless://', 'ss://').encode(), (URI + '&unknown=yes').replace('#Node', '').encode(), URI.replace('security=reality', 'security=none').encode(), URI.replace('443', '99999').encode(), (URI + '\nhttps://example.com').encode()]:
            with self.subTest(raw=raw), self.assertRaises(Invalid):
                import_body(raw)
        node = decode_uri(URI)
        node['streamSettings']['sockopt'] = {'dialerProxy': 'hidden'}
        with self.assertRaises(Invalid):
            import_body(json.dumps({'outbounds': [node]}).encode())

    def test_fetch_rejects_private_and_insecure_sources(self):
        for source in ['http://example.com/sub', 'https://127.0.0.1/sub', 'https://user:pass@example.com/sub']:
            with self.subTest(source=source), self.assertRaises(Invalid):
                fetch(source)

    def test_panel_api_uses_form_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = pathlib.Path(tmp) / 'auth.json'
            auth.write_text(json.dumps({'token': 'test-token'}))
            panel = Panel({'panel_url': 'http://127.0.0.1:2053/base', 'panel_auth_file': str(auth)})
            with patch('urllib.request.build_opener') as opener:
                response = opener.return_value.open.return_value.__enter__.return_value
                response.read.return_value = b'{"success":true,"obj":[]}'
                panel.call('xray/outbound-subs/parse', {'url': 'http://127.0.0.1/subscription', 'allowPrivate': True}, 'POST')
                request = opener.return_value.open.call_args.args[0]
                self.assertEqual(request.get_header('Content-type'), 'application/x-www-form-urlencoded')
                self.assertIn(b'allowPrivate=true', request.data)


class FakePanel:
    def __init__(self):
        self.baseline = {'template': 'unchanged'}
        self.refreshes = 0
        self.fail = False
        self.target = ''
        self.overrides = []

    def preflight(self):
        return copy.deepcopy(self.baseline)

    def parse(self, url):
        return import_body(URI.encode())[1]

    def refresh(self):
        self.refreshes += 1
        if self.fail:
            raise Invalid('API unavailable')

    def balancer(self):
        return {'running': True, 'override': self.target, 'selected': ['pixel-auto-candidate']}

    def override(self, tag):
        self.target = tag
        self.overrides.append(tag)


class FakeProbe:
    def __init__(self):
        self.failure = False
        self.old_dead = False
        self.ms = 123

    def validate(self, nodes):
        pass

    def candidates(self, nodes):
        return 1

    def latency(self, node):
        return self.ms

    def wait(self, record, guard):
        pass

    def live(self, record, guard):
        if self.failure and (record['url'] != 'old' or self.old_dead):
            raise Invalid('unreachable')


class TransactionsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.old = {'url': 'old', 'body': URI, 'nodes': import_body(URI.encode())[1], 'working': 1}
        atomic(self.root / 'active.json', self.old)
        self.runtime = {'inbounds': [], 'routing': {}, 'outbounds': [{**self.old['nodes'][0], 'tag': 'pixel-node-1'}]}
        atomic(self.root / 'runtime.json', self.runtime)
        self.config = {'state_dir': str(self.root), 'runtime': str(self.root / 'runtime.json'), 'feed_url': 'http://127.0.0.1:19087/subscription'}
        self.panel, self.probe = FakePanel(), FakeProbe()
        self.manager = Manager(self.config, self.panel, self.probe)
        self.new = {**self.old, 'url': 'new'}

    def tearDown(self):
        self.tmp.cleanup()

    def test_success_and_previous(self):
        self.manager.apply(self.new, self.panel.preflight())
        self.assertEqual(self.manager.active['url'], 'new')
        self.assertEqual(json.loads((self.root / 'previous.json').read_text())['url'], 'old')
        self.assertFalse((self.root / 'pending.json').exists())

    def test_connection_failure_rolls_back(self):
        self.probe.failure = True
        with self.assertRaisesRegex(Invalid, 'Предыдущая восстановлена'):
            self.manager.apply(self.new, self.panel.preflight())
        self.assertEqual(self.manager.active['url'], 'old')
        self.assertEqual(self.panel.refreshes, 2)

    def test_failed_apply_preserves_earlier_previous(self):
        atomic(self.root / 'previous.json', {**self.old, 'url': 'earlier'})
        self.probe.failure = True
        with self.assertRaises(Invalid):
            self.manager.apply(self.new, self.panel.preflight())
        self.assertEqual(json.loads((self.root / 'previous.json').read_text())['url'], 'earlier')
        self.assertFalse(self.manager.recovery_needed)

    def test_failure_writing_active_recovers_journal(self):
        real_atomic = atomic
        def write(path, value):
            if pathlib.Path(path).name == 'active.json' and value['url'] == 'new':
                raise OSError('disk full')
            real_atomic(path, value)
        with patch('backend.atomic', side_effect=write), self.assertRaises(Invalid):
            self.manager.apply(self.new, self.panel.preflight())
        self.assertEqual(self.manager.active['url'], 'old')
        self.assertFalse(self.manager.recovery_needed)
        self.assertFalse((self.root / 'pending.json').exists())

    def test_dead_old_provider_is_reported(self):
        self.probe.failure = self.probe.old_dead = True
        with self.assertRaisesRegex(Invalid, 'также недоступен'):
            self.manager.apply(self.new, self.panel.preflight())
        self.assertEqual(self.manager.active['working'], 0)

    def test_api_failure_retains_recovery_journal(self):
        self.panel.fail = True
        with self.assertRaisesRegex(Invalid, 'не подтвердила откат'):
            self.manager.apply(self.new, self.panel.preflight())
        self.assertTrue((self.root / 'pending.json').exists())
        self.assertEqual(self.manager.active['url'], 'old')
        self.assertTrue(self.manager.recovery_needed)

    def test_restart_recovers_crash_during_apply(self):
        atomic(self.root / 'pending.json', {'old': self.old, 'new': self.new, 'guard': 'old'})
        atomic(self.root / 'active.json', self.new)
        restarted = Manager(self.config, self.panel, self.probe)
        self.assertTrue(restarted.recovery_needed)
        self.assertEqual(restarted.active['url'], 'old')
        restarted.restore(json.loads((self.root / 'pending.json').read_text()))
        self.assertEqual(restarted.active['url'], 'old')
        self.assertFalse(restarted.recovery_needed)

    def test_concurrent_panel_change_refuses_apply(self):
        baseline = self.panel.preflight()
        self.panel.baseline['template'] = 'changed'
        with self.assertRaisesRegex(Invalid, 'изменились'):
            self.manager.apply(self.new, baseline)
        self.assertEqual(self.panel.refreshes, 0)

    def test_check_does_not_change_active(self):
        with patch('backend.fetch', return_value=URI.encode()):
            self.manager.check('https://example.com/sub', None)
        self.assertEqual(self.manager.active, self.old)
        self.assertTrue(self.manager.candidate)
        self.assertFalse(self.manager.staged)

    def test_failed_download_invalidates_old_candidate(self):
        self.manager.candidate = {'id': 'old'}
        with patch('backend.fetch', side_effect=Invalid('timeout')), self.assertRaises(Invalid):
            self.manager.check('https://example.com/sub', None)
        self.assertIsNone(self.manager.candidate)
        self.assertEqual(self.manager.active, self.old)

    def test_invalid_candidate_does_not_touch_panel(self):
        with patch('backend.fetch', return_value=b'{}'), self.assertRaises(Invalid):
            self.manager.check('https://example.com/sub', None)
        self.assertEqual(self.panel.refreshes, 0)
        self.assertEqual(self.manager.active, self.old)

    def test_duplicate_apply_does_not_replay(self):
        self.manager.lock.acquire()
        self.manager.run('apply', {'id': 'used'})
        self.assertIn('Повторите', self.manager.state()['message'])
        self.assertEqual(self.panel.refreshes, 0)

    def test_operation_is_serialized(self):
        self.manager.lock.acquire()
        try:
            with self.assertRaisesRegex(Invalid, 'выполняется'):
                self.manager.submit('check', {'url': 'x'})
        finally:
            self.manager.lock.release()


class SelectionTest(unittest.TestCase):
    def setUp(self):
        TransactionsTest.setUp(self)

    def tearDown(self):
        TransactionsTest.tearDown(self)

    def node_id(self):
        return self.manager.node_id(self.runtime['outbounds'][0])

    def test_ping_does_not_switch(self):
        self.manager.measure_nodes(self.node_id())
        state = self.manager.state()
        self.assertEqual(state['connections'][0]['latency'], 123)
        self.assertEqual(state['mode'], 'auto')
        self.assertEqual(self.panel.overrides, [])

    def test_manual_and_return_to_auto(self):
        self.manager.select_node(self.node_id())
        self.assertEqual(self.panel.target, 'pixel-node-1')
        self.assertEqual(self.manager.state()['mode'], 'manual')
        self.assertTrue(self.manager.state()['connections'][0]['selected'])
        self.manager.select_node(None)
        self.assertEqual(self.panel.target, '')
        self.assertEqual(self.manager.state()['mode'], 'auto')

    def test_override_is_effective_even_when_strategy_selects_another(self):
        self.manager.select_node(self.node_id())
        self.assertEqual(self.panel.balancer()['selected'], ['pixel-auto-candidate'])
        self.assertEqual(self.manager.state()['connection']['selected'], ['pixel-node-1'])

    def test_unreachable_node_keeps_mode(self):
        self.probe.ms = None
        with self.assertRaisesRegex(Invalid, 'не отвечает'):
            self.manager.select_node(self.node_id())
        self.assertEqual(self.panel.overrides, [])
        self.assertEqual(self.manager.state()['mode'], 'auto')

    def test_stale_or_arbitrary_id_rejected(self):
        with self.assertRaisesRegex(Invalid, 'не найден'):
            self.manager.select_node('0' * 64)
        self.assertEqual(self.panel.overrides, [])

    def test_manual_choice_survives_restart(self):
        self.manager.select_node(self.node_id())
        self.panel.target = ''  # Xray restarted and forgot its runtime override.
        restarted = Manager(self.config, self.panel, self.probe)
        restarted.reconcile_selection()
        self.assertEqual(self.panel.target, 'pixel-node-1')
        self.assertEqual(restarted.state()['mode'], 'manual')

    def test_renamed_tag_preserves_same_server(self):
        self.manager.select_node(self.node_id())
        self.runtime['outbounds'][0]['tag'] = 'pixel-renamed'
        atomic(self.root / 'runtime.json', self.runtime)
        self.manager.reconcile_selection()
        self.assertEqual(self.panel.target, 'pixel-renamed')

    def test_changed_server_with_same_tag_resets_auto(self):
        self.manager.select_node(self.node_id())
        self.runtime['outbounds'][0]['settings']['vnext'][0]['address'] = 'different.example.com'
        atomic(self.root / 'runtime.json', self.runtime)
        self.manager.reconcile_selection()
        self.assertEqual(self.panel.target, '')
        self.assertEqual(self.manager.state()['mode'], 'auto')
        self.assertIn('исчез', self.manager.state()['message'])

    def test_status_never_exposes_node_credentials(self):
        raw = json.dumps(self.manager.state())
        self.assertNotIn('00000000-0000-4000-8000-000000000001', raw)
        self.assertNotIn('publicKey', raw)
        self.assertNotIn('vless://', raw)

    def test_failed_live_switch_restores_previous_mode(self):
        with patch.object(self.probe, 'live', side_effect=Invalid('failed')), self.assertRaisesRegex(Invalid, 'режим восстановлен'):
            self.manager.select_node(self.node_id())
        self.assertEqual(self.panel.target, '')
        self.assertEqual(self.manager.state()['mode'], 'auto')

    def test_failed_subscription_apply_preserves_manual_choice(self):
        self.manager.select_node(self.node_id())
        self.probe.failure = True
        with self.assertRaises(Invalid):
            self.manager.apply(self.new, self.panel.preflight())
        self.assertEqual(self.panel.target, 'pixel-node-1')
        self.assertEqual(self.manager.state()['mode'], 'manual')


class HTTPTest(unittest.TestCase):
    def test_csp_matches_browser_script_with_windows_and_mac_line_endings(self):
        original = b'<html>\n<script>\nwindow.example = 1;\n</script></html>'
        for newline in (b'\n', b'\r\n', b'\r'):
            with self.subTest(newline=newline):
                self.server.html, self.server.csp = prepare_html(original.replace(b'\n', newline))
                code, headers, raw = self.request('GET', '/')
                self.assertEqual(code, 200)
                self.assertNotIn(b'\r', raw)
                browser_script = raw.split(b'<script>')[1].split(b'</script>')[0].replace(b'\r\n', b'\n').replace(b'\r', b'\n')
                expected = base64.b64encode(hashlib.sha256(browser_script).digest()).decode()
                self.assertIn("'sha256-" + expected + "'", headers['Content-Security-Policy'])

    def test_login_page_with_query_never_requires_an_existing_session(self):
        for path in ('/?', '/?refresh=1'):
            code, headers, body = self.request('GET', path)
            self.assertEqual(code, 200)
            self.assertTrue(headers['Content-Type'].startswith('text/html'))
            self.assertEqual(body, self.server.html)

    def setUp(self):
        TransactionsTest.setUp(self)
        self.server = Server(('127.0.0.1', 0), Admin)
        self.server.manager = self.manager
        self.host = '127.0.0.1:' + str(self.server.server_port)
        self.manager.config.update(admin_host=self.host, lan_subnet='127.0.0.0/8', password_salt='aa' * 16, password_hash=password_hash('test-password', 'aa' * 16))
        self.server.html = b'test'
        self.server.sessions, self.server.failures = {}, {}
        self.server.auth_lock = threading.Lock()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        TransactionsTest.tearDown(self)

    def request(self, method, path, data=None, headers=None):
        c = http.client.HTTPConnection('127.0.0.1', self.server.server_port)
        h = {'Host': self.host, 'Origin': 'http://' + self.host, 'Content-Type': 'application/json'}
        h.update(headers or {})
        c.request(method, path, None if data is None else json.dumps(data), h)
        response = c.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        c.close()
        return result

    def test_login_and_csrf(self):
        self.assertEqual(self.request('GET', '/api/status')[0], 401)
        code, headers, body = self.request('POST', '/api/login', {'password': 'test-password'})
        self.assertEqual(code, 200)
        cookie = headers['Set-Cookie'].split(';')[0]
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        code, _, raw = self.request('GET', '/api/status', headers={'Cookie': cookie})
        self.assertEqual(code, 200)
        state = json.loads(raw)
        self.assertNotIn('old', raw.decode())
        self.assertEqual(self.request('POST', '/api/rollback', {}, {'Cookie': cookie})[0], 403)
        self.assertEqual(self.request('POST', '/api/rollback', {}, {'Cookie': cookie, 'X-CSRF-Token': state['csrf'], 'Origin': 'http://evil.example'})[0], 403)
        self.assertEqual(self.request('GET', '/', headers={'Host': 'evil.example'})[0], 403)
        self.assertEqual(self.request('POST', '/api/logout', {}, {'Cookie': cookie, 'X-CSRF-Token': state['csrf']})[0], 200)
        self.assertEqual(self.request('GET', '/api/status', headers={'Cookie': cookie})[0], 401)

    def test_rate_limit(self):
        for _ in range(5):
            self.assertEqual(self.request('POST', '/api/login', {'password': 'wrong'})[0], 401)
        self.assertEqual(self.request('POST', '/api/login', {'password': 'test-password'})[0], 429)

    def test_session_is_isolated_from_other_panels_and_malformed_cookies(self):
        code, headers, _ = self.request('POST', '/api/login', {'password': 'test-password'})
        self.assertEqual(code, 200)
        cookie = headers['Set-Cookie'].split(';')[0]
        self.assertTrue(cookie.startswith(SESSION_COOKIE + '='))
        for raw in ('session=other-panel; ' + cookie,
                    cookie + '; session=other-panel',
                    'other={malformed value}; ' + cookie):
            with self.subTest(raw=raw):
                code, _, body = self.request('GET', '/api/status', headers={'Cookie': raw})
                self.assertEqual(code, 200)
                self.assertTrue(json.loads(body)['csrf'])
        token = cookie.partition('=')[2]
        self.assertEqual(self.request('GET', '/api/status', headers={'Cookie': 'session=' + token})[0], 401)
        self.assertEqual(self.request('GET', '/api/status', headers={'Cookie': cookie + '; ' + cookie})[0], 401)

    def test_lan_filter_and_feed_survive_provider_failure(self):
        self.manager.config['lan_subnet'] = '192.168.1.0/24'
        self.assertEqual(self.request('GET', '/')[0], 403)
        feed = Server(('127.0.0.1', 0), Feed)
        feed.manager = self.manager
        thread = threading.Thread(target=feed.serve_forever, daemon=True)
        thread.start()
        try:
            with patch('backend.fetch', side_effect=Invalid('timeout')), self.assertRaises(Invalid):
                self.manager.check('https://example.com/sub', None)
            c = http.client.HTTPConnection('127.0.0.1', feed.server_port)
            c.request('GET', '/subscription')
            response = c.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read().decode(), self.old['body'])
            c.close()
        finally:
            feed.shutdown()
            feed.server_close()
            thread.join()


if __name__ == '__main__':
    unittest.main()

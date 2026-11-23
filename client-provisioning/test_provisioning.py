import concurrent.futures
import copy
import http.client
import http.server
import json
import pathlib
import tempfile
import threading
import unittest
import urllib.parse

from backend import Invalid, Manager, Panel, Unavailable, client_node, normalize_login
from server import RateLimiter, Server


def inbound(number, clients=None, protocol='vless'):
    return {'id': number, 'protocol': protocol, 'enable': True, 'port': 443 + number,
            'listen': '', 'settings': json.dumps({'clients': clients or []}),
            'streamSettings': json.dumps({'network': 'tcp', 'security': 'reality',
                'realitySettings': {'serverNames': ['example.org'], 'shortIds': ['abcd'],
                                   'settings': {'publicKey': 'public-key'}}})}


class FakePanel:
    def __init__(self):
        self.items = [inbound(1), inbound(2), inbound(3, protocol='socks')]
        self.additions = []
        self.fail_after_add = False

    def inbounds(self):
        return copy.deepcopy(self.items)

    def add(self, entry, client, existing=False):
        current = next(i for i in self.items if i['id'] == entry['id'])
        settings = json.loads(current['settings'])
        settings['clients'].append(copy.deepcopy(client))
        current['settings'] = json.dumps(settings)
        self.additions.append((entry['id'], copy.deepcopy(client)))
        if self.fail_after_add:
            self.fail_after_add = False
            raise Unavailable('Connection lost after add')


class FakeWdtt:
    def __init__(self):
        self.entries = []
        self.creates = 0
        self.fail = False
        self.fail_after_create = False

    def listing(self):
        if self.fail:
            raise Unavailable('Offline')
        return {'passwords': copy.deepcopy(self.entries)}

    def create(self, password, label):
        if len(password) != 16 or any(c not in 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789' for c in password):
            raise Unavailable('Invalid WDTT password')
        entry = {'password': password, 'label': label, 'shared': True, 'status': 'active',
                 'ports': '56000,56001,9000', 'vk_hash': 'hash'}
        self.entries.append(entry)
        self.creates += 1
        if self.fail_after_create:
            self.fail_after_create = False
            raise Unavailable('Connection lost after create')
        return copy.deepcopy(entry)


class ProvisioningTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = {'database': str(pathlib.Path(self.temp.name) / 'state.sqlite3'),
                       'public_url': 'https://hub.everens.online', 'public_host': 'hub.everens.online',
                       'wdtt_hashes': 'hash'}
        self.panel, self.wdtt = FakePanel(), FakeWdtt()
        self.manager = Manager(self.config, self.panel, self.wdtt)

    def test_new_account_and_no_device_limit(self):
        result = self.manager.provision(' Example@gmail.com ')
        self.assertEqual(result['login'], 'example@gmail.com')
        self.assertTrue(result['wdtt_link'].startswith('wdtt://connect?'))
        self.assertEqual(len(self.panel.additions), 2)
        for _ in range(1000):
            self.assertEqual(self.manager.provision('EXAMPLE@gmail.com'), result)
        self.assertEqual(self.wdtt.creates, 1)
        self.assertEqual(self.panel.additions[0][1]['limitIp'], 0)

    def test_concurrent_registration(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            values = list(pool.map(self.manager.provision, ['same-login'] * 30))
        self.assertTrue(all(v == values[0] for v in values))
        self.assertEqual(len(self.panel.additions), 2)
        self.assertEqual(self.wdtt.creates, 1)

    def test_preserve_legacy_and_create_only_missing(self):
        existing = {'id': 'existing-uuid', 'email': 'Somebody', 'subId': 'old-sub-id',
                    'enable': True, 'totalGB': 123, 'limitIp': 0, 'flow': 'xtls-rprx-vision'}
        self.panel.items[0] = inbound(1, [existing])
        personal = {'password': 'personal', 'label': 'Somebody', 'shared': False, 'status': 'active'}
        self.wdtt.entries.append(personal.copy())
        result = self.manager.provision('somebody')
        self.assertEqual(json.loads(self.panel.items[0]['settings'])['clients'], [existing])
        self.assertEqual(len(self.panel.additions), 1)
        self.assertEqual(self.panel.additions[0][1]['id'], 'existing-uuid')
        self.assertEqual(self.panel.additions[0][1]['subId'], 'old-sub-id')
        self.assertEqual(self.wdtt.entries[0], personal)
        self.assertNotIn('password=personal', result['wdtt_link'])

    def test_reuse_existing_shared_wdtt(self):
        entry = self.wdtt.create('abcdefghjkmnpqrs', 'Name')
        result = self.manager.provision('name')
        self.assertIn('password=abcdefghjkmnpqrs', result['wdtt_link'])
        self.assertEqual(self.wdtt.creates, 1)
        self.assertEqual(self.wdtt.entries[0], entry)

    def test_retry_after_panel_or_wdtt_partial_failure(self):
        self.panel.fail_after_add = True
        with self.assertRaises(Unavailable):
            self.manager.provision('recover')
        self.wdtt.fail_after_create = True
        with self.assertRaises(Unavailable):
            self.manager.provision('recover')
        restarted = Manager(self.config, self.panel, self.wdtt)
        result = restarted.provision('RECOVER')
        self.assertEqual(self.wdtt.creates, 1)
        self.assertEqual(len(self.panel.additions), 2)
        self.assertEqual(restarted.provision('recover'), result)

    def test_incomplete_legacy_password_recovers_without_changing_vless(self):
        self.wdtt.fail = True
        with self.assertRaises(Unavailable):
            self.manager.provision('recover-password')
        with self.manager.connect() as db:
            db.execute("UPDATE accounts SET wdtt_password=?", ('a' * 32,))
        self.wdtt.fail = False
        result = self.manager.provision('recover-password')
        self.assertEqual(len(self.wdtt.entries[0]['password']), 16)
        self.assertTrue(result['wdtt_link'])
        self.assertEqual(len(self.panel.additions), 2)

    def test_repair_deleted_sides_and_new_inbound_on_refresh(self):
        result = self.manager.provision('repair')
        self.panel.items[0]['settings'] = '{"clients":[]}'
        self.panel.items.append(inbound(9))
        self.wdtt.entries.clear()
        token = result['subscription_url'].rsplit('/', 1)[1]
        config = self.manager.subscription(token)
        self.assertEqual(len(config['proxies']), 3)
        self.assertEqual(len(self.panel.additions), 4)
        self.assertEqual(self.manager.subscription(token, True), result)

    def test_disabled_or_conflicting_accounts_fail_without_rewriting(self):
        clients = [{'id': 'uuid', 'subId': 'sub', 'email': 'same', 'enable': False}]
        self.panel.items[0] = inbound(1, clients)
        with self.assertRaises(Unavailable):
            self.manager.provision('same')
        self.assertFalse(self.panel.additions)
        clients[0]['enable'] = True
        self.panel.items[0] = inbound(1, clients)
        self.panel.items[1] = inbound(2, [{'id': 'different', 'subId': 'other', 'email': 'same'}])
        with self.assertRaises(Unavailable):
            self.manager.provision('same')

    def test_normalization_and_invalid_inputs(self):
        self.assertEqual(normalize_login('  ИМЯ  '), ('имя', 'ИМЯ'))
        for value in ('', '  ', 'x' * 255, 'x\ny', 'x\x00', 'x\u200by', None, 4):
            with self.subTest(value=value), self.assertRaises(Invalid):
                normalize_login(value)

    def test_transport_conversion_and_unsupported_settings(self):
        client = {'id': 'uuid', 'flow': ''}
        item = inbound(1)
        for network, transport, expected in (
                ('ws', {'path': '/socket', 'headers': {'Host': 'cdn.example'}},
                 {'ws-opts': {'path': '/socket', 'headers': {'Host': 'cdn.example'}}}),
                ('grpc', {'serviceName': 'service', 'authority': 'cdn.example'},
                 {'grpc-opts': {'grpc-service-name': 'service', 'grpc-authority': 'cdn.example'}}),
                ('xhttp', {'path': '/x', 'extra': {'noGRPCHeader': True, 'scMaxEachPostBytes': 10000}},
                 {'xhttp-opts': {'path': '/x', 'host': '', 'mode': 'auto',
                                 'no-grpc-header': True, 'sc-max-each-post-bytes': '10000'}})):
            with self.subTest(network=network):
                item['streamSettings'] = {'network': network, 'security': 'tls',
                                          'tlsSettings': {'serverName': 'tls.example', 'alpn': ['h2']},
                                          network + 'Settings': transport}
                node = client_node(item, client, 'hub.everens.online')
                for key, value in expected.items():
                    self.assertEqual(node[key], value)
                self.assertEqual(node['servername'], 'tls.example')
                self.assertNotIn('skip-cert-verify', node)
        item['streamSettings']['xhttpSettings']['extra']['downloadSettings'] = {'address': 'other.example'}
        with self.assertRaises(Unavailable):
            client_node(item, client, 'host')
        self.panel.items[0]['streamSettings'] = {'network': 'unsupported'}
        with self.assertRaises(Unavailable):
            self.manager.provision('unsupported')
        self.assertEqual(self.panel.additions, [])

    def test_public_port_mapping_does_not_change_inbound(self):
        self.config['inbound_ports'] = {'1': 443}
        account = self.manager.provision('public-port')
        token = account['subscription_url'].rsplit('/', 1)[1]
        nodes = self.manager.subscription(token)['proxies']
        self.assertEqual(nodes[0]['port'], 443)
        self.assertEqual(self.panel.items[0]['port'], 444)
        self.assertEqual(nodes[1]['port'], self.panel.items[1]['port'])

    def test_reality_mlkem_survives_repeated_registration_without_key_changes(self):
        self.config['reality_mlkem_inbound_ids'] = [1]
        account = self.manager.provision('Existing')
        token = account['subscription_url'].rsplit('/', 1)[1]
        first = self.manager.subscription(token)
        self.assertTrue(first['proxies'][0]['reality-opts']['support-x25519mlkem768'])
        self.assertNotIn('support-x25519mlkem768', first['proxies'][1]['reality-opts'])
        old_clients = copy.deepcopy(self.panel.items)
        self.assertEqual(self.manager.provision('EXISTING'), account)
        self.assertEqual(self.manager.subscription(token), first)
        self.assertEqual(self.panel.items, old_clients)
        self.assertEqual(len(self.panel.additions), 2)

    def test_reality_mlkem_for_existing_vless_keeps_uuid_and_sub_id(self):
        self.config['reality_mlkem_inbound_ids'] = [1]
        old = {'id': 'legacy-uuid', 'email': 'Sergey', 'subId': 'legacy-sub',
               'flow': 'xtls-rprx-vision', 'enable': True}
        self.panel.items[0] = inbound(1, [old])
        account = self.manager.provision('Sergey')
        node = self.manager.subscription(account['subscription_url'].rsplit('/', 1)[1])['proxies'][0]
        self.assertEqual(node['uuid'], old['id'])
        self.assertTrue(node['reality-opts']['support-x25519mlkem768'])
        self.assertEqual(json.loads(self.panel.items[0]['settings'])['clients'], [old])

    def test_real_panel_adapter_contract(self):
        records = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                records.append((self.path, self.headers.get('Authorization'), None))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps({'success': True, 'obj': [inbound(1)]}).encode())

            def do_POST(self):
                raw = self.rfile.read(int(self.headers['Content-Length']))
                records.append((self.path, self.headers.get('Authorization'), urllib.parse.parse_qs(raw.decode())))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"success":true,"obj":null}')

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        auth = pathlib.Path(self.temp.name) / 'auth.json'
        auth.write_text('{"token":"test-token"}')
        panel = Panel({'panel_url': 'http://127.0.0.1:' + str(server.server_address[1]) + '/base',
                       'panel_auth_file': str(auth), 'client_api': 'legacy'})
        selected = panel.inbounds()[0]
        panel.add(selected, {'id': 'uuid', 'email': 'имя', 'subId': 'sub'})
        self.assertEqual(records[0][:2], ('/base/panel/api/inbounds/list', 'Bearer test-token'))
        self.assertEqual(records[1][0], '/base/panel/api/inbounds/addClient')
        self.assertEqual(json.loads(records[1][2]['settings'][0])['clients'][0]['email'], 'имя')

    def test_universal_panel_api_preserves_existing_client_on_attach(self):
        panel = Panel({'client_api': 'universal'})
        calls = []
        panel.call = lambda path, data=None, json_body=False: calls.append((path, data, json_body))
        panel.add({'id': 2}, {'id': 'uuid', 'email': 'person@example.org', 'subId': 'sub', 'tgId': ''})
        self.assertEqual(calls[0][0], 'clients/add')
        self.assertEqual(calls[0][1]['client']['tgId'], 0)
        self.assertEqual(calls[0][1]['client']['limitHwid'], 0)
        self.assertEqual(calls[0][1]['inboundIds'], [2])
        self.assertTrue(calls[0][2])
        panel.add({'id': 9}, {'email': 'person@example.org', 'totalGB': 123}, existing=True)
        self.assertEqual(calls[1], ('clients/person%40example.org/attach', {'inboundIds': [9]}, True))

    def test_http_contract_and_errors(self):
        server = Server(('127.0.0.1', 0), self.manager)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        def request(method, path, value=None):
            connection = http.client.HTTPConnection(*server.server_address, timeout=5)
            connection.request(method, path, json.dumps(value) if value is not None else None,
                               {'Content-Type': 'application/json'})
            response = connection.getresponse()
            status, body = response.status, json.loads(response.read())
            connection.close()
            return status, body

        status, account = request('POST', '/api/v1/provision', {'login': 'web'})
        self.assertEqual(status, 200)
        path = '/api/v1/subscriptions/' + account['subscription_url'].rsplit('/', 1)[1]
        self.assertEqual(request('GET', path)[0], 200)
        self.assertEqual(request('GET', path + '/metadata'), (200, account))
        self.assertEqual(request('POST', '/api/v1/provision', {'login': ''})[0], 400)
        self.assertEqual(request('GET', '/api/v1/subscriptions/unknown')[0], 404)
        self.wdtt.fail = True
        status, error = request('POST', '/api/v1/provision', {'login': 'web'})
        self.assertEqual(status, 503)
        self.assertNotIn('password', json.dumps(error))

    def test_rate_limit_is_not_a_device_limit(self):
        limiter = RateLimiter(limit=2)
        self.assertTrue(limiter.allow('ip'))
        self.assertTrue(limiter.allow('ip'))
        self.assertFalse(limiter.allow('ip'))
        self.assertTrue(limiter.allow('other-ip'))


if __name__ == '__main__':
    unittest.main()

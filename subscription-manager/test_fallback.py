"""Source isolation, failover evidence, persistence, and HTTP contracts."""
import base64
import copy
import json
import subprocess
import socket
import threading
import unittest
from unittest.mock import patch

import test_manager as fixtures
from backend import FREE_URL, Manager, NoWorkingNodes, Probe, atomic, proxy_header_relay
from formats import Invalid, LIMIT, free_batches, import_body


class PublicFeedTest(unittest.TestCase):
    def test_proxy_header_relay_preserves_bidirectional_traffic(self):
        received = []
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen()
            server.settimeout(5)
            port = server.getsockname()[1]
            def echo():
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(5)
                    with connection.makefile('rb') as reader:
                        received.append(reader.readline())
                        received.append(reader.read(4))
                        connection.sendall(b'pong')
            thread = threading.Thread(target=echo)
            thread.start()
            with proxy_header_relay(port) as relay_port:
                with socket.create_connection(('127.0.0.1', relay_port), timeout=5) as client:
                    client.sendall(b'ping')
                    self.assertEqual(client.recv(4), b'pong')
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertTrue(received[0].startswith(b'PROXY TCP4 127.0.0.1 127.0.0.1 '))
        self.assertTrue(received[0].endswith((' ' + str(port) + '\r\n').encode()))
        self.assertEqual(received[1], b'ping')

    def test_reality_key_derivation_keeps_private_key_out_of_arguments(self):
        private = base64.urlsafe_b64encode(b'a' * 32).decode().rstrip('=')
        public = b'b' * 32
        result = subprocess.CompletedProcess([], 0, bytes.fromhex('302a300506032b656e032100') + public, b'')
        with patch('backend.subprocess.run', return_value=result) as run:
            self.assertEqual(Probe.reality_public_key(private), base64.urlsafe_b64encode(public).decode().rstrip('='))
        self.assertNotIn(private, str(run.call_args.args))
        self.assertTrue(run.call_args.kwargs['input'].endswith(b'a' * 32))
        with self.assertRaises(Invalid):
            Probe.reality_public_key('invalid')

    def test_routed_probe_supports_existing_reality_ingress(self):
        probe = Probe({})
        inbound = {'protocol': 'vless', 'listen': '127.0.0.1', 'port': 8443,
            'settings': {'clients': [{'id': 'local-id', 'flow': 'xtls-rprx-vision'}]},
            'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {
                'privateKey': 'private', 'serverNames': ['example.com'], 'shortIds': ['ab']}}}
        with patch.object(probe, 'reality_public_key', return_value='public'), patch.object(probe, 'one', return_value=True) as one:
            self.assertTrue(probe.routed({'inbounds': [inbound]}))
        settings = one.call_args.args[0]['streamSettings']['realitySettings']
        self.assertEqual(settings['publicKey'], 'public')
        self.assertEqual(settings['serverName'], 'example.com')
        self.assertNotIn('privateKey', settings)

    def test_routed_probe_uses_real_loopback_vless_when_socks_is_absent(self):
        probe = Probe({})
        inbound = {'protocol': 'vless', 'listen': '127.0.0.1', 'port': 8443,
                   'settings': {'clients': [{'id': 'local-id', 'flow': ''}]},
                   'streamSettings': {'network': 'ws', 'wsSettings': {'path': '/local'}}}
        with patch.object(probe, 'one', return_value=True) as one:
            self.assertTrue(probe.routed({'inbounds': [inbound]}))
        outbound = one.call_args.args[0]
        self.assertEqual(outbound['settings']['vnext'][0]['address'], '127.0.0.1')
        self.assertEqual(outbound['settings']['vnext'][0]['users'][0]['id'], 'local-id')
        self.assertEqual(outbound['streamSettings']['wsSettings'], {'path': '/local'})
        inbound['listen'] = '0.0.0.0'
        with self.assertRaises(Invalid):
            probe.routed({'inbounds': [inbound]})

    def test_routed_probe_prefers_existing_socks(self):
        probe = Probe({})
        account = {'user': 'local', 'pass': 'local-secret'}
        with patch.object(probe, 'curl', return_value=True) as curl:
            self.assertTrue(probe.routed({'inbounds': [{'protocol': 'socks', 'listen': '127.0.0.1',
                'port': 1080, 'settings': {'accounts': [account]}}]}))
        curl.assert_called_once_with(1080, account)

    def test_mixed_feed_skips_invalid_and_deduplicates_names(self):
        raw = '\n'.join([fixtures.URI, fixtures.URI.replace('#Node', '#Other'),
                         'trojan://other', fixtures.URI.replace('security=reality', 'security=none'),
                         'vless://broken'])
        batches, skipped = free_batches(raw.encode())
        self.assertEqual(len(batches), 1)
        self.assertEqual(len(batches[0][1]), 1)
        self.assertEqual(skipped, 4)
        self.assertEqual(free_batches(base64.b64encode(raw.encode())), (batches, skipped))

    def test_batches_respect_limit(self):
        raw = '\n'.join(fixtures.URI.replace('example.com:443', f'host{i}.example.com:443') for i in range(257))
        batches, skipped = free_batches(raw.encode())
        self.assertEqual([len(nodes) for _, nodes in batches], [128, 128, 1])
        self.assertEqual(skipped, 0)

    def test_no_vless_empty_invalid_encoding_and_oversize(self):
        for raw in (b'', b'vmess://other', b'vless://bad', b'\xff', b'x' * (LIMIT + 1)):
            with self.subTest(raw=raw[:20]), self.assertRaises(Invalid):
                free_batches(raw)

    def test_network_failure_has_distinct_type(self):
        probe = Probe({})
        with patch.object(probe, 'validate'), patch.object(probe, 'one', return_value=False):
            with self.assertRaises(NoWorkingNodes):
                probe.candidates([{}])
        with patch.object(probe, 'validate', side_effect=Invalid('configuration')):
            with self.assertRaises(Invalid) as cm:
                probe.candidates([{}])
            self.assertNotIsInstance(cm.exception, NoWorkingNodes)


class FallbackTest(unittest.TestCase):
    def setUp(self):
        fixtures.TransactionsTest.setUp(self)
        self.primary = copy.deepcopy(self.old)
        self.free = {**copy.deepcopy(self.old), 'url': FREE_URL, 'source': 'free'}
        self.free['nodes'][0]['settings']['vnext'][0]['address'] = 'free.example.com'
        self.free['body'] = import_body(json.dumps({'outbounds': self.free['nodes']}).encode())[0].decode()
        self.dead = set()
        self.manager.save_sources({'enabled': True, 'primary': self.primary, 'free': self.free,
                                   'catalog': {'free': {'name': 'Parsabrg/free_sub', 'url': FREE_URL, 'enabled': True}}})
        self.dns_patch = patch('backend.socket.getaddrinfo', return_value=[(2, 1, 6, '', ('1.1.1.1', 443))])
        self.dns_patch.start()
        self.runtime['inbounds'] = [{'protocol': 'socks', 'listen': '127.0.0.1', 'port': 1080}]
        atomic(self.root / 'runtime.json', self.runtime)
        self.probe.curl = lambda *args: False
        self.probe.routed = lambda runtime: self.probe.curl(1080)
        self.probe.candidates = self.candidates
        self.probe.wait = self.wait_runtime
        self.clock = patch('backend.time.time', return_value=1000)
        self.now = self.clock.start()

    def tearDown(self):
        self.dns_patch.stop()
        self.clock.stop()
        fixtures.TransactionsTest.tearDown(self)

    def candidates(self, nodes):
        good = sum(n['settings']['vnext'][0]['address'] not in self.dead for n in nodes)
        if not good:
            raise NoWorkingNodes('dead')
        return good

    def wait_runtime(self, record, guard):
        runtime = copy.deepcopy(self.runtime)
        runtime['outbounds'] = [{**copy.deepcopy(n), 'tag': 'pixel-' + str(i)} for i, n in enumerate(record['nodes'])]
        atomic(self.root / 'runtime.json', runtime)
        return runtime

    def tick(self, now):
        self.now.return_value = now
        self.manager.health_tick()

    def test_migration_defaults_to_primary_and_disabled(self):
        (self.root / 'sources.json').unlink()
        manager = Manager(self.config, self.panel, self.probe)
        self.assertFalse(manager.sources['enabled'])
        self.assertEqual(manager.sources['primary']['url'], self.old['url'])
        self.assertIsNone(manager.sources['free'])

    def test_two_failures_switch_and_two_successes_return(self):
        atomic(self.root / 'previous.json', {'url': 'historical'})
        self.dead.add('example.com')
        self.tick(1000)
        self.assertEqual(self.panel.refreshes, 0)
        self.tick(1059)
        self.assertEqual(self.panel.refreshes, 0)
        self.tick(1060)
        self.assertEqual(self.manager.active['source'], 'free')
        self.dead.clear()
        self.tick(1120)
        self.assertEqual(self.manager.active['source'], 'free')
        self.tick(1180)
        self.assertEqual(self.manager.active['source'], 'primary')
        self.assertEqual(json.loads((self.root / 'previous.json').read_text())['url'], 'historical')

    def test_one_working_primary_prevents_fallback(self):
        other = copy.deepcopy(self.primary['nodes'][0])
        other['settings']['vnext'][0]['address'] = 'working.example.com'
        self.manager.sources['primary']['nodes'].append(other)
        self.dead.add('example.com')
        self.tick(1000)
        self.tick(1060)
        self.assertEqual(self.panel.refreshes, 0)

    def test_live_success_avoids_expensive_full_check(self):
        self.probe.curl = lambda *args: True
        with patch.object(self.probe, 'candidates') as check:
            self.tick(1000)
            check.assert_not_called()

    def test_transient_failure_resets_confirmation(self):
        self.dead.add('example.com')
        self.tick(1000)
        self.dead.clear()
        self.tick(1060)
        self.dead.add('example.com')
        self.tick(1120)
        self.assertEqual(self.panel.refreshes, 0)

    def test_api_error_does_not_count_as_failure(self):
        self.dead.add('example.com')
        with patch.object(self.panel, 'preflight', side_effect=Invalid('api')), self.assertRaises(Invalid):
            self.tick(1000)
        self.tick(1060)
        self.assertEqual(self.panel.refreshes, 0)

    def test_api_error_between_failures_resets_confirmation(self):
        self.dead.add('example.com')
        self.tick(1000)
        with patch.object(self.panel, 'preflight', side_effect=Invalid('api')), self.assertRaises(Invalid):
            self.tick(1060)
        self.tick(1120)
        self.assertEqual(self.panel.refreshes, 0)

    def test_missing_or_changed_runtime_is_not_network_failure(self):
        self.dead.add('example.com')
        self.runtime['outbounds'] = []
        atomic(self.root / 'runtime.json', self.runtime)
        with self.assertRaises(Invalid):
            self.tick(1000)
        self.assertIsNone(self.manager.health_result)
        self.assertEqual(self.panel.refreshes, 0)

    def test_probe_configuration_error_resets_confirmation(self):
        self.dead.add('example.com')
        self.tick(1000)
        with patch.object(self.probe, 'candidates', side_effect=Invalid('config')), self.assertRaises(Invalid):
            self.tick(1060)
        self.tick(1120)
        self.assertEqual(self.panel.refreshes, 0)

    def test_failed_reserve_keeps_configuration(self):
        self.dead.update(('example.com', 'free.example.com'))
        self.tick(1000)
        with patch('backend.fetch', side_effect=Invalid('offline')):
            self.tick(1060)
        self.assertEqual(self.manager.active['url'], self.old['url'])
        self.assertEqual(self.panel.refreshes, 0)

    def test_disabled_reserve_never_switches(self):
        self.manager.sources['enabled'] = False
        self.dead.add('example.com')
        self.tick(1000)
        self.tick(1060)
        self.assertEqual(self.panel.refreshes, 0)

    def test_healthy_manual_primary_is_kept(self):
        self.manager.select_node(self.manager.node_id(self.primary['nodes'][0]), 'primary')
        self.tick(1000)
        self.tick(1060)
        self.assertEqual(self.manager.selection['id'], self.manager.node_id(self.primary['nodes'][0]))
        self.assertEqual(self.panel.refreshes, 0)

    def allow_manual_free(self):
        self.dead.add('example.com')
        self.manager.health_result = 'primary-dead'
        self.manager.health_since = 900

    def test_manual_free_node_and_explicit_auto_return(self):
        self.allow_manual_free()
        node_id = self.manager.node_id(self.free['nodes'][0])
        self.manager.select_node(node_id, 'free')
        self.assertEqual(self.manager.active['source'], 'free')
        self.assertEqual(self.manager.selection, {'id': node_id, 'source': 'free'})
        self.assertEqual(self.panel.target, 'pixel-0')
        self.dead.clear()
        self.manager.select_node(None)
        self.assertEqual(self.manager.active['source'], 'primary')
        self.assertIsNone(self.manager.selection['id'])

    def test_failed_cross_source_selection_restores_everything(self):
        self.allow_manual_free()
        with patch.object(self.probe, 'live', side_effect=Invalid('bad')), self.assertRaises(Invalid):
            self.manager.select_node(self.manager.node_id(self.free['nodes'][0]), 'free')
        self.assertEqual(self.manager.active['url'], self.old['url'])
        self.assertEqual(self.manager.selection, {'id': None})
        self.assertEqual(self.manager.sources['primary'], self.primary)

    def test_inactive_refresh_never_switches(self):
        with patch('backend.fetch', return_value=self.free['body'].encode()), patch.object(self.manager, 'prepare_record', return_value=(copy.deepcopy(self.free), self.panel.preflight())):
            self.manager.refresh_source('free')
        self.assertEqual(self.panel.refreshes, 0)
        self.assertEqual(self.manager.active['url'], self.old['url'])

    def test_refresh_keeps_missing_manual_node_until_auto(self):
        node_id = self.manager.node_id(self.primary['nodes'][0])
        self.manager.select_node(node_id)
        replacement = copy.deepcopy(self.primary)
        replacement['nodes'][0]['settings']['vnext'][0]['address'] = 'new.example.com'
        with patch('backend.fetch', return_value=fixtures.URI.encode()), patch.object(self.manager, 'prepare_record', return_value=(replacement, self.panel.preflight())):
            self.manager.refresh_source('primary')
        self.assertEqual(self.manager.selection['id'], node_id)
        self.assertEqual(self.manager.active['nodes'], self.old['nodes'])
        self.assertEqual(self.manager.sources['primary']['nodes'], replacement['nodes'])
        self.assertIn('прежняя конфигурация', self.manager.state()['message'])
        self.assertTrue(self.manager.state()['pinned_missing'])
        self.manager.select_node(None)
        self.assertEqual(self.manager.active['nodes'], replacement['nodes'])

    def test_new_cached_node_can_be_selected_while_old_node_is_pinned(self):
        self.manager.select_node(self.manager.node_id(self.primary['nodes'][0]))
        replacement = copy.deepcopy(self.primary)
        replacement['nodes'][0]['settings']['vnext'][0]['address'] = 'new.example.com'
        self.manager.sources['primary'] = replacement
        node_id = self.manager.node_id(replacement['nodes'][0])
        self.manager.select_node(node_id, 'primary')
        self.assertEqual(self.manager.selection['id'], node_id)
        self.assertEqual(self.manager.active['nodes'], replacement['nodes'])

    def test_settings_persist_even_when_initial_fetch_fails(self):
        self.manager.sources['enabled'] = False
        self.manager.sources['free'] = None
        self.manager.lock.acquire()
        with patch('backend.fetch', side_effect=Invalid('offline')):
            self.manager.run('settings', {'enabled': True})
        restarted = Manager(self.config, self.panel, self.probe)
        self.assertTrue(restarted.sources['enabled'])
        self.assertIsNone(restarted.sources['free'])

    def test_disabling_on_free_keeps_current_exit_and_allows_return(self):
        self.manager.apply(self.free, self.panel.preflight(), source='free', remember_previous=False)
        self.manager.lock.acquire()
        self.manager.run('settings', {'enabled': False})
        self.assertEqual(self.manager.active['source'], 'free')
        self.tick(1000)
        self.tick(1060)
        self.assertEqual(self.manager.active['source'], 'primary')

    def test_manual_replacement_does_not_inherit_free_pin(self):
        self.allow_manual_free()
        self.manager.select_node(self.manager.node_id(self.free['nodes'][0]), 'free')
        self.manager.apply(self.primary, self.panel.preflight())
        self.assertEqual(self.manager.active['source'], 'primary')
        self.assertIsNone(self.manager.selection['id'])

    def test_download_failure_preserves_both_caches(self):
        before = copy.deepcopy(self.manager.sources)
        with patch('backend.fetch', side_effect=Invalid('offline')):
            for source in ('primary', 'free'):
                with self.assertRaises(Invalid):
                    self.manager.refresh_source(source)
        self.assertEqual(self.manager.sources['primary'], before['primary'])
        self.assertEqual(self.manager.sources['free'], before['free'])
        self.assertEqual(self.manager.catalog()['free']['next_refresh'], 1000 + 12 * 3600)
        self.assertTrue(self.manager.state()['sources']['free']['error'])

    def test_background_refresh_is_independent_and_runs_in_manual_mode(self):
        self.manager.selection = {'id': 'pinned', 'source': 'primary'}
        self.manager.sources['enabled'] = False
        with patch.object(self.manager, 'refresh_source', side_effect=[Invalid('primary offline'), None]) as refresh:
            self.manager.refresh_sources()
        self.assertEqual([call.args[0] for call in refresh.call_args_list], ['primary', 'free'])

    def test_pending_recovery_stops_further_source_updates(self):
        def fail(source):
            self.manager.recovery_needed = True
            raise Invalid('pending')
        with patch.object(self.manager, 'refresh_source', side_effect=fail) as refresh:
            self.manager.refresh_sources()
        refresh.assert_called_once_with('primary')

    def test_free_batches_continue_after_dead_first_group(self):
        raw = '\n'.join(fixtures.URI.replace('example.com:443', f'host{i}.example.com:443') for i in range(129)).encode()
        calls = []
        def prepare(url, profile, body, nodes):
            calls.append(len(nodes))
            if len(calls) == 1:
                raise NoWorkingNodes('dead')
            return {**self.free, 'nodes': nodes, 'body': body.decode()}, self.panel.preflight()
        with patch('backend.fetch', return_value=raw), patch.object(self.manager, 'prepare_record', side_effect=prepare):
            self.manager.refresh_source('free')
        self.assertEqual(calls, [128, 1])

    def test_restart_restores_sources_and_manual_free_choice(self):
        self.allow_manual_free()
        self.manager.select_node(self.manager.node_id(self.free['nodes'][0]), 'free')
        restarted = Manager(self.config, self.panel, self.probe)
        self.assertEqual(restarted.active['source'], 'free')
        self.assertEqual(restarted.sources, self.manager.sources)
        self.assertEqual(restarted.selection, self.manager.selection)

    def test_crash_recovery_restores_source_registry(self):
        old_sources = copy.deepcopy(self.manager.sources)
        pending = {'old': self.old, 'new': self.free, 'guard': 'guard', 'selection': {'id': None}, 'sources': old_sources}
        atomic(self.root / 'pending.json', pending)
        atomic(self.root / 'active.json', self.free)
        self.manager.sources['primary'] = self.free
        atomic(self.root / 'sources.json', self.manager.sources)
        restarted = Manager(self.config, self.panel, self.probe)
        self.assertEqual(restarted.sources, old_sources)
        restarted.restore(pending)
        self.assertEqual(restarted.active, self.old)
        self.assertFalse(restarted.recovery_needed)

    def test_status_groups_sources_without_credentials(self):
        state = self.manager.state()
        self.assertEqual({n['source'] for n in state['connections']}, {'primary', 'free'})
        for secret in ('vless://', 'publicKey', FREE_URL, '00000000-0000-4000-8000-000000000001'):
            self.assertNotIn(secret, json.dumps(state))


class FallbackHTTPTest(fixtures.HTTPTest):
    def test_new_actions_validate_and_require_csrf(self):
        _, headers, _ = self.request('POST', '/api/login', {'password': 'test-password'})
        cookie = {'Cookie': headers['Set-Cookie'].split(';')[0]}
        _, _, raw = self.request('GET', '/api/status', headers=cookie)
        auth = {**cookie, 'X-CSRF-Token': json.loads(raw)['csrf']}
        for action in ('settings', 'refresh-free'):
            self.assertEqual(self.request('POST', '/api/' + action, {'enabled': True}, cookie)[0], 403)
        self.assertEqual(self.request('POST', '/api/settings', {'enabled': 'yes'}, auth)[0], 400)
        self.assertEqual(self.request('POST', '/api/select', {'id': None, 'source': 'unknown'}, auth)[0], 400)
        with patch.object(self.manager, 'submit') as submit:
            self.assertEqual(self.request('POST', '/api/settings', {'enabled': True}, auth)[0], 202)
            submit.assert_called_with('settings', {'enabled': True})
            self.assertEqual(self.request('POST', '/api/refresh-free', {}, auth)[0], 202)

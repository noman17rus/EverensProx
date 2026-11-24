"""Emergency egress is independent of subscription caches and manual pins."""
import contextlib
import hashlib
import json
import subprocess
import threading
import unittest
from unittest.mock import MagicMock, patch

import test_fallback as fixtures
import test_manager as http_fixtures
from backend import Manager, Probe, atomic
from configure_warp import provision, read_profile, register
from formats import Invalid
from warp import TAG, PROBE_TAG, PROBE_PORT, Warp


class WarpTest(unittest.TestCase):
    candidates = fixtures.FallbackTest.candidates
    tick = fixtures.FallbackTest.tick
    tearDown = fixtures.FallbackTest.tearDown

    def wait_runtime(self, record, guard):
        runtime = fixtures.FallbackTest.wait_runtime(self, record, guard)
        runtime['outbounds'].append(self.node)
        atomic(self.root / 'runtime.json', runtime)
        return runtime

    def setUp(self):
        fixtures.FallbackTest.setUp(self)
        self.node = {'tag': TAG, 'protocol': 'wireguard', 'settings': {'secretKey': 'private-warp-key'}}
        self.runtime['outbounds'].append(self.node)
        atomic(self.root / 'runtime.json', self.runtime)
        self.warp = self.manager.warp
        self.checker = patch.object(self.warp, 'check', return_value={'healthy': True})
        self.check = self.checker.start()
        self.addCleanup(self.checker.stop)
        self.probe.routed = lambda runtime: self.panel.target == TAG or self.probe.curl(1080)

    def test_existing_installation_keeps_subscriptions_and_no_auto_opt_in(self):
        self.assertEqual(self.warp.state()['mode'], 'subscriptions')
        self.assertFalse(self.warp.fallback_enabled)
        self.assertEqual(self.panel.overrides, [])

    def test_manual_warp_works_without_subscription_nodes(self):
        self.manager.active['nodes'] = []
        self.manager.sources['primary']['nodes'] = []
        self.runtime['outbounds'] = [self.node]
        atomic(self.root / 'runtime.json', self.runtime)
        self.warp.choose('warp')
        self.manager.reconcile_selection()
        self.assertEqual(self.panel.target, TAG)
        self.assertEqual(self.warp.value['origin'], 'manual')
        self.assertFalse(self.warp.journal.exists())

    def test_manual_warp_does_not_return_when_subscriptions_recover(self):
        self.warp.choose('warp')
        with patch.object(self.manager, 'check_source_health') as health:
            self.tick(1060)
            self.tick(1120)
            health.assert_not_called()
        self.assertEqual(self.panel.target, TAG)

    def test_failed_manual_check_never_changes_exit(self):
        self.check.side_effect = Invalid('WARP blocked')
        with self.assertRaisesRegex(Invalid, 'blocked'):
            self.warp.choose('warp')
        self.assertEqual(self.panel.overrides, [])
        self.assertFalse(self.warp.is_active)

    def test_routed_failure_rolls_back_and_keeps_subscription_history(self):
        self.probe.routed = lambda runtime: False
        atomic(self.root / 'previous.json', {'url': 'historical'})
        with self.assertRaisesRegex(Invalid, 'Предыдущий режим восстановлен'):
            self.warp.choose('warp')
        self.assertEqual(self.panel.target, '')
        self.assertFalse(self.warp.is_active)
        self.assertFalse(self.warp.journal.exists())
        self.assertEqual(json.loads((self.root / 'previous.json').read_text())['url'], 'historical')

    def test_unconfirmed_rollback_is_retried_after_restart(self):
        self.probe.routed = lambda runtime: False
        real_override = self.panel.override
        def override(tag):
            if not tag:
                raise Invalid('API offline')
            real_override(tag)
        with patch.object(self.panel, 'override', side_effect=override), self.assertRaisesRegex(Invalid, 'журнал'):
            self.warp.choose('warp')
        self.assertTrue(self.warp.journal.exists())
        restarted = Manager(self.config, self.panel, self.probe)
        restarted.reconcile_selection()
        self.assertFalse(restarted.warp.journal.exists())
        self.assertEqual(self.panel.target, '')

    def test_restart_restores_manual_warp_and_keeps_pin(self):
        pin = {'id': self.manager.node_id(self.primary['nodes'][0]), 'source': 'primary'}
        self.manager.save_selection(pin)
        self.warp.choose('warp')
        restarted = Manager(self.config, self.panel, self.probe)
        self.panel.target = ''
        restarted.reconcile_selection()
        self.assertEqual(self.panel.target, TAG)
        self.assertEqual(restarted.selection, pin)

    def test_automatic_warp_is_last_and_requires_confirmed_failure(self):
        self.warp.settings(True)
        self.dead.add('example.com')
        self.tick(1000)
        self.tick(1060)
        self.assertEqual(self.manager.active['source'], 'free')
        self.check.assert_not_called()
        self.dead.add('free.example.com')
        self.tick(1120)
        self.tick(1180)
        self.assertEqual(self.panel.target, TAG)
        self.assertEqual(self.warp.value['origin'], 'auto')

    def test_return_from_automatic_warp_requires_two_successes(self):
        self.warp.switch('warp', 'auto')
        self.probe.curl = lambda *args: True
        self.tick(1060)
        self.assertTrue(self.warp.is_active)
        self.tick(1119)
        self.assertTrue(self.warp.is_active)
        self.tick(1120)
        self.assertFalse(self.warp.is_active)
        self.assertEqual(self.panel.target, '')

    def test_recovery_interrupted_by_error_requires_new_confirmation(self):
        self.warp.switch('warp', 'auto')
        self.tick(1060)
        with patch.object(self.manager, 'check_source_health', side_effect=Invalid('API')), self.assertRaises(Invalid):
            self.tick(1120)
        self.tick(1180)
        self.assertTrue(self.warp.is_active)

    def test_failed_warp_never_falls_back_to_direct(self):
        self.warp.choose('warp')
        self.check.side_effect = Invalid('offline')
        self.tick(1060)
        self.assertEqual(self.panel.target, TAG)
        self.assertIn('offline', self.manager.state()['message'])

    def test_automatic_warp_works_with_empty_subscription_caches(self):
        self.manager.active['nodes'] = []
        for source in ('primary', 'free'):
            self.manager.sources[source]['nodes'] = []
        self.runtime['outbounds'] = [self.node]
        atomic(self.root / 'runtime.json', self.runtime)
        self.warp.settings(True)
        self.tick(1000)
        self.assertFalse(self.warp.is_active)
        self.tick(1060)
        self.assertTrue(self.warp.is_active)

    def test_dead_pin_does_not_prevent_manual_return_to_working_subscription(self):
        self.manager.save_selection({'id': self.manager.node_id(self.primary['nodes'][0])})
        self.warp.choose('warp')
        self.probe.ms = None
        self.probe.curl = lambda *args: True
        self.warp.choose('subscriptions')
        self.assertFalse(self.warp.is_active)
        self.assertIsNone(self.manager.selection['id'])

    def test_disabled_free_source_does_not_prevent_last_resort_warp(self):
        self.manager.sources['enabled'] = False
        self.warp.settings(True)
        self.dead.add('example.com')
        self.tick(1000)
        self.tick(1060)
        self.assertTrue(self.warp.is_active)

    def test_control_failure_before_automatic_switch_preserves_subscriptions(self):
        self.warp.settings(True)
        self.dead.update(('example.com', 'free.example.com'))
        self.check.side_effect = Invalid('WARP offline')
        self.tick(1000)
        with self.assertRaisesRegex(Invalid, 'WARP offline'):
            self.tick(1060)
        self.assertFalse(self.warp.is_active)
        self.assertEqual(self.panel.target, '')

    def test_unchecked_feed_is_not_treated_as_a_confirmed_failure(self):
        self.warp.settings(True)
        self.manager.sources['free'] = None
        self.dead.add('example.com')
        self.tick(1000)
        with self.assertRaisesRegex(Invalid, 'первоначальной проверки'):
            self.tick(1060)
        self.assertFalse(self.warp.is_active)
        self.check.assert_not_called()

    def test_direct_control_route_cannot_hide_failure_of_all_subscriptions(self):
        self.probe.curl = lambda *args: True
        self.warp.settings(True)
        self.dead.update(('example.com', 'free.example.com'))
        self.tick(1000)
        self.tick(1060)
        self.assertTrue(self.warp.is_active)

    def test_pending_egress_recovery_blocks_new_mutations(self):
        atomic(self.warp.journal, {'old': self.warp.value, 'override': ''})
        with self.assertRaisesRegex(Invalid, 'Восстановление'):
            self.manager.submit('settings', {'enabled': False})
        self.assertFalse(self.manager.lock.locked())

    def test_unavailable_subscriptions_do_not_disable_warp_on_manual_return(self):
        self.warp.choose('warp')
        self.dead.update(('example.com', 'free.example.com'))
        with self.assertRaisesRegex(Invalid, 'Рабочих подписок нет'):
            self.warp.choose('subscriptions')
        self.assertEqual(self.panel.target, TAG)

    def test_background_refresh_does_not_replace_warp_override(self):
        self.warp.choose('warp')
        self.manager.apply(self.primary, self.panel.preflight())
        self.assertEqual(self.panel.target, TAG)
        self.assertTrue(self.warp.is_active)

    def test_node_selection_is_explicitly_disabled_during_warp(self):
        self.warp.choose('warp')
        with self.assertRaisesRegex(Invalid, 'Сначала переключите'):
            self.manager.select_node(None)

    def test_status_never_contains_warp_keys(self):
        self.assertNotIn('private-warp-key', json.dumps(self.manager.state()))
        self.assertTrue(self.manager.state()['egress']['configured'])

    def test_concurrent_configuration_change_refuses_switch(self):
        self.check.side_effect = lambda: self.panel.baseline.update(template='changed')
        with self.assertRaisesRegex(Invalid, 'изменились'):
            self.warp.choose('warp')
        self.assertFalse(self.warp.journal.exists())
        self.assertEqual(self.panel.overrides, [])


class WarpProbeTest(unittest.TestCase):
    setUp = WarpTest.setUp
    tearDown = WarpTest.tearDown
    candidates = WarpTest.candidates
    wait_runtime = WarpTest.wait_runtime

    def check_trace(self, text, returncode=0, resource=True):
        probe = Probe({})
        self.manager.probe = probe
        probe.slots = threading.BoundedSemaphore(1)
        response = subprocess.CompletedProcess([], returncode, text, '')
        with patch.object(probe, 'validate'), patch.object(probe, 'tunnel', return_value=contextlib.nullcontext(1080)), \
             patch.object(probe, 'curl', return_value=resource), patch('warp.subprocess.run', return_value=response) as run:
            try:
                return Warp.check(self.warp)
            finally:
                args = run.call_args.args[0]
                self.assertIn('--socks5-hostname', args)
                self.assertNotIn('--insecure', args)
                self.assertNotIn('private-warp-key', str(args))

    def test_trace_proves_warp_ip_and_control_resource(self):
        result = self.check_trace('warp=on\nip=1.1.1.1\n')
        self.assertTrue(result['healthy'])
        self.assertEqual(result['ip'], '1.1.1.1')

    def test_plain_cloudflare_connection_is_rejected(self):
        with self.assertRaisesRegex(Invalid, 'не подтвердил'):
            self.check_trace('warp=off\nip=1.1.1.1\n')
        self.assertFalse(self.warp.result['healthy'])

    def test_connected_tunnel_without_working_resource_is_rejected(self):
        with self.assertRaisesRegex(Invalid, 'контрольные ресурсы'):
            self.check_trace('warp=plus\nip=1.1.1.1\n', resource=False)

    def test_invalid_trace_ip_is_not_shown_as_healthy(self):
        with self.assertRaisesRegex(Invalid, 'некорректный'):
            self.check_trace('warp=on\nip=<script>\n')

    def test_profile_is_userspace_only(self):
        path = self.root / 'wgcf.conf'
        path.write_text('[Interface]\nPrivateKey = private\nAddress = 172.16.0.2/32, fd00::2/128\n'
                        '[Peer]\nPublicKey = public\nEndpoint = engage.cloudflareclient.com:2408\n')
        node = read_profile(path)
        self.assertTrue(node['settings']['noKernelTun'])
        self.assertEqual(node['tag'], TAG)
        self.assertEqual(len(node['settings']['address']), 2)

    def test_active_probe_reuses_production_wireguard_session(self):
        self.warp.value['mode'] = 'warp'
        account = {'user': 'warp-check', 'pass': 'private-probe-secret'}
        self.runtime['inbounds'].append({'tag': PROBE_TAG, 'protocol': 'socks', 'listen': '127.0.0.1',
                                        'port': PROBE_PORT, 'settings': {'accounts': [account]}})
        self.runtime['routing'] = {'rules': [{'type': 'field', 'inboundTag': [PROBE_TAG], 'outboundTag': TAG}]}
        atomic(self.root / 'runtime.json', self.runtime)
        probe = Probe({})
        self.manager.probe = probe
        response = subprocess.CompletedProcess([], 0, 'warp=on\nip=1.1.1.1\n', '')
        with patch.object(probe, 'tunnel') as tunnel, patch.object(probe, 'curl', return_value=True) as curl, \
             patch('warp.subprocess.run', return_value=response) as run:
            self.assertTrue(Warp.check(self.warp)['healthy'])
            tunnel.assert_not_called()
            curl.assert_called_once_with(PROBE_PORT, account)
            self.assertNotIn(account['pass'], str(run.call_args.args))
            self.assertIn(account['pass'], run.call_args.kwargs['input'])

    def test_active_probe_never_starts_competing_wireguard_session(self):
        self.warp.value['mode'] = 'warp'
        probe = Probe({})
        self.manager.probe = probe
        with patch.object(probe, 'tunnel') as tunnel, self.assertRaisesRegex(Invalid, 'проверочный вход'):
            Warp.check(self.warp)
        tunnel.assert_not_called()

    def test_api_rule_before_probe_rule_is_safe(self):
        self.runtime['inbounds'].append({'tag': PROBE_TAG, 'protocol': 'socks', 'listen': '127.0.0.1', 'port': PROBE_PORT})
        self.runtime['routing'] = {'rules': [
            {'type': 'field', 'inboundTag': ['api'], 'outboundTag': 'api'},
            {'type': 'field', 'inboundTag': [PROBE_TAG], 'outboundTag': TAG}]}
        atomic(self.root / 'runtime.json', self.runtime)
        with self.warp.probe_tunnel(self.node) as (port, account):
            self.assertEqual(port, PROBE_PORT)

    def test_general_rule_before_probe_rule_is_rejected(self):
        self.runtime['inbounds'].append({'tag': PROBE_TAG, 'protocol': 'socks', 'listen': '127.0.0.1', 'port': PROBE_PORT})
        self.runtime['routing'] = {'rules': [
            {'type': 'field', 'network': 'tcp', 'outboundTag': 'direct'},
            {'type': 'field', 'inboundTag': [PROBE_TAG], 'outboundTag': TAG}]}
        atomic(self.root / 'runtime.json', self.runtime)
        with self.assertRaisesRegex(Invalid, 'Не подтверждён'), self.warp.probe_tunnel(self.node):
            pass

    def test_shared_route_probe_skips_warp_only_inbound(self):
        probe = Probe({})
        runtime = {'inbounds': [{'tag': PROBE_TAG, 'protocol': 'socks', 'listen': '127.0.0.1', 'port': PROBE_PORT},
                                {'tag': 'shared-socks', 'protocol': 'socks', 'listen': '127.0.0.1', 'port': 1080}]}
        with patch.object(probe, 'curl', return_value=True) as curl:
            self.assertTrue(probe.routed(runtime))
        curl.assert_called_once_with(1080, None)


class WarpHTTPTest(unittest.TestCase):
    setUp = http_fixtures.HTTPTest.setUp
    tearDown = http_fixtures.HTTPTest.tearDown
    request = http_fixtures.HTTPTest.request

    def login(self):
        _, headers, _ = self.request('POST', '/api/login', {'password': 'test-password'})
        cookie = headers['Set-Cookie'].split(';')[0]
        _, _, raw = self.request('GET', '/api/status', headers={'Cookie': cookie})
        return {'Cookie': cookie, 'X-CSRF-Token': json.loads(raw)['csrf']}

    def test_new_controls_require_session_csrf_and_same_origin(self):
        headers = self.login()
        for path, data in (('/api/egress', {'mode': 'warp'}), ('/api/warp-check', {}),
                           ('/api/warp-settings', {'enabled': True})):
            with self.subTest(path=path), patch.object(self.manager, 'submit') as submit:
                self.assertEqual(self.request('POST', path, data)[0], 401)
                self.assertEqual(self.request('POST', path, data, {'Cookie': headers['Cookie']})[0], 403)
                self.assertEqual(self.request('POST', path, data, {**headers, 'Origin': 'http://evil.example'})[0], 403)
                submit.assert_not_called()
                self.assertEqual(self.request('POST', path, data, headers)[0], 202)
                submit.assert_called_once_with(path.rsplit('/', 1)[1], data)

    def test_invalid_modes_and_boolean_settings_are_rejected(self):
        headers = self.login()
        for path, data in (('/api/egress', {'mode': 'direct'}), ('/api/egress', {}),
                           ('/api/warp-settings', {'enabled': 'true'}),
                           ('/api/warp-settings', {'enabled': 1})):
            with patch.object(self.manager, 'submit') as submit:
                self.assertEqual(self.request('POST', path, data, headers)[0], 400)
                submit.assert_not_called()


class ProvisionSafetyTest(unittest.TestCase):
    setUp = http_fixtures.TransactionsTest.setUp
    tearDown = http_fixtures.TransactionsTest.tearDown

    def test_failed_isolated_probe_never_updates_production(self):
        panel = MagicMock()
        panel.preflight.return_value = {'template': {'outbounds': []}}
        panel.call.return_value = {'xraySetting': {'outbounds': []}}
        backup = self.root / 'warp-backup'
        with patch('configure_warp.Panel', return_value=panel), \
             patch('configure_warp.Probe'), patch('configure_warp.Warp.check', side_effect=Invalid('offline')):
            with self.assertRaisesRegex(Invalid, 'offline'):
                provision(self.config, {'tag': TAG, 'protocol': 'wireguard'}, backup)
        self.assertFalse(backup.exists())
        panel.call.assert_called_once_with('xray/', {}, 'POST')

    def test_download_digest_mismatch_is_rejected_before_execution(self):
        raw = b'not-executable'
        name = 'wgcf_2.3.1_linux_amd64'
        release = {'assets': [{'name': name, 'browser_download_url': 'https://example.org/bin',
                               'digest': 'sha256:wrong'},
                              {'name': 'checksums.txt', 'browser_download_url': 'https://example.org/checksums'}]}
        checksum = hashlib.sha256(raw).hexdigest()
        with patch('configure_warp.platform.machine', return_value='x86_64'), \
             patch('configure_warp.download', side_effect=[json.dumps(release).encode(), raw,
                                                          (checksum + '  ' + name).encode()]), \
             patch('configure_warp.subprocess.run') as run:
            with self.assertRaisesRegex(Invalid, 'Контрольная сумма'):
                register(self.root)
        run.assert_not_called()
        self.assertFalse((self.root / 'wgcf').exists())


if __name__ == '__main__':
    unittest.main()

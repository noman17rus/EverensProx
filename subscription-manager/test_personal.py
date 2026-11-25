"""Ordered private subscriptions precede public fallback feeds."""
import copy
import json
import unittest
from unittest.mock import patch

import test_fallback as fixtures
from backend import Manager, NoWorkingNodes
from formats import Invalid


class PersonalTest(unittest.TestCase):
    setUp = fixtures.FallbackTest.setUp
    tearDown = fixtures.FallbackTest.tearDown
    candidates = fixtures.FallbackTest.candidates
    wait_runtime = fixtures.FallbackTest.wait_runtime
    tick = fixtures.FallbackTest.tick

    def add_personal(self, name='Backup'):
        self.manager.save_feed({'name': name, 'url': 'https://' + name.lower() + '.example.org/sub', 'kind': 'personal'})
        key = next(key for key, value in self.manager.catalog().items() if value['name'] == name)
        record = copy.deepcopy(self.primary)
        record['source'] = key
        record['url'] = self.manager.catalog()[key]['url']
        record['nodes'][0]['settings']['vnext'][0]['address'] = name.lower() + '.example.com'
        self.manager.sources[key] = record
        self.manager.save_sources(self.manager.sources)
        return key

    def test_ordered_chain_then_free_and_recovery(self):
        first, second = self.add_personal('First'), self.add_personal('Second')
        self.dead.add('example.com')
        self.tick(1000)
        self.assertEqual(self.panel.refreshes, 0)
        self.tick(1060)
        self.assertEqual(self.manager.active['source'], first)
        self.dead.add('first.example.com')
        self.tick(1120)
        self.tick(1180)
        self.assertEqual(self.manager.active['source'], second)
        self.dead.add('second.example.com')
        self.tick(1240)
        self.tick(1300)
        self.assertEqual(self.manager.active['source'], 'free')
        self.dead.remove('second.example.com')
        self.tick(1360)
        self.tick(1420)
        self.assertEqual(self.manager.active['source'], second)
        self.dead.clear()
        self.tick(1480)
        self.tick(1540)
        self.assertEqual(self.manager.active.get('source', 'primary'), 'primary')

    def test_personal_works_when_free_disabled(self):
        first = self.add_personal()
        self.manager.sources['enabled'] = False
        self.dead.add('example.com')
        self.tick(1000)
        self.tick(1060)
        self.assertEqual(self.manager.active['source'], first)
        self.dead.add('backup.example.com')
        self.tick(1120)
        self.tick(1180)
        self.assertEqual(self.manager.active['source'], first)

    def test_partial_failure_stays_on_same_subscription(self):
        first = self.add_personal()
        other = copy.deepcopy(self.primary['nodes'][0])
        other['settings']['vnext'][0]['address'] = 'healthy.example.com'
        self.manager.sources['primary']['nodes'].append(other)
        self.dead.add('example.com')
        self.tick(1000)
        self.tick(1060)
        self.assertEqual(self.panel.refreshes, 0)
        self.assertEqual(self.manager.active.get('source', 'primary'), 'primary')

    def test_move_disable_and_restart(self):
        first, second = self.add_personal('First'), self.add_personal('Second')
        self.manager.move_feed(second, 'up')
        self.assertEqual(self.manager.priority_ids(), ['primary', second, first, 'free'])
        self.manager.save_feed({'source': second, 'name': 'Second', 'enabled': False})
        restored = Manager(self.config, self.panel, self.probe)
        self.assertEqual(restored.priority_ids(), ['primary', first, 'free'])
        self.assertEqual(restored.catalog()[second]['kind'], 'personal')
        self.assertEqual(restored.feed_interval(first), 3600)
        self.assertEqual(restored.feed_interval('free'), 43200)

    def test_manual_free_cannot_skip_personal(self):
        self.add_personal()
        self.dead.add('example.com')
        with self.assertRaisesRegex(Invalid, 'более высоким приоритетом'):
            self.manager.select_node(self.manager.node_id(self.free['nodes'][0]), 'free')
        self.assertEqual(self.panel.refreshes, 0)

    def test_auto_does_not_skip_confirmation(self):
        self.add_personal()
        self.dead.add('example.com')
        self.manager.select_node(None)
        self.assertEqual(self.panel.refreshes, 0)

    def test_configuration_error_is_not_failed_subscription(self):
        self.add_personal()
        with patch.object(self.probe, 'candidates', side_effect=Invalid('API error')):
            with self.assertRaises(Invalid):
                self.tick(1000)
        self.assertIsNone(self.manager.health_result)
        self.assertEqual(self.panel.refreshes, 0)

    def test_recovery_during_scan_cancels_switch(self):
        self.add_personal()
        self.dead.add('example.com')
        self.tick(1000)
        original = self.manager.check_source_health
        def check(source):
            result = original(source)
            if source != 'primary':
                self.dead.clear()
            return result
        with patch.object(self.manager, 'check_source_health', side_effect=check):
            self.tick(1060)
        self.assertEqual(self.panel.refreshes, 0)

    def test_personal_refresh_is_strict_and_supports_profiles(self):
        key = self.add_personal()
        self.manager.save_feed({'source': key, 'name': 'Backup', 'profile': 1})
        node = self.primary['nodes'][0]
        raw = json.dumps([{'outbounds': [node]}, {'outbounds': [node]}]).encode()
        with patch('backend.fetch', return_value=raw), patch.object(self.manager, 'prepare_record', return_value=('record', 'baseline')) as prepare:
            self.assertEqual(self.manager.build_free_record(key, 'https://backup.example.org/sub'), ('record', 'baseline'))
            self.assertEqual(prepare.call_args.args[1], 1)
        with patch('backend.fetch', return_value=b'trojan://unsupported'):
            with self.assertRaises(Invalid):
                self.manager.build_free_record(key, 'https://backup.example.org/sub')

    def test_status_does_not_expose_private_subscription_url(self):
        key = self.add_personal()
        state = self.manager.state()
        self.assertEqual(state['catalog'][key]['kind'], 'personal')
        self.assertNotIn('backup.example.org', json.dumps(state))

    def test_initial_loading_does_not_skip_personal_or_block_worker(self):
        self.manager.save_feed({'name': 'Pending', 'url': 'https://pending.example.org/sub', 'kind': 'personal'})
        key = self.manager.personal_ids()[0]
        self.dead.add('example.com')
        self.tick(1000)
        self.tick(1060)
        self.assertEqual(self.panel.refreshes, 0)
        self.manager.catalog()['free']['next_refresh'] = 9999
        with patch('backend.threading.Thread') as thread:
            self.manager.poll_free_refresh()
        self.assertEqual(self.manager.refresh_job['source'], key)
        thread.return_value.start.assert_called_once()

    def test_failed_refresh_keeps_personal_cache(self):
        key = self.add_personal()
        before = copy.deepcopy(self.manager.sources[key])
        with patch('backend.fetch', side_effect=Invalid('provider offline')):
            with self.assertRaises(Invalid):
                self.manager.refresh_source(key)
        self.assertEqual(self.manager.sources[key], before)
        self.assertEqual(self.manager.catalog()[key]['next_refresh'], 4600)

    def test_starred_node_is_kept_despite_faster_strategy_candidate(self):
        self.add_personal()
        node_id = self.manager.node_id(self.primary['nodes'][0])
        self.manager.select_node(node_id, 'primary')
        self.assertEqual(self.panel.target, 'pixel-node-1')
        self.probe.routed = lambda runtime: True
        # The balancer strategy keeps suggesting another node; override wins.
        self.manager.measurements['primary:' + node_id] = {'latency': 110, 'measured': 1000}
        with patch.object(self.probe, 'latency', return_value=100):
            self.tick(1000)
            self.tick(1060)
            self.manager.reconcile_selection()
        self.assertEqual(self.manager.selection['id'], node_id)
        self.assertEqual(self.panel.target, 'pixel-node-1')
        self.assertEqual(self.manager.state()['connection']['selected'], ['pixel-node-1'])
        self.assertEqual(self.panel.refreshes, 0)

    def test_failed_star_uses_other_nodes_and_keeps_preference(self):
        self.add_personal()
        node_id = self.manager.node_id(self.primary['nodes'][0])
        self.manager.select_node(node_id, 'primary')
        other = copy.deepcopy(self.primary['nodes'][0])
        other['settings']['vnext'][0]['address'] = 'healthy.example.com'
        self.manager.sources['primary']['nodes'].append(other)
        self.dead.add('example.com')
        with patch.object(self.probe, 'latency', return_value=None):
            self.tick(1000)
        self.assertEqual(self.manager.selection['id'], node_id)
        self.assertTrue(self.manager.state()['pin_suspended'])
        self.assertEqual(self.panel.target, '')
        self.assertEqual(self.manager.active.get('source', 'primary'), 'primary')
        self.assertEqual(len(self.manager.active['nodes']), 2)

    def test_priority_node_is_restored_after_recovery(self):
        self.add_personal()
        node_id = self.manager.node_id(self.primary['nodes'][0])
        self.manager.select_node(node_id, 'primary')
        other = copy.deepcopy(self.primary['nodes'][0])
        other['settings']['vnext'][0]['address'] = 'healthy.example.com'
        self.manager.sources['primary']['nodes'].append(other)
        self.dead.add('example.com')
        with patch.object(self.probe, 'latency', side_effect=[None, 100]):
            self.tick(1000)
            self.assertTrue(self.manager.state()['pin_suspended'])
            self.assertEqual(self.panel.target, '')
            self.tick(1060)
        self.assertFalse(self.manager.state()['pin_suspended'])
        self.assertEqual(self.manager.state()['mode'], 'manual')
        restored = next(n['tag'] for n in self.manager.runtime_nodes()
                        if self.manager.node_id(n) == node_id)
        self.assertEqual(self.panel.target, restored)


    def test_primary_pin_survives_full_outage_and_returns(self):
        node_id = self.manager.node_id(self.primary['nodes'][0])
        self.manager.select_node(node_id, 'primary')
        self.dead.add('example.com')
        with patch.object(self.probe, 'latency', side_effect=[None, None, 100]):
            self.tick(1000)
            self.tick(1060)
            self.assertEqual(self.manager.active.get('source'), 'free')
            self.assertEqual(self.manager.selection['id'], node_id)
            self.assertTrue(self.manager.state()['pin_suspended'])
            self.dead.clear()
            self.tick(1120)
            self.tick(1180)
            self.assertEqual(self.manager.active.get('source', 'primary'), 'primary')
            self.tick(1240)
        self.assertFalse(self.manager.state()['pin_suspended'])
        self.assertEqual(self.manager.state()['mode'], 'manual')
        restored = next(n['tag'] for n in self.manager.runtime_nodes()
                        if self.manager.node_id(n) == node_id)
        self.assertEqual(self.panel.target, restored)


if __name__ == '__main__':
    unittest.main()

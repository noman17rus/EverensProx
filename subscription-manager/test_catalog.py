"""Priority, multi-source state, refresh scheduling and background isolation."""
import copy
import json
import threading
import unittest
from unittest.mock import patch

from backend import FREE_INTERVAL, Manager, NoWorkingNodes, atomic
from formats import Invalid
import test_fallback as fallback_fixtures
import test_manager as manager_fixtures


class CatalogTest(unittest.TestCase):
    setUp = fallback_fixtures.FallbackTest.setUp
    tearDown = fallback_fixtures.FallbackTest.tearDown
    candidates = fallback_fixtures.FallbackTest.candidates
    wait_runtime = fallback_fixtures.FallbackTest.wait_runtime
    tick = fallback_fixtures.FallbackTest.tick
    allow_manual_free = fallback_fixtures.FallbackTest.allow_manual_free
    def add_reserve(self):
        self.manager.save_feed({'name': 'Second', 'url': 'https://feed.example.org/sub'})
        key = next(k for k in self.manager.catalog() if k != 'free')
        record = copy.deepcopy(self.free)
        record['nodes'][0]['settings']['vnext'][0]['address'] = 'second.example.com'
        record['source'] = key
        self.manager.sources[key] = record
        return key

    def test_manual_free_rejected_while_any_primary_works(self):
        with self.assertRaisesRegex(Invalid, 'Основная подписка работает'):
            self.manager.select_node(self.manager.node_id(self.free['nodes'][0]), 'free')
        self.assertEqual(self.panel.refreshes, 0)

    def test_manual_free_requires_confirmed_failure(self):
        self.dead.add('example.com')
        with self.assertRaisesRegex(Invalid, 'двумя проверками'):
            self.manager.select_node(self.manager.node_id(self.free['nodes'][0]), 'free')
        self.assertEqual(self.panel.refreshes, 0)

    def test_auto_button_cannot_bypass_primary_failure_confirmation(self):
        self.dead.add('example.com')
        self.manager.select_node(None)
        self.assertEqual(self.panel.refreshes, 0)

    def test_dead_manual_primary_clears_pin_before_reserve(self):
        self.manager.select_node(self.manager.node_id(self.primary['nodes'][0]))
        other = copy.deepcopy(self.primary['nodes'][0])
        other['settings']['vnext'][0]['address'] = 'other.example.com'
        self.manager.sources['primary']['nodes'].append(other)
        self.dead.add('example.com')
        with patch.object(self.probe, 'latency', return_value=None):
            self.tick(1000)
        self.assertIsNone(self.manager.selection['id'])
        self.assertEqual(self.manager.active['source'], 'primary')
        self.assertEqual(len(self.manager.active['nodes']), 2)

    def test_dead_manual_primary_can_reach_reserve(self):
        self.manager.select_node(self.manager.node_id(self.primary['nodes'][0]))
        self.dead.add('example.com')
        with patch.object(self.probe, 'latency', return_value=None):
            self.tick(1000)
            self.tick(1060)
        self.assertEqual(self.manager.active['source'], 'free')

    def test_manual_free_does_not_block_return_to_primary(self):
        self.allow_manual_free()
        self.manager.select_node(self.manager.node_id(self.free['nodes'][0]), 'free')
        self.dead.clear()
        self.tick(1000)
        self.tick(1060)
        self.assertEqual(self.manager.active['source'], 'primary')
        self.assertIsNone(self.manager.selection['id'])

    def test_second_feed_works_when_first_feed_is_dead(self):
        key = self.add_reserve()
        self.dead.update(('example.com', 'free.example.com'))
        self.tick(1000)
        self.tick(1060)
        self.assertEqual(self.manager.active['source'], key)

    def test_disabled_feed_is_never_selected(self):
        key = self.add_reserve()
        self.manager.catalog()[key]['enabled'] = False
        self.dead.update(('example.com', 'free.example.com'))
        self.tick(1000)
        self.tick(1060)
        self.assertEqual(self.panel.refreshes, 0)

    def test_free_exit_failure_uses_another_feed(self):
        key = self.add_reserve()
        self.manager.apply(self.free, self.panel.preflight(), source='free', remember_previous=False)
        self.dead.update(('example.com', 'free.example.com'))
        self.tick(1000)
        self.assertEqual(self.manager.active['source'], key)

    def test_primary_recovery_during_reserve_scan_cancels_switch(self):
        self.dead.add('example.com')
        self.tick(1000)
        original = self.manager.reserve_target
        def restored():
            target = original()
            self.dead.clear()
            return target
        with patch.object(self.manager, 'reserve_target', side_effect=restored):
            self.tick(1060)
        self.assertEqual(self.panel.refreshes, 0)

    def test_catalog_edit_delete_and_active_protection(self):
        key = self.add_reserve()
        self.manager.save_feed({'source': key, 'name': 'Renamed', 'enabled': False})
        self.assertFalse(self.manager.catalog()[key]['enabled'])
        self.manager.delete_feed(key)
        self.assertNotIn(key, self.manager.catalog())
        self.manager.apply(self.free, self.panel.preflight(), source='free', remember_previous=False)
        with self.assertRaises(Invalid):
            self.manager.delete_feed('free')
        with self.assertRaises(Invalid):
            self.manager.save_feed({'source': 'free', 'name': 'Free', 'enabled': False})

    def test_source_filter_checks_only_requested_feed(self):
        key = self.add_reserve()
        with patch.object(self.probe, 'latency', return_value=10) as latency:
            self.manager.measure_nodes(source=key)
        self.assertEqual(latency.call_count, 1)

    def test_migration_preserves_active_primary_and_previous(self):
        before = (self.root / 'active.json').read_bytes()
        atomic(self.root / 'previous.json', {'historical': True})
        atomic(self.root / 'sources.json', {'enabled': True, 'primary': self.primary, 'free': self.free})
        migrated = Manager(self.config, self.panel, self.probe)
        self.assertEqual(len(migrated.catalog()), 5)
        self.assertEqual(migrated.sources['free'], self.free)
        self.assertEqual((self.root / 'active.json').read_bytes(), before)
        self.assertEqual(json.loads((self.root / 'previous.json').read_text()), {'historical': True})

    def test_background_download_does_not_hold_operation_lock(self):
        entered, finish = threading.Event(), threading.Event()
        self.manager.schedule_free('free')
        def build(*args):
            entered.set()
            finish.wait(3)
            return copy.deepcopy(self.free), self.panel.preflight()
        with patch.object(self.manager, 'build_free_record', side_effect=build):
            self.manager.poll_free_refresh()
            self.assertTrue(entered.wait(2))
            self.assertTrue(self.manager.lock.acquire(False))
            self.manager.lock.release()
            self.assertFalse(self.manager.state()['busy'])
            finish.set()
            # Join the worker through its explicit test event.
            for thread in threading.enumerate():
                if thread.name.endswith('(free_worker)'):
                    thread.join(3)
            self.manager.poll_free_refresh()
        self.assertEqual(self.panel.refreshes, 0)
        self.assertEqual(self.manager.catalog()['free']['next_refresh'], 1000 + FREE_INTERVAL)
        restarted = Manager(self.config, self.panel, self.probe)
        self.assertEqual(restarted.catalog()['free']['next_refresh'], 1000 + FREE_INTERVAL)

    def test_background_error_keeps_cache_and_advances_schedule(self):
        feed = copy.deepcopy(self.manager.catalog()['free'])
        self.manager.refresh_job = {'source': 'free', 'feed': feed, 'done': True, 'error': 'offline'}
        self.manager.poll_free_refresh()
        self.assertEqual(self.manager.sources['free'], self.free)
        self.assertEqual(self.manager.catalog()['free']['next_refresh'], 1000 + FREE_INTERVAL)
        self.assertIn('offline', self.manager.source_status['free']['error'])
        restarted = Manager(self.config, self.panel, self.probe)
        self.assertIn('offline', restarted.state()['sources']['free']['error'])

    def test_stale_background_result_is_discarded(self):
        key = self.add_reserve()
        old = copy.deepcopy(self.manager.catalog()[key])
        self.manager.save_feed({'source': key, 'name': 'Second', 'url': 'https://changed.example.org/sub'})
        self.manager.refresh_job = {'source': key, 'feed': old, 'done': True,
                                    'result': (copy.deepcopy(self.free), self.panel.preflight())}
        with patch('backend.threading.Thread'):
            self.manager.poll_free_refresh()
        self.assertIsNone(self.manager.sources[key])

    def test_private_free_node_is_skipped(self):
        with patch('backend.fetch', return_value=self.free['body'].encode()), patch('backend.socket.getaddrinfo', return_value=[(2, 1, 6, '', ('127.0.0.1', 443))]):
            with self.assertRaises(NoWorkingNodes):
                self.manager.build_free_record('free', 'https://example.org/sub')


class CatalogHTTPTest(unittest.TestCase):
    setUp = manager_fixtures.HTTPTest.setUp
    tearDown = manager_fixtures.HTTPTest.tearDown
    request = manager_fixtures.HTTPTest.request
    def test_catalog_actions_require_csrf_and_validate_sources(self):
        _, headers, _ = self.request('POST', '/api/login', {'password': 'test-password'})
        cookie = {'Cookie': headers['Set-Cookie'].split(';')[0]}
        _, _, raw = self.request('GET', '/api/status', headers=cookie)
        auth = {**cookie, 'X-CSRF-Token': json.loads(raw)['csrf']}
        for action in ('save-source', 'delete-source', 'refresh-free', 'move-source'):
            self.assertEqual(self.request('POST', '/api/' + action, {}, cookie)[0], 403)
            self.assertEqual(self.request('POST', '/api/' + action, {'source': []}, auth)[0], 400)
        with patch.object(self.manager, 'submit') as submit:
            self.assertEqual(self.request('POST', '/api/save-source', {'name': 'New', 'url': 'https://example.org/sub'}, auth)[0], 202)
            self.assertEqual(submit.call_args.args[0], 'save-source')
            self.assertEqual(self.request('POST', '/api/move-source', {'source': 'free', 'direction': 'bad'}, auth)[0], 400)

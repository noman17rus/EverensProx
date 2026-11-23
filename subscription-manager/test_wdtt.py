import copy
import json
import unittest
from unittest.mock import Mock

from formats import Invalid
from wdtt import WdttUsers
from test_manager import HTTPTest


class UsersTest(unittest.TestCase):
    def setUp(self):
        self.api = WdttUsers({})
        self.user = {'password': 'private-client-password', 'label': 'Phone',
                     'vk_hash': 'hash', 'ports': '56000,56001,1080', 'status': 'active'}
        self.response = {'ok': True, 'password': self.user, 'passwords': [self.user],
                         'server': {'effective_public_ip': 'vpn.example.com',
                                    'admin_profile': {'secret': 'never-return'}}}
        self.api.call = Mock(side_effect=lambda args: copy.deepcopy(self.response))
        self.user_id = self.api.user_id(self.user['password'])

    def test_list_hides_credentials_and_owner_profile(self):
        listing = self.api.listing()
        self.assertEqual(listing['users'][0]['id'], self.user_id)
        self.assertNotIn('private-client-password', json.dumps(listing))
        self.assertNotIn('never-return', json.dumps(listing))
        self.assertNotIn('vk_hash', listing['users'][0])

    def test_details_link_is_encoded_and_only_selected_user_returned(self):
        self.user['label'] = '<script> & name'
        result = self.api.execute({'operation': 'details', 'id': self.user_id})
        self.assertIn('wdtt://connect?', result['user']['link'])
        self.assertIn('host=vpn.example.com', result['user']['link'])
        self.assertIn('%3Cscript%3E', result['user']['link'])
        self.assertNotIn('never-return', json.dumps(result))

    def test_stale_id_and_unlisted_commands_cannot_mutate(self):
        for data in ({'operation': 'delete', 'id': '0' * 64},
                     {'operation': 'restart'}, {'operation': 'backup-export'}):
            with self.assertRaises(Invalid):
                self.api.execute(data)
        self.assertTrue(all(c.args[0] == ['list'] for c in self.api.call.call_args_list))

    def test_invalid_inputs_do_not_issue_commands(self):
        for fields in ({'days': True}, {'days': 366}, {'days': -1},
                       {'days': 30, 'shared': 'true'}, {'days': 30, 'label': []},
                       {'days': 30, 'new_password': '0000000000000000'}):
            with self.assertRaises(Invalid):
                self.api.execute({'operation': 'create', **fields})
        self.api.call.assert_not_called()

    def test_dispatch_and_shared_access_are_preserved(self):
        self.api.execute({'operation': 'update', 'id': self.user_id, 'shared': True,
                          'label': 'New', 'vk_hash': 'hash', 'ports': self.user['ports']})
        args = self.api.call.call_args.args[0]
        self.assertEqual(args[:3], ['update-client', '--password', self.user['password']])
        self.assertIn('--shared=true', args)
        for operation in ('activate', 'deactivate', 'unbind', 'delete', 'set-expiry', 'set-password'):
            self.api.execute({'operation': operation, 'id': self.user_id, 'days': 0, 'new_password': 'Abcdefgh23456789'})
            self.assertEqual(self.api.call.call_args.args[0][0], operation)


class UsersHTTPTest(HTTPTest):
    def test_user_routes_require_session_origin_and_csrf(self):
        self.server.wdtt = Mock()
        self.server.wdtt.listing.return_value = {'users': []}
        self.server.wdtt.execute.return_value = {'message': 'done'}
        self.assertEqual(self.request('GET', '/api/wdtt/users')[0], 401)
        self.assertEqual(self.request('POST', '/api/wdtt/user', {'operation': 'delete'})[0], 401)
        _, headers, _ = self.request('POST', '/api/login', {'password': 'test-password'})
        cookie = headers['Set-Cookie'].split(';')[0]
        auth = {'Cookie': cookie}
        _, _, raw = self.request('GET', '/api/status', headers=auth)
        csrf = json.loads(raw)['csrf']
        self.assertEqual(self.request('GET', '/api/wdtt/users', headers=auth)[0], 200)
        self.assertEqual(self.request('POST', '/api/wdtt/user', {'operation': 'delete'}, auth)[0], 403)
        auth['X-CSRF-Token'] = csrf
        self.assertEqual(self.request('POST', '/api/wdtt/user', {}, dict(auth, Origin='http://evil.example'))[0], 403)
        self.server.wdtt.execute.assert_not_called()
        self.assertEqual(self.request('POST', '/api/wdtt/user', {'operation': 'details'}, auth)[0], 200)
        self.server.wdtt.execute.side_effect = Invalid('WDTT недоступен')
        self.assertEqual(self.request('POST', '/api/wdtt/user', {}, auth)[0], 400)

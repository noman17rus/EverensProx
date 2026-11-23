"""User administration through the running WDTT server's private admin socket."""
import hashlib
import json
import pathlib
import re
import socket
import threading
import urllib.parse

from formats import Invalid


class WdttUsers:
    def __init__(self, config):
        self.config = config
        self.lock = threading.Lock()

    def call(self, args):
        try:
            secret = pathlib.Path(self.config.get('wdtt_password_file',
                '/etc/everensprox-provisioning/wdtt-password')).read_text().strip()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(12)
                connection.connect(self.config.get('wdtt_socket', '/run/wdtt/admin.sock'))
                connection.sendall(json.dumps({'main_password': secret, 'args': args}).encode() + b'\n')
                with connection.makefile('rb') as stream:
                    raw = stream.readline(8 * 1024 * 1024 + 1)
                if len(raw) > 8 * 1024 * 1024:
                    raise ValueError()
                result = json.loads(raw)
        except (OSError, ValueError, KeyError):
            raise Invalid('Управление WDTT недоступно. Проверьте службу и настройки admin-сокета.') from None
        if result.get('ok') is not True:
            message = str(result.get('message') or 'WDTT отклонил операцию.')
            raise Invalid(message.replace(secret, '[секрет]')[:500])
        return result

    @staticmethod
    def user_id(password):
        return hashlib.sha256(password.encode()).hexdigest()

    def listing(self):
        with self.lock:
            result = self.call(['list'])
        users = []
        for entry in result.get('passwords') or []:
            user = dict(entry)
            user['id'] = self.user_id(user.pop('password'))
            user.pop('vk_hash', None)
            users.append(user)
        users.sort(key=lambda u: (u.get('label', '').casefold(), u['id']))
        info = result.get('server') or {}
        return {'users': users, 'limit': info.get('max_passwords'),
                'default_ports': info.get('default_ports', ''),
                'default_hash': self.config.get('wdtt_default_hash', '')}

    @staticmethod
    def text(data, key, limit=4096, default=''):
        value = data.get(key, default)
        if not isinstance(value, str) or len(value) > limit or '\x00' in value:
            raise Invalid('Некорректное поле: ' + key)
        return value.strip()

    @staticmethod
    def days(data):
        value = data.get('days')
        if type(value) is not int or not 0 <= value <= 365:
            raise Invalid('Срок должен быть от 0 до 365 дней; 0 — бессрочно.')
        return str(value)

    def client_password(self, data, required=False):
        value = self.text(data, 'new_password', 128)
        if (required or value) and not re.fullmatch(r'[ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789]{16}', value):
            raise Invalid('Пароль WDTT: ровно 16 латинских букв или цифр; символы I, O, i, l, o, 0 и 1 не допускаются.')
        return value

    def details(self, result):
        user = dict(result['password'])
        user['id'] = self.user_id(user['password'])
        info = result.get('server') or {}
        ports = user.get('ports', '').split(',')
        host = self.config.get('wdtt_public_host') or info.get('effective_public_ip') or info.get('public_ip')
        hashes = user.get('vk_hash')
        user['link'] = ''
        if host and hashes and len(ports) == 3:
            user['link'] = 'wdtt://connect?' + urllib.parse.urlencode({
                'v': '1', 'host': host, 'dtls': ports[0], 'wg': ports[1], 'local': ports[2],
                'password': user['password'], 'hashes': hashes, 'name': user.get('label') or 'WDTT'})
        return {'user': user}

    def execute(self, data):
        operation = data.get('operation')
        if operation not in ('details', 'create', 'update', 'set-password', 'set-expiry',
                             'activate', 'deactivate', 'unbind', 'delete'):
            raise Invalid('Неизвестная операция WDTT.')
        # Validate the entire command before making any mutation. The WDTT socket
        # serializes these commands with changes from the bot and provisioner.
        options = []
        if operation in ('create', 'update'):
            shared = data.get('shared', False)
            if type(shared) is not bool:
                raise Invalid('Некорректный тип доступа.')
            options = ['--label', self.text(data, 'label', 200), '--vk-hash',
                       self.text(data, 'vk_hash'), '--ports', self.text(data, 'ports', 100),
                       '--shared=' + str(shared).lower()]
        if operation == 'create':
            options += ['--days', self.days(data), '--client-password', self.client_password(data)]
        elif operation == 'set-password':
            value = self.client_password(data, required=True)
            options = ['--new-password', value]
        elif operation == 'set-expiry':
            options = ['--days', self.days(data)]
        with self.lock:
            if operation == 'create':
                result = self.call(['create'] + options)
            else:
                user_id = self.text(data, 'id', 64)
                listing = self.call(['list'])
                entry = next((u for u in listing.get('passwords') or []
                              if self.user_id(u['password']) == user_id), None)
                if entry is None:
                    raise Invalid('Пользователь уже удалён или пароль изменён. Обновите список.')
                command = 'update-client' if operation == 'update' else operation
                result = self.call([command, '--password', entry['password']] + options)
        if operation == 'delete':
            return {'message': 'Пользователь удалён.'}
        return dict(self.details(result), message=result.get('message', 'Готово.'))

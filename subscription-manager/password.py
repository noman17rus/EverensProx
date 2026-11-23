#!/usr/bin/env python3
import getpass
import json
import pathlib
import secrets

from backend import atomic
from server import password_hash

if __name__ == '__main__':
    password = getpass.getpass('Новый пароль (не менее 16 символов): ')
    if len(password) < 16 or password != getpass.getpass('Повторите пароль: '):
        raise SystemExit('Пароли не совпадают или слишком короткие.')
    path = pathlib.Path('/etc/everensprox-subscription/config.json')
    config = json.loads(path.read_text())
    config['password_salt'] = secrets.token_hex(16)
    config['password_hash'] = password_hash(password, config['password_salt'])
    atomic(path, config)
    print('Пароль обновлён. Перезапустите everensprox-subscription для завершения всех сессий.')

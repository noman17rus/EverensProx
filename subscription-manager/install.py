#!/usr/bin/env python3
"""Adopt the existing loopback bridge without rewriting Xray or client settings."""
import argparse
import json
import os
import pathlib
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import time
import urllib.parse
import urllib.request

from backend import Panel, Probe, atomic, digest
from server import password_hash


def run(*args):
    return subprocess.run(args, capture_output=True, text=True, check=True, timeout=60)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--address', required=True, help='Exact server LAN IPv4 address')
    parser.add_argument('--subnet', required=True)
    parser.add_argument('--port', type=int, default=19090)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run as root')
    import ipaddress
    address = ipaddress.ip_address(args.address)
    subnet = ipaddress.ip_network(args.subnet)
    if not address.is_private or address.is_unspecified or address not in subnet:
        raise SystemExit('Use an exact private LAN address inside --subnet')
    destination = pathlib.Path('/opt/everensprox-subscription')
    config_dir = pathlib.Path('/etc/everensprox-subscription')
    state_dir = pathlib.Path('/var/lib/everensprox-subscription')
    config_path = config_dir / 'config.json'
    # Deliberately refuse implicit upgrade/adoption of unknown state.
    if config_path.exists() or state_dir.exists():
        raise SystemExit('Already installed: follow the upgrade instructions, do not bootstrap again')
    for bind in [(args.address, args.port)]:
        with socket.socket() as sock:
            sock.bind(bind)
    db = sqlite3.connect('file:/etc/x-ui/x-ui.db?mode=ro', uri=True)
    settings = dict(db.execute('select key,value from settings'))
    db.close()
    if settings.get('webCertFile'):
        raise SystemExit('Panel TLS configured: configure a verified panel_url manually before adoption')
    panel_url = 'http://127.0.0.1:' + settings['webPort'] + '/' + settings.get('webBasePath', '').strip('/')
    source = json.loads(pathlib.Path('/etc/pixelartick-subscription.json').read_text())['url']
    cache_path = pathlib.Path('/var/lib/pixelartick-subscription/subscription.txt')
    body = cache_path.read_text()
    bootstrap_auth = '/opt/everensprox-monitoring/secrets/xui_auth.json'
    config = {'admin_host': args.address + ':' + str(args.port), 'lan_subnet': args.subnet,
              'state_dir': str(state_dir), 'panel_url': panel_url, 'panel_auth_file': bootstrap_auth,
              'runtime': '/usr/local/x-ui/bin/config.json', 'xray': '/usr/local/x-ui/bin/xray-linux-amd64',
              'xray_cwd': '/usr/local/x-ui', 'feed_url': 'http://127.0.0.1:19087/subscription',
              'tag_prefix': 'pixel-', 'test_urls': ['https://www.youtube.com/robots.txt', 'https://telegram.org/robots.txt'], 'refresh_interval': 3600}
    panel = Panel(config)
    subs = panel.call('xray/outbound-subs')
    matching = [s for s in subs if s['url'] == config['feed_url'] and s['tagPrefix'] == config['tag_prefix'] and s['enabled']]
    if len(matching) != 1:
        raise SystemExit('Expected exactly one existing loopback subscription with prefix pixel-')
    config['subscription_id'] = matching[0]['id']
    baseline = panel.preflight()
    runtime = json.loads(pathlib.Path(config['runtime']).read_text())
    nodes = [o for o in runtime['outbounds'] if o.get('tag', '').startswith(config['tag_prefix'])]
    probe = Probe(config)
    probe.validate(nodes)
    working = 0
    try:
        working = probe.candidates(nodes)
    except Exception:
        print('Existing provider is unavailable; preserving cached subscription for manual replacement.')
    if digest(panel.preflight()) != digest(baseline):
        raise SystemExit('Panel changed during preflight; rerun installer')
    print('Preflight passed: API, VLESS, WDTT, foreign-auto, loopback subscription and Xray.')
    # Backups contain credentials and never leave this host.
    backup = pathlib.Path('/root/everensprox-subscription-backup-' + time.strftime('%Y%m%d-%H%M%S'))
    backup.mkdir(mode=0o700)
    for path in [pathlib.Path('/etc/systemd/system/pixelartick-subscription.service'), pathlib.Path('/usr/local/lib/pixelartick-subscription/adapter.py'), pathlib.Path('/etc/pixelartick-subscription.json'), cache_path]:
        shutil.copy2(path, backup / path.name)
    atomic(backup / 'panel-before.json', baseline)
    run('systemctl', 'is-active', '--quiet', 'pixelartick-subscription')
    for directory in [config_dir, state_dir, destination]:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    source_dir = pathlib.Path(__file__).resolve().parent
    for name in ['server.py', 'backend.py', 'formats.py', 'index.html', 'password.py', 'wdtt.py', 'warp.py', 'configure_warp.py']:
        shutil.copy2(source_dir / name, destination / name)
    # Give the manager a separate API token so rotating monitoring does not break it.
    result = run('/usr/local/x-ui/x-ui', 'setting', '-getApiToken', '-tokenName', 'everensprox-subscription', '-tokenScope', 'admin')
    match = re.search(r'^apiToken:\s*(\S+)\s*$', result.stdout, re.MULTILINE)
    if not match:
        raise SystemExit('Could not create panel token; output withheld')
    atomic(config_dir / 'panel-auth.json', {'token': match.group(1)})
    config['panel_auth_file'] = str(config_dir / 'panel-auth.json')
    password = secrets.token_urlsafe(20)
    config['password_salt'] = secrets.token_hex(16)
    config['password_hash'] = password_hash(password, config['password_salt'])
    atomic(config_path, config)
    record = {'url': source, 'profile': None, 'body': body, 'nodes': nodes, 'working': working, 'updated': int(time.time())}
    atomic(state_dir / 'active.json', record)
    atomic(backup / 'install-info.json', {'password': password, 'url': 'http://' + config['admin_host'], 'backup': str(backup)})
    # The old service remains the rollback path; only replace its loopback listener.
    shutil.copy2(source_dir / 'everensprox-subscription.service', '/etc/systemd/system/everensprox-subscription.service')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'stop', 'pixelartick-subscription')
    try:
        run('systemctl', 'enable', '--now', 'everensprox-subscription')
        for _ in range(30):
            try:
                with urllib.request.urlopen('http://127.0.0.1:19087/health', timeout=2) as r:
                    if json.load(r).get('cached'):
                        break
            except OSError:
                time.sleep(.5)
        else:
            raise RuntimeError('New loopback feed did not start')
        # Verify authenticated API compatibility with the new, dedicated token.
        Panel(config).preflight()
        with urllib.request.urlopen(config['feed_url'], timeout=3) as r:
            if r.read().decode() != body:
                raise RuntimeError('Cached subscription changed during adoption')
        run('systemctl', 'disable', 'pixelartick-subscription')
    except Exception:
        subprocess.run(['systemctl', 'disable', '--now', 'everensprox-subscription'], capture_output=True)
        run('systemctl', 'start', 'pixelartick-subscription')
        raise SystemExit('Adoption failed; original adapter restarted. New files retained for diagnosis.')
    print('Installed:', 'http://' + config['admin_host'])
    print('Password and recovery information:', backup / 'install-info.json')
    print('Xray/client configuration unchanged. Original adapter preserved, disabled.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise SystemExit('Installation failed (' + type(exc).__name__ + '); sensitive output withheld.')

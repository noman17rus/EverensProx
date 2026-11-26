"""Provision a private WARP profile and add its tested Xray outbound safely."""
import argparse
import configparser
import copy
import hashlib
import json
import os
import pathlib
import platform
import shutil
import secrets
import socket
import subprocess
import tempfile
import time
import types
import urllib.request

from backend import Panel, Probe, atomic, digest, runtime_guard
from formats import Invalid
from warp import TAG, PROBE_TAG, PROBE_PORT, Warp

WARP_USER = 'warp@everensprox'


def add_warp_rule(template, email=WARP_USER):
    """Route one VLESS identity to WARP without touching other clients."""
    rules = template.setdefault('routing', {}).setdefault('rules', [])
    if any(email in (rule.get('user') or []) and rule.get('outboundTag') == TAG for rule in rules):
        return
    index = 0
    api_tag = template.get('api', {}).get('tag', 'api')
    while index < len(rules) and rules[index].get('outboundTag') == api_tag and rules[index].get('inboundTag'):
        index += 1
    rules.insert(index, {'type': 'field', 'user': [email], 'outboundTag': TAG})


def download(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'EverensProx-WARP'})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read(32 * 1024 * 1024)


def register(directory):
    """Verify a pinned upstream binary against release digest AND checksums."""
    architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if architecture is None:
        raise Invalid('Для автоматической регистрации поддержаны amd64 и arm64.')
    release = json.loads(download('https://api.github.com/repos/ViRb3/wgcf/releases/tags/v2.3.1'))
    name = 'wgcf_2.3.1_linux_' + architecture
    asset = next(a for a in release['assets'] if a['name'] == name)
    raw = download(asset['browser_download_url'])
    checksum = hashlib.sha256(raw).hexdigest()
    checksums = download(next(a['browser_download_url'] for a in release['assets'] if a['name'] == 'checksums.txt')).decode()
    expected = next(line.split()[0] for line in checksums.splitlines() if line.split()[-1].lstrip('*') == name)
    if checksum != expected or asset.get('digest') != 'sha256:' + checksum:
        raise Invalid('Контрольная сумма wgcf не совпадает с официальным выпуском.')
    tool = directory / 'wgcf'
    tool.write_bytes(raw)
    tool.chmod(0o700)
    account = directory / 'wgcf-account.toml'
    if not account.exists():
        subprocess.run([str(tool), 'register', '--accept-tos'], cwd=directory,
                       check=True, capture_output=True, timeout=120)
    profile = directory / 'wgcf-profile.conf'
    if not profile.exists():
        subprocess.run([str(tool), 'generate'], cwd=directory, check=True, capture_output=True, timeout=60)
    for path in directory.iterdir():
        if path.is_file():
            path.chmod(0o600 if path != tool else 0o700)
    return profile


def read_profile(path):
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(pathlib.Path(path).read_text())
    interface, peer = parser['Interface'], parser['Peer']
    return {'tag': TAG, 'protocol': 'wireguard', 'settings': {
        'secretKey': interface['PrivateKey'],
        'address': [x.strip() for x in interface['Address'].split(',')],
        'peers': [{'publicKey': peer['PublicKey'], 'endpoint': peer['Endpoint'],
                   'keepAlive': int(peer.get('PersistentKeepalive', '25')),
                   'allowedIPs': [x.strip() for x in peer.get('AllowedIPs', '0.0.0.0/0, ::/0').split(',')]}],
        'mtu': int(interface.get('MTU', '1280')), 'noKernelTun': True}}


def provision(config, node, backup):
    panel = Panel(config)
    before = panel.preflight()
    original = panel.call('xray/', {}, 'POST')
    if isinstance(original, str):
        original = json.loads(original)
    template = copy.deepcopy(before['template'])
    old_node = next((n for n in template.get('outbounds', []) if n.get('tag') == TAG), None)
    if old_node is not None and old_node != node:
        raise Invalid('Выход WARP уже существует с другими настройками; автоматическая замена запрещена.')
    runtime = json.loads(pathlib.Path(config['runtime']).read_text())
    # Test the profile before changing production, using an isolated Xray.
    candidate = copy.deepcopy(runtime)
    candidate['outbounds'] = [node]
    with tempfile.TemporaryDirectory() as directory:
        path = pathlib.Path(directory) / 'candidate.json'
        atomic(path, candidate)
        test_config = {**config, 'runtime': str(path)}
        manager = types.SimpleNamespace(directory=pathlib.Path(directory), config=test_config,
                                        probe=Probe(test_config), update=lambda **values: None)
        result = Warp(manager).check()
    backup.mkdir(mode=0o700, parents=True, exist_ok=False)
    atomic(backup / 'panel.json', original)
    atomic(backup / 'runtime.json', runtime)
    if old_node is None:
        template.setdefault('outbounds', []).append(node)
    if not any(i.get('tag') == PROBE_TAG for i in template.get('inbounds', [])):
        if any(i.get('tag') == PROBE_TAG for i in runtime.get('inbounds', [])):
            raise Invalid('Проверочный вход WARP уже занят другой конфигурацией.')
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', PROBE_PORT))
        template.setdefault('inbounds', []).append({
            'tag': PROBE_TAG, 'listen': '127.0.0.1', 'port': PROBE_PORT, 'protocol': 'socks',
            'settings': {'auth': 'password', 'accounts': [{'user': 'warp-check', 'pass': secrets.token_urlsafe(24)}], 'udp': True}})
        rules = template['routing']['rules']
        index = 0
        api_tag = template.get('api', {}).get('tag', 'api')
        while index < len(rules) and rules[index].get('outboundTag') == api_tag and rules[index].get('inboundTag'):
            index += 1
        # 3x-ui always keeps its own API rule first; preserve that invariant.
        rules.insert(index, {'type': 'field', 'inboundTag': [PROBE_TAG], 'outboundTag': TAG})
    add_warp_rule(template)
    if digest(panel.preflight()) != digest(before):
        raise Invalid('Конфигурация изменилась во время проверки WARP.')

    def save(value):
        panel.call('xray/update', {'xraySetting': json.dumps(value),
                                 'outboundTestUrl': original.get('outboundTestUrl', '')}, 'POST')

    try:
        if template != before['template']:
            save(template)
        for _ in range(60):
            live = json.loads(pathlib.Path(config['runtime']).read_text())
            if node in live.get('outbounds', []) and any(i.get('tag') == PROBE_TAG for i in live.get('inbounds', [])):
                break
            time.sleep(.5)
        else:
            raise Invalid('Xray не подтвердил добавление выхода WARP.')
        if panel.preflight()['template'] != template:
            raise Invalid('3x-ui не подтвердила сохранение WARP.')
        guarded = copy.deepcopy(live)
        guarded['inbounds'] = [i for i in guarded.get('inbounds', []) if i.get('tag') != PROBE_TAG]
        guarded['routing']['rules'] = [r for r in guarded['routing']['rules'] if r not in (
            {'type': 'field', 'inboundTag': [PROBE_TAG], 'outboundTag': TAG},
            {'type': 'field', 'user': [WARP_USER], 'outboundTag': TAG})]
        old_guarded = copy.deepcopy(runtime)
        old_guarded['inbounds'] = [i for i in old_guarded.get('inbounds', []) if i.get('tag') != PROBE_TAG]
        old_guarded['routing']['rules'] = [r for r in old_guarded['routing']['rules'] if r not in (
            {'type': 'field', 'inboundTag': [PROBE_TAG], 'outboundTag': TAG},
            {'type': 'field', 'user': [WARP_USER], 'outboundTag': TAG})]
        if runtime_guard(guarded) != runtime_guard(old_guarded):
            raise Invalid('При настройке WARP изменились входы или маршрутизация.')
    except Exception:
        if template != before['template']:
            current = panel.snapshot()['template']
            if current != template:
                raise Invalid('Конфигурация изменена извне; резервная копия сохранена, автоматический откат остановлен.')
            save(before['template'])
        raise
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='/etc/everensprox-subscription/config.json')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--profile', type=pathlib.Path)
    source.add_argument('--register', action='store_true')
    parser.add_argument('--accept-tos', action='store_true', help='Accept Cloudflare WARP terms for registration')
    args = parser.parse_args()
    os.umask(0o077)
    if args.register and not args.accept_tos:
        parser.error('--register requires --accept-tos')
    config = json.loads(pathlib.Path(args.config).read_text())
    directory = pathlib.Path(args.config).parent / 'warp'
    directory.mkdir(mode=0o700, exist_ok=True)
    profile = register(directory) if args.register else args.profile
    node = read_profile(profile)
    backup = pathlib.Path('/root') / ('everensprox-warp-backup-' + time.strftime('%Y%m%d-%H%M%S'))
    result = provision(config, node, backup)
    if profile.resolve() != (directory / 'wgcf-profile.conf').resolve():
        shutil.copyfile(profile, directory / 'wgcf-profile.conf')
        (directory / 'wgcf-profile.conf').chmod(0o600)
    print(json.dumps({'healthy': result['healthy'], 'ip': result['ip'], 'latency': result['latency'],
                      'backup': str(backup)}, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Xray output, registration logs and API errors can contain private keys.
        raise SystemExit(str(exc) if isinstance(exc, Invalid) else 'Настройка WARP не завершена (' + type(exc).__name__ + '). Секретные данные скрыты.')

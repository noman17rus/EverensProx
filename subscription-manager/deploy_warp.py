"""Test, back up and upgrade an existing panel with a verified WARP outbound."""
import argparse
import copy
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
import urllib.request

from backend import Manager, Panel, atomic
from configure_warp import provision, read_profile, register
from formats import Invalid
from warp import TAG, PROBE_TAG

FILES = ('backend.py', 'server.py', 'formats.py', 'index.html', 'wdtt.py', 'password.py',
         'warp.py', 'configure_warp.py')
SERVICE = 'everensprox-subscription'


def command(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=180, **kwargs)


def wait_feed(config):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    url = config['feed_url'].rsplit('/', 1)[0] + '/health'
    for _ in range(30):
        try:
            with opener.open(url, timeout=2) as response:
                if json.load(response).get('cached'):
                    return
        except OSError:
            pass
        time.sleep(1)
    raise Invalid('Обновлённая панель не запустилась.')


def restore_files(source, target, names):
    for name in names:
        if (source / name).exists():
            shutil.copy2(source / name, target / name)
        else:
            (target / name).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='/etc/everensprox-subscription/config.json')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--profile', type=pathlib.Path)
    source.add_argument('--register', action='store_true')
    parser.add_argument('--accept-tos', action='store_true')
    parser.add_argument('--enable-fallback', action='store_true')
    args = parser.parse_args()
    if args.register and not args.accept_tos:
        parser.error('--register requires --accept-tos')
    os.umask(0o077)
    stage = pathlib.Path(__file__).resolve().parent
    code = pathlib.Path('/opt/everensprox-subscription')
    if stage == code:
        raise Invalid('Запустите обновление из отдельного закрытого staging-каталога.')
    config_path = pathlib.Path(args.config)
    config = json.loads(config_path.read_text())
    state = pathlib.Path(config['state_dir'])
    panel = Panel(config)
    original = panel.preflight()
    command(sys.executable, '-m', 'unittest', 'discover', '-s', str(stage), cwd=stage)
    command('node', str(stage / 'test_panel.cjs'), cwd=stage)
    command('systemctl', 'is-active', '--quiet', SERVICE)
    if any((state / name).exists() for name in ('pending.json', 'egress-pending.json')):
        raise Invalid('Сначала завершите восстановление предыдущей операции.')
    backup = pathlib.Path('/root') / ('everensprox-warp-update-' + time.strftime('%Y%m%d-%H%M%S'))
    backup.mkdir(mode=0o700)
    shutil.copytree(code, backup / 'code')
    shutil.copytree(config_path.parent, backup / 'config')
    atomic(backup / 'panel.json', original)
    stopped = False
    try:
        directory = config_path.parent / 'warp'
        directory.mkdir(mode=0o700, exist_ok=True)
        profile = register(directory) if args.register else args.profile
        result = provision(config, read_profile(profile), backup / 'outbound')
        if profile.resolve() != (directory / 'wgcf-profile.conf').resolve():
            shutil.copyfile(profile, directory / 'wgcf-profile.conf')
            (directory / 'wgcf-profile.conf').chmod(0o600)
        expected = panel.preflight()
        expected_override = panel.balancer().get('override', '')
        command('systemctl', 'stop', SERVICE)
        stopped = True
        if any((state / name).exists() for name in ('pending.json', 'egress-pending.json')):
            raise Invalid('Панель завершилась с незавершённой операцией; обновление отменено.')
        shutil.copytree(state, backup / 'state')
        for name in FILES:
            shutil.copy2(stage / name, code / name)
        manager = Manager(config)
        manager.reconcile_selection()
        # Exercise the existing shared ingress, then restore the saved exit.
        saved = copy.deepcopy(manager.warp.value)
        saved_override = panel.balancer().get('override', '')
        try:
            manager.warp.switch('warp')
        finally:
            manager.warp.save(saved)
            manager.warp.override(saved_override)
            manager.warp.journal.unlink(missing_ok=True)
        if args.enable_fallback:
            manager.warp.settings(True)
        for name in ('active.json', 'selection.json', 'previous.json'):
            old = backup / 'state' / name
            new = state / name
            if old.exists() != new.exists() or (old.exists() and old.read_bytes() != new.read_bytes()):
                raise Invalid('Изменилось состояние подписок при обновлении: ' + name)
        if panel.preflight() != expected:
            raise Invalid('Конфигурация 3x-ui изменилась во время обновления.')
        manager.reconcile_selection()
        if panel.balancer().get('override', '') != expected_override:
            # An old runtime pin may have disappeared in Xray's reload; the saved
            # selection is authoritative, and was checked by reconcile_selection.
            selection = manager.selection.get('id')
            if not selection and expected_override:
                raise Invalid('Не подтверждён исходный внешний выход.')
        command('systemctl', 'start', SERVICE)
        stopped = False
        wait_feed(config)
        print(json.dumps({'updated': True, 'backup': str(backup), 'warp': result,
                          'shared_ingress_https': True, 'fallback_enabled': manager.warp.fallback_enabled},
                         ensure_ascii=False))
    except Exception as exc:
        # Restore only our added outbound; never overwrite unrelated panel edits.
        errors = []
        try:
            if not stopped:
                command('systemctl', 'stop', SERVICE)
                stopped = True
            restore_files(backup / 'code', code, FILES)
            if (backup / 'state').exists():
                names = {p.name for p in (backup / 'state').iterdir() if p.is_file()}
                restore_files(backup / 'state', state, names | {'egress.json', 'egress-pending.json'})
            current = panel.snapshot()['template']
            clean = copy.deepcopy(current)
            before_node = next((n for n in original['template'].get('outbounds', []) if n.get('tag') == TAG), None)
            if before_node is None:
                clean['outbounds'] = [n for n in clean.get('outbounds', []) if n.get('tag') != TAG]
            if not any(i.get('tag') == PROBE_TAG for i in original['template'].get('inbounds', [])):
                clean['inbounds'] = [i for i in clean.get('inbounds', []) if i.get('tag') != PROBE_TAG]
                if not clean['inbounds'] and 'inbounds' not in original['template']:
                    clean.pop('inbounds')
                clean['routing']['rules'] = [r for r in clean['routing']['rules'] if r != {'type': 'field', 'inboundTag': [PROBE_TAG], 'outboundTag': TAG}]
            if clean == original['template'] and current != clean:
                raw = panel.call('xray/', {}, 'POST')
                raw = json.loads(raw) if isinstance(raw, str) else raw
                panel.call('xray/update', {'xraySetting': json.dumps(clean),
                                         'outboundTestUrl': raw.get('outboundTestUrl', '')}, 'POST')
            elif clean != original['template']:
                errors.append('3x-ui изменена извне; автоматический откат шаблона пропущен')
        except Exception:
            errors.append('не удалось полностью подтвердить откат')
        finally:
            command('systemctl', 'start', SERVICE)
        reason = str(exc) if isinstance(exc, Invalid) else type(exc).__name__
        raise Invalid('Обновление отменено: ' + reason + '. Резервная копия: ' + str(backup)
                      + ('. ' + '; '.join(errors) if errors else '')) from exc


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        raise SystemExit(str(exc) if isinstance(exc, Invalid) else 'Обновление не завершено (' + type(exc).__name__ + '). Секретные данные скрыты.')

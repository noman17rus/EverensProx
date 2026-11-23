"""Upgrade an existing installation from a verified stage, with code/state rollback."""
import json
import os
import pathlib
import shutil
import subprocess
import time
import urllib.request

from backend import Panel, Probe, atomic, digest, node_signature, runtime_guard
from verify_sources import signature


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def main():
    stage = pathlib.Path(__file__).resolve().parent
    proof = json.loads((stage / 'verification.json').read_text())
    config_path = pathlib.Path('/etc/everensprox-subscription/config.json')
    config = json.loads(config_path.read_text())
    state = pathlib.Path(config['state_dir'])
    code = pathlib.Path('/opt/everensprox-subscription')
    panel = Panel(config)
    original_runtime = json.loads(pathlib.Path(config['runtime']).read_text())
    original_guard = runtime_guard(original_runtime)
    if time.time() - proof['checked'] > 3600:
        raise SystemExit('Verification is older than one hour; rerun it')
    if digest(panel.preflight()) != proof['baseline']:
        raise SystemExit('Panel configuration changed; rerun verification')
    if not any(v.get('working', 0) for v in proof['results'].values()):
        raise SystemExit('No verified free nodes; installation unchanged')
    Probe(config).live(json.loads((state / 'active.json').read_text()),
                       runtime_guard(json.loads(pathlib.Path(config['runtime']).read_text())))
    backup = pathlib.Path('/root/everensprox-catalog-backup-' + time.strftime('%Y%m%d-%H%M%S'))
    backup.mkdir(mode=0o700)
    service = 'everensprox-subscription'
    files = ('server.py', 'backend.py', 'formats.py', 'index.html', 'password.py', 'wdtt.py')
    run('systemctl', 'stop', service)
    try:
        if (state / 'pending.json').exists():
            raise RuntimeError('Recovery pending; update refused')
        if any(signature(state / name) != value for name, value in proof['original'].items()):
            raise RuntimeError('Live state changed; update refused')
        shutil.copytree(code, backup / 'code')
        shutil.copytree(state, backup / 'state')
        shutil.copytree(config_path.parent, backup / 'config')
        staged_sources = json.loads((stage / 'verified-state' / 'sources.json').read_text())
        staged_sources['enabled'] = True
        for key, result in proof['results'].items():
            staged_sources['catalog'][key]['last_error'] = result.get('error')
        atomic(state / 'sources.json', staged_sources)
        for name in files:
            shutil.copy2(stage / name, code / name)
        run('systemctl', 'start', service)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(30):
            try:
                with opener.open('http://127.0.0.1:19087/health', timeout=2) as response:
                    if json.load(response).get('cached'):
                        break
            except OSError:
                pass
            time.sleep(1)
        else:
            raise RuntimeError('Updated panel did not start')
        for name in ('active.json', 'selection.json', 'previous.json'):
            if signature(state / name) != proof['original'][name]:
                raise RuntimeError('Startup changed ' + name)
        if digest(panel.preflight()) != proof['baseline']:
            raise RuntimeError('Live configuration changed')
        active = json.loads((state / 'active.json').read_text())
        Probe(config).live(active, runtime_guard(json.loads(pathlib.Path(config['runtime']).read_text())))
        print(json.dumps({'updated': True, 'backup': str(backup), 'active_source': active.get('source', 'primary'),
                          'verified_feeds': proof['results'], 'live_exit_https': 'passed'}, ensure_ascii=False))
    except Exception:
        run('systemctl', 'stop', service)
        if (backup / 'code').exists():
            for name in files:
                shutil.copy2(backup / 'code' / name, code / name)
        if (backup / 'state').exists():
            for path in (backup / 'state').iterdir():
                if path.is_file():
                    shutil.copy2(path, state / path.name)
            if not (backup / 'state' / 'pending.json').exists():
                (state / 'pending.json').unlink(missing_ok=True)
        run('systemctl', 'start', service)
        if (backup / 'state').exists():
            old = json.loads((state / 'active.json').read_text())
            runtime = json.loads(pathlib.Path(config['runtime']).read_text())
            live_nodes = [n for n in runtime['outbounds'] if n.get('protocol') == 'vless'
                          and n.get('tag', '').startswith(config['tag_prefix'])]
            if node_signature(live_nodes) != node_signature(old['nodes']):
                panel.refresh()
                Probe(config).wait(old, original_guard)
        raise SystemExit('Update refused or failed; previous code/state retained. Backup: ' + str(backup))


if __name__ == '__main__':
    main()

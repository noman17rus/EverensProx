"""Stage-only live verification. Never refreshes the installed Xray configuration."""
import copy
import hashlib
import json
import os
import pathlib
import shutil
import threading
import time

from backend import Manager, Panel, atomic, digest
from server import Feed, Server


def signature(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def main():
    stage = pathlib.Path(__file__).resolve().parent
    state = stage / 'verified-state'
    state.mkdir(mode=0o700)
    config = json.loads(pathlib.Path('/etc/everensprox-subscription/config.json').read_text())
    live = pathlib.Path(config['state_dir'])
    if (live / 'pending.json').exists():
        raise SystemExit('Recovery pending; verification refused')
    names = ('active.json', 'sources.json', 'selection.json', 'previous.json')
    original = {name: signature(live / name) for name in names}
    for name in names:
        if (live / name).exists():
            shutil.copy2(live / name, state / name)
            os.chmod(state / name, 0o600)
    panel = Panel(config)
    baseline = digest(panel.preflight())
    isolated = copy.deepcopy(config)
    isolated['state_dir'] = str(state)
    server = Server(('127.0.0.1', 0), Feed)
    isolated['feed_url'] = 'http://127.0.0.1:' + str(server.server_port) + '/subscription'
    manager = Manager(isolated, panel=panel)
    server.manager = manager
    threading.Thread(target=server.serve_forever, daemon=True).start()
    results = {}
    try:
        # Force all results into inactive caches, even if production is on a reserve.
        manager.active['source'] = 'verification-only'
        for source, feed in manager.catalog().items():
            print(json.dumps({'checking': source, 'name': feed['name']}, ensure_ascii=False), flush=True)
            try:
                manager.refresh_source(source)
                record = manager.sources[source]
                results[source] = {'working': record['working'], 'nodes': len(record['nodes']),
                                   'skipped': record.get('skipped', 0)}
            except Exception:
                results[source] = {'error': manager.source_status[source].get('error', 'Verification failed')}
            if digest(panel.preflight()) != baseline:
                raise RuntimeError('Live configuration changed; refuse to use staged state')
            atomic(stage / 'verification-progress.json', results)
            print(json.dumps({'source': source, **results[source]}, ensure_ascii=False), flush=True)
        if any(signature(live / name) != value for name, value in original.items()):
            raise RuntimeError('Live state changed; rerun verification before deployment')
        atomic(stage / 'verification.json', {'original': original, 'baseline': baseline,
                                            'results': results, 'checked': int(time.time())})
        print('Verification finished; live files and routing unchanged.', flush=True)
    finally:
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()

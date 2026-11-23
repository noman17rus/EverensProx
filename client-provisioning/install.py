"""Install code only after the administrator has supplied the server configuration."""
import json
import os
import pathlib
import shutil
import subprocess

from backend import Panel, Wdtt, Unavailable


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo on the Linux server.')
    source = pathlib.Path(__file__).resolve().parent
    config_dir = pathlib.Path('/etc/everensprox-provisioning')
    code_dir = pathlib.Path('/opt/everensprox-provisioning')
    state_dir = pathlib.Path('/var/lib/everensprox-provisioning')
    config_dir.mkdir(mode=0o700, exist_ok=True)
    config_file = config_dir / 'config.json'
    if not config_file.exists():
        shutil.copyfile(source / 'config.example.json', config_file)
        config_file.chmod(0o600)
        raise SystemExit('Created config template. Configure HTTPS address, panel auth file, WDTT password and hashes, then run again.')
    config = json.loads(config_file.read_text())
    if not config['public_url'].startswith('https://') or 'REPLACE' in json.dumps(config):
        raise SystemExit('Complete config.json before installation.')
    for field in ('panel_auth_file', 'wdtt_password_file'):
        path = pathlib.Path(config[field])
        if not path.is_file() or path.stat().st_mode & 0o077:
            raise SystemExit(field + ' must exist and have mode 0600.')
    if pathlib.Path(config['database']).parent != state_dir:
        raise SystemExit('Database must be in /var/lib/everensprox-provisioning.')
    if code_dir.exists():
        raise SystemExit('Already installed. Follow the backup/update procedure in README.md.')
    try:
        inbounds = Panel(config).inbounds()
        if not isinstance(inbounds, list) or not any(i.get('protocol') == 'vless' for i in inbounds):
            raise Unavailable('No VLESS inbounds found.')
        listing = Wdtt(config).listing()
        if 'server' not in listing or 'passwords' not in listing:
            raise Unavailable('Unsupported WDTT admin response.')
    except Exception:
        raise SystemExit('Preflight failed. Check the panel URL/token, WDTT socket/password and service availability.') from None
    state_dir.mkdir(mode=0o700, exist_ok=True)
    code_dir.mkdir(mode=0o755)
    for name in ('backend.py', 'server.py'):
        shutil.copyfile(source / name, code_dir / name)
    shutil.copyfile(source / 'everensprox-provisioning.service', '/etc/systemd/system/everensprox-provisioning.service')
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', 'everensprox-provisioning'], check=True)


if __name__ == '__main__':
    main()

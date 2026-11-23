"""Strict, loss-averse VLESS subscription import; no provider routing is imported."""
import base64
import copy
import json
import urllib.parse as url
import uuid

LIMIT = 2 * 1024 * 1024
MAX_NODES = 128


class Invalid(ValueError):
    pass


class ChooseProfile(Invalid):
    def __init__(self, profiles):
        self.profiles = profiles
        super().__init__('Выберите профиль подписки и повторите проверку.')


def unbase64(value):
    value = ''.join(value.split())
    try:
        return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True).decode('utf-8-sig')
    except (ValueError, UnicodeError) as exc:
        raise Invalid('Не удалось распознать формат подписки.') from exc


def import_body(raw, profile=None):
    if len(raw) > LIMIT:
        raise Invalid('Подписка превышает 2 МиБ.')
    try:
        text = raw.decode('utf-8-sig').strip()
    except UnicodeError as exc:
        raise Invalid('Подписка должна быть текстовой.') from exc
    if not text:
        raise Invalid('Пустая подписка.')
    if not text.startswith(('[', '{', 'vless://')):
        text = unbase64(text).strip()
    if text.startswith(('[', '{')):
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise Invalid('Некорректный JSON подписки.') from exc
        profiles = data if isinstance(data, list) else [data]
        if not profiles or any(not isinstance(p, dict) for p in profiles):
            raise Invalid('Ожидается конфигурация Xray или список профилей Happ.')
        auto = next((i for i, p in enumerate(profiles) if 'Автовыбор' in str(p.get('remarks', ''))), None)
        if profile is None and auto is None and len(profiles) > 1:
            raise ChooseProfile([{'id': i, 'name': str(p.get('remarks', 'Профиль ' + str(i + 1)))[:120]} for i, p in enumerate(profiles)])
        selected = profile if profile is not None else auto if auto is not None else 0
        if not isinstance(selected, int) or selected < 0 or selected >= len(profiles):
            raise Invalid('Профиль не найден.')
        nodes = [copy.deepcopy(o) for o in profiles[selected].get('outbounds', []) if isinstance(o, dict) and o.get('protocol') == 'vless']
    else:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if any(not line.startswith('vless://') for line in lines):
            raise Invalid('Поддерживаются только узлы VLESS.')
        nodes = [decode_uri(line) for line in lines]
    if not nodes or len(nodes) > MAX_NODES:
        raise Invalid('Нужно от 1 до 128 узлов VLESS.')
    lines = []
    for i, node in enumerate(nodes):
        node['tag'] = 'node-' + str(i + 1)
        try:
            lines.append(encode_uri(node))
        except (KeyError, TypeError, IndexError, ValueError) as exc:
            if isinstance(exc, Invalid):
                raise
            raise Invalid('Некорректные параметры узла VLESS.') from exc
    return ('\n'.join(lines) + '\n').encode(), nodes


def free_batches(raw):
    """Tolerant public-feed boundary; private subscriptions remain strict."""
    if len(raw) > LIMIT:
        raise Invalid('Подписка превышает 2 МиБ.')
    try:
        text = raw.decode('utf-8-sig').strip()
    except UnicodeError as exc:
        raise Invalid('Подписка должна быть текстовой.') from exc
    if text and '://' not in text:
        text = unbase64(text)
    accepted, seen, skipped = [], set(), 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            if not line.startswith('vless://'):
                raise Invalid('Другой протокол.')
            body, nodes = import_body(line.encode())
            # import_body normalizes the tag, so names do not affect deduplication.
            key = json.dumps(nodes[0], sort_keys=True)
            if key in seen:
                skipped += 1
                continue
            seen.add(key)
            accepted.append(body.decode().strip())
        except Invalid:
            skipped += 1
    if not accepted:
        raise Invalid('В бесплатной ленте нет совместимых узлов VLESS.')
    batches = [import_body(('\n'.join(accepted[i:i + MAX_NODES])).encode())
               for i in range(0, len(accepted), MAX_NODES)]
    return batches, skipped


def only_keys(obj, keys):
    if not isinstance(obj, dict) or set(obj) - set(keys):
        raise Invalid('В узле есть неподдерживаемые параметры; они не будут удалены молча.')


TLS_PARAMS = [('serverName', 'sni'), ('fingerprint', 'fp'), ('publicKey', 'pbk'),
              ('shortId', 'sid'), ('spiderX', 'spx'), ('mldsa65Verify', 'pqv'),
              ('echConfigList', 'ech'), ('verifyPeerCertByName', 'vcn'), ('pinnedPeerCertSha256', 'pcs')]


def encode_uri(node):
    only_keys(node, ['protocol', 'tag', 'settings', 'streamSettings'])
    settings = node['settings']
    only_keys(settings, ['vnext'])
    if len(settings['vnext']) != 1:
        raise Invalid('Один узел должен содержать один сервер.')
    server = settings['vnext'][0]
    only_keys(server, ['address', 'port', 'users'])
    if len(server['users']) != 1:
        raise Invalid('Один узел должен содержать одного пользователя.')
    user = server['users'][0]
    only_keys(user, ['id', 'encryption', 'flow', 'level', 'email'])
    uuid.UUID(user['id'])
    if not isinstance(server['port'], int) or not 1 <= server['port'] <= 65535:
        raise Invalid('Некорректный порт узла.')
    host = server['address']
    if not isinstance(host, str) or not host or any(c in host for c in '/?#@\r\n '):
        raise Invalid('Некорректный адрес узла.')
    st = node.get('streamSettings', {})
    net, security = st.get('network', 'tcp'), st.get('security', 'none')
    if net not in ('tcp', 'ws', 'grpc', 'xhttp') or security not in ('tls', 'reality'):
        raise Invalid('Поддержаны TCP, WS, gRPC и XHTTP с TLS или Reality.')
    only_keys(st, ['network', 'security', 'tlsSettings', 'realitySettings', net + 'Settings', 'finalmask'])
    tls = st.get('tlsSettings' if security == 'tls' else 'realitySettings', {})
    only_keys(tls, [k for k, _ in TLS_PARAMS] + ['allowInsecure', 'alpn', 'show', 'enableSessionResumption'])
    if tls.get('enableSessionResumption'):
        raise Invalid('TLS session resumption в ссылках подписки не поддерживается.')
    if tls.get('allowInsecure') or tls.get('show'):
        raise Invalid('Небезопасные параметры TLS не поддерживаются.')
    q = dict(type=net, security=security, encryption=user.get('encryption', 'none'), flow=user.get('flow', ''))
    for key, param in TLS_PARAMS:
        if key in tls:
            if not isinstance(tls[key], (str, int)):
                raise Invalid('Неподдерживаемый параметр TLS.')
            q[param] = tls[key]
    if tls.get('alpn'):
        q['alpn'] = ','.join(tls['alpn'])
    tr = st.get(net + 'Settings', {})
    if net == 'tcp':
        if tr and tr != {'header': {'type': 'none'}}:
            raise Invalid('Нестандартный TCP header не поддерживается.')
    elif net == 'ws':
        only_keys(tr, ['host', 'headers', 'path'])
        only_keys(tr.get('headers', {}), ['Host'])
        q.update(host=tr.get('host') or tr.get('headers', {}).get('Host', ''), path=tr.get('path', '/'))
    elif net == 'grpc':
        only_keys(tr, ['serviceName', 'authority', 'multiMode', 'mode'])
        mode = tr.get('multiMode', tr.get('mode', False))
        q.update(serviceName=tr.get('serviceName', ''), authority=tr.get('authority', ''), mode='multi' if mode in (True, 'multi') else 'gun')
    else:
        extra = dict(tr.get('extra', {}))
        extra.update({k: v for k, v in tr.items() if k not in ('host', 'path', 'mode', 'extra')})
        q.update(host=tr.get('host', ''), path=tr.get('path', '/'), mode=tr.get('mode', 'auto'), extra=json.dumps(extra, separators=(',', ':')))
    if st.get('finalmask'):
        q['fm'] = json.dumps(st['finalmask'], separators=(',', ':'))
    return 'vless://' + url.quote(user['id'], safe='') + '@' + ('[' + host.strip('[]') + ']' if ':' in host else host) + ':' + str(server['port']) + '?' + url.urlencode(q) + '#' + url.quote(node['tag'], safe='')


def decode_uri(line):
    try:
        parsed = url.urlsplit(line)
        params = url.parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
        if any(len(v) != 1 for v in params.values()):
            raise Invalid('Повторяющиеся параметры VLESS.')
        q = {k: v[0] for k, v in params.items()}
        allowed = {'type', 'security', 'encryption', 'flow', 'alpn', 'host', 'path', 'serviceName', 'authority', 'mode', 'extra', 'fm', 'headerType'} | {p for _, p in TLS_PARAMS}
        if set(q) - allowed or q.get('headerType', 'none') != 'none':
            raise Invalid('В ссылке VLESS есть неподдерживаемые параметры.')
        if parsed.password is not None or not parsed.hostname or not parsed.port:
            raise Invalid('Некорректная ссылка VLESS.')
        net, security = q.get('type', 'tcp'), q.get('security', 'none')
        tls = {k: q[p] for k, p in TLS_PARAMS if p in q}
        if q.get('alpn'):
            tls['alpn'] = q['alpn'].split(',')
        st = {'network': net, 'security': security, 'tlsSettings' if security == 'tls' else 'realitySettings': tls}
        if net == 'ws':
            st['wsSettings'] = {'host': q.get('host', ''), 'path': q.get('path', '/')}
        elif net == 'grpc':
            if q.get('mode', 'gun') not in ('gun', 'multi'):
                raise Invalid('Неподдерживаемый режим gRPC.')
            st['grpcSettings'] = {'serviceName': q.get('serviceName', ''), 'authority': q.get('authority', ''), 'multiMode': q.get('mode') == 'multi'}
        elif net == 'xhttp':
            st['xhttpSettings'] = {'host': q.get('host', ''), 'path': q.get('path', '/'), 'mode': q.get('mode', 'auto'), 'extra': json.loads(q.get('extra', '{}'))}
        if 'fm' in q:
            st['finalmask'] = json.loads(q['fm'])
        return {'protocol': 'vless', 'settings': {'vnext': [{'address': parsed.hostname, 'port': parsed.port, 'users': [{'id': url.unquote(parsed.username or ''), 'encryption': q.get('encryption', 'none'), 'flow': q.get('flow', '')}]}]}, 'streamSettings': st}
    except (ValueError, TypeError, KeyError) as exc:
        if isinstance(exc, Invalid):
            raise
        raise Invalid('Некорректная ссылка VLESS.') from exc

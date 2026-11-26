# WARP в EverensProx: деплой на сервер

WARP работает на сервере. В приложении только переключатель и проверка статуса; ключи WARP на телефон не попадают. Один общий WARP-клиент `warp@everensprox` направляется Xray-правилом в существующий выход `warp-emergency`.

## 1. Обновить файлы

На сервере:

```sh
install -m 0755 configure_warp.py /opt/everensprox-subscription/configure_warp.py
install -m 0644 backend.py /opt/everensprox-provisioning/backend.py
install -m 0644 server.py  /opt/everensprox-provisioning/server.py
```

Файлы берутся из `subscription-manager/configure_warp.py` и `client-provisioning/`.

## 2. Проверить WARP-профиль

Если профиль уже есть:

```sh
ls -l /etc/everensprox-subscription/warp/wgcf-profile.conf
```

Если файла нет, зарегистрировать новый WARP-аккаунт (нужен интернет и согласие с условиями Cloudflare):

```sh
cd /opt/everensprox-subscription
python3 configure_warp.py \
  --config /etc/everensprox-subscription/config.json \
  --register --accept-tos
```

Если профиль есть, применить его без перерегистрации:

```sh
cd /opt/everensprox-subscription
python3 configure_warp.py \
  --config /etc/everensprox-subscription/config.json \
  --profile /etc/everensprox-subscription/warp/wgcf-profile.conf
```

Команда добавляет выход `warp-emergency` (если его ещё нет), проверочный вход и правило:

```json
{"type":"field","user":["warp@everensprox"],"outboundTag":"warp-emergency"}
```

Она же делает резервную копию в `/root/everensprox-warp-backup-*`.

## 3. Добавить WARP в конфиг provisioning

В `/etc/everensprox-provisioning/config.json` добавить блок (UUID сгенерировать один раз и сохранить):

```json
"warp": {
  "enabled": true,
  "email": "warp@everensprox",
  "uuid": "<UUID>",
  "inbound_id": 2,
  "name": "WARP"
}
```

Сгенерировать UUID:

```sh
python3 -c 'import uuid; print(uuid.uuid4())'
```

`inbound_id` должен совпадать с VLESS-inbound из `inbound_ids` (обычно `2`). Email должен совпадать с `WARP_USER` в `configure_warp.py`.

## 4. Перезапустить provisioning

```sh
systemctl restart everensprox-provisioning
systemctl status everensprox-provisioning --no-pager
curl -fsS https://hub.everens.online/health
```

## 5. Проверить в приложении

1. Установить APK 0.9.6 (или новее).
2. На экране «Доступ» синхронизировать профиль (меню профиля → «Синхронизация»).
3. В блоке «Маршрут» появится переключатель `WARP`.
4. Включить WARP и VPN. Через несколько секунд рядом с «Маршрут» появится:
   - `WARP работает` — зелёный;
   - `WARP не работает` — красный (проверьте Xray-правило и выход `warp-emergency`).

Проверка идёт через `https://www.cloudflare.com/cdn-cgi/trace` и ожидает `warp=on` или `warp=plus`.

## Откат

Если `configure_warp.py` сообщает об ошибке, он не меняет конфигурацию. Резервная копия:

```sh
ls -dt /root/everensprox-warp-backup-* | head -1
```

Не удаляйте старый `warp-emergency`, пока не проверите новый.

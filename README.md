# EverensProx

[![Android](https://img.shields.io/badge/platform-Android-3DDC84?logo=android&logoColor=white)](https://github.com/noman17rus/EverensProx/releases/latest)
[![Release](https://img.shields.io/github/v/release/noman17rus/EverensProx)](https://github.com/noman17rus/EverensProx/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/noman17rus/EverensProx/total)](https://github.com/noman17rus/EverensProx/releases)

Android-клиент на основе FlClash с поддержкой WDTT, VLESS и настройками обхода DPI.
Исходники приложений подключены как Git-подмодули и закреплены на конкретных коммитах.

## Скачать и установить

**[Скачать APK для Android](https://github.com/noman17rus/EverensProx/releases/latest)**

В релизах этого репозитория публикуются только Android APK и файлы контрольных сумм
`SHA256SUMS` и `FlClash-<версия>-SHA256SUMS`. APK `android-arm64-v8a` и
`android-arm64` содержат одну сборку для совместимости обновлений старого и
нового клиента. Эта сборка предназначена для устройств ARM64;
для устройств ARMv7 и эмуляторов x86 этот APK не подходит.

1. Скачайте APK из последнего релиза.
2. Разрешите установку приложений из выбранного браузера или файлового менеджера.
3. Установите приложение и подтвердите запрос Android на VPN-подключение при запуске туннеля.

## WARP

В версии 0.9.6 появился отдельный маршрут WARP: переключатель в приложении,
выход через сервер и индикатор «WARP работает». WARP не меняет маршруты других
пользователей и не передаёт ключи WARP на телефон. Подробности:
[WARP.md](WARP.md), установка на сервере: [WARP-DEPLOY.md](WARP-DEPLOY.md).

## Обновления

Приложение проверяет новые версии **только в `noman17rus/EverensProx`**.
Проверка доступна в разделе «О приложении»; автоматическая проверка зависит от
соответствующей настройки приложения. При скачивании обновления проверяется SHA-256
APK по `SHA256SUMS` из того же релиза. Установку подтверждает пользователь в Android.

Релизы исходного FlClash и других репозиториев не используются как источник обновлений.
Для следующих выпусков увеличивайте версию `X.Y.Z` и Android `versionCode`, сохраняйте
тот же идентификатор приложения и ключ подписи. Подробности: [выпуск Android](RELEASING.md).

| Компонент | Форк | Исходный проект |
| --- | --- | --- |
| FlClash | [noman17rus/FlClash](https://github.com/noman17rus/FlClash) | [chen08209/FlClash](https://github.com/chen08209/FlClash) |
| WDTT Plus | [noman17rus/WDTT-Plus](https://github.com/noman17rus/WDTT-Plus) | [Ivan4537/WDTT-Plus](https://github.com/Ivan4537/WDTT-Plus) |

## Получение исходников

```sh
git clone --recurse-submodules https://github.com/noman17rus/EverensProx.git
cd EverensProx
```

Если репозиторий уже клонирован:

```sh
git submodule update --init --recursive
```

Инструкции сборки и лицензии находятся в каталогах соответствующих приложений. Каталог `.build/` содержит локальные инструменты и результаты сборок и не публикуется.

## Автоматическая выдача клиентских подписок

[client-provisioning](client-provisioning/README.md) — отдельный серверный сервис
для создания связанной пары VLESS/WDTT по имени или email из Android FlClash.
Адрес API по умолчанию — `https://hub.everens.online`. Общие подписки не ограничивают
число устройств; старые профили сохраняют ссылки и настройки. Сервис требуется
установить на сервере отдельно по инструкции в каталоге.

## Мониторинг сервера

Каталог [monitoring](monitoring/README.md) содержит Docker Compose для Grafana,
Prometheus и статистики клиентов WDTT/VLESS через 3x-ui. Нагрузка сервера,
онлайн-клиенты и трафик отображаются в общей панели с историей.

## Замена внешней подписки

Каталог [subscription-manager](subscription-manager/README.md) содержит локальную
панель быстрой замены внешней VLESS-подписки для общего выхода VLESS и WDTT:
проверка узлов до применения, сохранение клиентских настроек и откат.

## Обновление компонентов

Сначала сохраните и отправьте изменения в соответствующий форк, затем закоммитьте новую ссылку на подмодуль в этом репозитории:

```sh
git add FlClash WDTT-Plus
git commit -m "chore: update application revisions"
git push
```

## Лицензии и авторство

Проект основан на FlClash и WDTT Plus. Лицензии исходных компонентов сохранены
в [FlClash/LICENSE](https://github.com/noman17rus/FlClash/blob/main/LICENSE) и
[WDTT-Plus](https://github.com/noman17rus/WDTT-Plus). Условия лицензий компонентов
продолжают действовать; исходники версии APK закреплены подмодулями в теге релиза.

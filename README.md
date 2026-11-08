# EverensProx

Рабочий проект FlClash с поддержкой WDTT. Исходники приложений подключены как Git-подмодули и закреплены на конкретных коммитах.

| Компонент | Форк | Исходный проект |
| --- | --- | --- |
| FlClash | [noman17/FlClash](https://github.com/noman17rus/FlClash) | [chen08209/FlClash](https://github.com/chen08209/FlClash) |
| WDTT Plus | [noman17/WDTT-Plus](https://github.com/noman17rus/WDTT-Plus) | [Ivan4537/WDTT-Plus](https://github.com/Ivan4537/WDTT-Plus) |

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

## Обновление компонентов

Сначала сохраните и отправьте изменения в соответствующий форк, затем закоммитьте новую ссылку на подмодуль в этом репозитории:

```sh
git add FlClash WDTT-Plus
git commit -m "chore: update application revisions"
git push
```

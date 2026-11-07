<!-- SPDX-FileCopyrightText: 2026 Olivares.AI -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

**Языки:** [English](./README.md) · [Español](./README.es.md) · [简体中文](./README.zh.md) · **Русский** · [日本語](./README.ja.md) · [Deutsch](./README.de.md) · [Français](./README.fr.md) · [Українська](./README.uk.md) · [한국어](./README.ko.md) · [Português](./README.pt.md)

# Olivares Server

Olivares Server — это appliance Olivares: образ Linux, который устанавливает движок и консоль Olivares, локальную
консоль для самого хоста и настройку при первой загрузке, запускающую продукт.

Этот репозиторий содержит **рецепт** appliance Community: исходники, описания образов, юниты служб, политику SELinux
и тесты, из которых собирается образ.

## Что здесь есть

| Путь | Содержимое |
| --- | --- |
| `appliance/answers/` | Автономный инструмент ответов. Он проверяет один документ ответов и выводит план. |
| `appliance/cmd/`, `appliance/layer/` | Первая загрузка, консоль Appliance (`:9443`), консоль восстановления и вспомогательные программы с правами root, которые они используют. |
| `appliance/images/` | Рецепт образа (KIWI), сборка ISO, qcow2 и OVA и закреплённый набор инструментов сборки. |
| `appliance/selinux/` | Модуль политики SELinux и инструменты, которые его генерируют и проверяют. |
| `appliance/test/` | Набор тестов загрузки и тесты рецепта. |
| `packaging/nfpm/`, `scripts/` | Два описания пакетов и скрипт, который собирает полезную нагрузку консоли Appliance. |

`appliance/README.md` подробно описывает документ ответов, первую загрузку и консоль.

## Сборка и тесты

Рецепт написан под исходный код продукта в [olivaresai/olivares](https://github.com/olivaresai/olivares): его код на
Go импортирует пакеты из `core/` этого репозитория. Скопируйте каталоги верхнего уровня этого репозитория в
checkout того репозитория по тем же путям, затем запустите тесты модуля из `appliance/`, у которого для этой цели есть
собственное рабочее пространство Go:

```sh
git clone https://github.com/olivaresai/olivares-server
git clone --branch "$(cat olivares-server/RELEASE-VERSION)" https://github.com/olivaresai/olivares
cp -r olivares-server/appliance olivares-server/packaging olivares-server/scripts olivares/
cd olivares/appliance && go test ./...
```

Некоторые тесты рецепта читают рабочие процессы релиза сборки, которая публикует образы. Эти рабочие процессы и их
вспомогательные программы публикации поддерживаются вместе с лицензируемым дистрибутивом, поэтому здесь такие тесты
пропускаются и выполняются в той сборке.

Для сборки образа нужен хост с поддержкой KVM и набор инструментов, закреплённый в `appliance/images/toolchain/`.
Следуйте `appliance/images/toolchain/README.md`.

## Редакции

Образ, который собирает этот рецепт, — это редакция Community. Служба лицензирования, возможности Business и
Enterprise и используемые ими пакеты — отдельные лицензируемые продукты, и в этот репозиторий они не входят. Когда
установлена лицензия Business, вспомогательная программа образа `olivares-entitled-repo` позволяет менеджеру пакетов
загружать эти пакеты из канала, на который даёт право лицензия, а `olivares-edition.service` заменяет пакет Community
пакетом Business на работающем appliance, сохраняя его данные. Удаление лицензии возвращает всё обратно. Ни один образ
не содержит пакета Business.

## Как создаётся этот репозиторий

Этот репозиторий генерируется из исходного кода разработки Olivares при каждом релизе. Не открывайте здесь pull
request: изменение, сделанное здесь, будет удалено следующим релизом. Сообщайте о проблемах и предлагайте изменения в
[olivaresai/olivares](https://github.com/olivaresai/olivares/issues).

## Лицензия

AGPL-3.0-only. См. `LICENSE`, `DISCLAIMER.md` и `NOTICE`. Чтобы сообщить об уязвимости, следуйте `SECURITY.md`.

<!-- SPDX-FileCopyrightText: 2026 Olivares.AI -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

**Мови:** [English](./README.md) · [Español](./README.es.md) · [简体中文](./README.zh.md) · [Русский](./README.ru.md) · [日本語](./README.ja.md) · [Deutsch](./README.de.md) · [Français](./README.fr.md) · **Українська** · [한국어](./README.ko.md) · [Português](./README.pt.md)

# Olivares Server

Olivares Server — це апаратний пристрій (appliance) Olivares: образ Linux, який встановлює рушій і консоль Olivares, локальну
консоль для самого хоста та налаштування під час першого завантаження, що запускає продукт.

Цей репозиторій містить **рецепт** пристрою Community: вихідний код, визначення образів, службові юніти, політику
SELinux і тести, з яких збирається образ.

## Що тут є

| Шлях | Вміст |
| --- | --- |
| `appliance/answers/` | Офлайн-інструмент відповідей. Він перевіряє один документ відповідей і виводить план. |
| `appliance/cmd/`, `appliance/layer/` | Перше завантаження, Appliance Console (`:9443`), консоль відновлення та кореневі допоміжні програми, які вона використовує. |
| `appliance/images/` | Рецепт образу (KIWI), збирання ISO, qcow2 і OVA та закріплений набір інструментів збирання. |
| `appliance/selinux/` | Модуль політики SELinux та інструменти, що його генерують і перевіряють. |
| `appliance/test/` | Батарея тестів завантаження та тести рецепта. |
| `packaging/nfpm/`, `scripts/` | Два визначення пакетів і скрипт, що збирає корисне навантаження Appliance Console. |

`appliance/README.md` докладно описує документ відповідей, перше завантаження та консоль.

## Збирання і тестування

Рецепт написано відносно вихідного коду продукту в [olivaresai/olivares](https://github.com/olivaresai/olivares): його
код Go імпортує пакети з `core/` того репозиторію. Скопіюйте каталоги верхнього рівня цього репозиторію в копію
того репозиторію за тими самими шляхами, а потім запустіть тести модуля з `appliance/`, який має власний робочий
простір Go для цієї мети:

```sh
git clone https://github.com/olivaresai/olivares-server
git clone --branch "$(cat olivares-server/RELEASE-VERSION)" https://github.com/olivaresai/olivares
cp -r olivares-server/appliance olivares-server/packaging olivares-server/scripts olivares/
cd olivares/appliance && go test ./...
```

Деякі тести рецепта читають робочі процеси випуску збірки, яка публікує образи. Ці робочі процеси та їхні
допоміжні програми публікації підтримуються разом із ліцензованим дистрибутивом, тому ці тести тут пропускаються й виконуються в тій збірці.

Для збирання образу потрібен хост із підтримкою KVM і набір інструментів, закріплений у `appliance/images/toolchain/`. Дотримуйтеся
`appliance/images/toolchain/README.md`.

## Редакції

Образ, який збирає цей рецепт, — це редакція Community. Служба ліцензування, можливості Business і Enterprise та
пакети, які вони використовують, є окремими ліцензованими продуктами й не входять до цього репозиторію. Якщо встановлено
ліцензію Business, допоміжна програма образу `olivares-entitled-repo` дає змогу менеджеру пакетів отримати ці пакети
з каналу, на який дає право ліцензія, а `olivares-edition.service` замінює пакет Community на пакет Business
на працюючому пристрої, зберігаючи його дані. Видалення ліцензії замінює його назад. Жоден образ не містить пакета Business.

## Як створюється цей репозиторій

Цей репозиторій генерується з джерельного коду розробки Olivares під час кожного випуску. Не відкривайте тут pull request:
зміну, зроблену тут, буде видалено наступним випуском. Повідомляйте про проблеми та пропонуйте зміни в
[olivaresai/olivares](https://github.com/olivaresai/olivares/issues).

## Ліцензія

AGPL-3.0-only. Дивіться `LICENSE`, `DISCLAIMER.md` і `NOTICE`. Щоб повідомити про вразливість, дотримуйтеся `SECURITY.md`.

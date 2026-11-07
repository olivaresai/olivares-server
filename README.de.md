<!-- SPDX-FileCopyrightText: 2026 Olivares.AI -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

**Sprachen:** [English](./README.md) · [Español](./README.es.md) · [简体中文](./README.zh.md) · [Русский](./README.ru.md) · [日本語](./README.ja.md) · **Deutsch** · [Français](./README.fr.md) · [Українська](./README.uk.md) · [한국어](./README.ko.md) · [Português](./README.pt.md)

# Olivares Server

Olivares Server ist die Olivares-Appliance: ein Linux-Image, das die Olivares-Engine und die Konsole installiert, dazu eine lokale
Konsole für den Host selbst und die Ersteinrichtung beim ersten Start, mit der das Produkt anläuft.

Dieses Repository enthält das **Rezept** für die Community-Appliance: die Quellen, Image-Definitionen, Dienst-Units,
die SELinux-Richtlinie und die Tests, aus denen das Image gebaut wird.

## Was hier liegt

| Pfad | Inhalt |
| --- | --- |
| `appliance/answers/` | Das Offline-Werkzeug für Antworten. Es prüft ein Antwortdokument und gibt einen Plan aus. |
| `appliance/cmd/`, `appliance/layer/` | Der erste Start, die Appliance Console (`:9443`), die Reparaturkonsole und die Root-Hilfsprogramme, die sie verwendet. |
| `appliance/images/` | Das Image-Rezept (KIWI), der Aufbau von ISO, qcow2 und OVA sowie die festgelegte Build-Toolchain. |
| `appliance/selinux/` | Das SELinux-Richtlinienmodul und die Werkzeuge, die es erzeugen und prüfen. |
| `appliance/test/` | Die Boot-Testreihe und die Rezepttests. |
| `packaging/nfpm/`, `scripts/` | Die beiden Paketdefinitionen und das Skript, das die Nutzdaten der Appliance Console baut. |

`appliance/README.md` beschreibt das Antwortdokument, den ersten Start und die Konsole im Detail.

## Erstellen und Testen

Das Rezept ist gegen den Produktquellcode in [olivaresai/olivares](https://github.com/olivaresai/olivares) geschrieben: Sein
Go-Code importiert Pakete aus dem `core/` dieses Repositorys. Kopieren Sie die Verzeichnisse der obersten Ebene dieses Repositorys an
denselben Pfaden in einen Checkout jenes Repositorys und führen Sie dann die Tests des Moduls in `appliance/` aus, das dafür
einen eigenen Go-Workspace mitbringt:

```sh
git clone https://github.com/olivaresai/olivares-server
git clone --branch "$(cat olivares-server/RELEASE-VERSION)" https://github.com/olivaresai/olivares
cp -r olivares-server/appliance olivares-server/packaging olivares-server/scripts olivares/
cd olivares/appliance && go test ./...
```

Einige Rezepttests lesen die Release-Workflows des Builds, der die Images veröffentlicht. Diese Workflows und ihre
Veröffentlichungshelfer werden mit der lizenzierten Distribution gepflegt; deshalb werden diese Tests hier übersprungen und laufen in jenem Build.

Zum Bauen eines Images brauchen Sie einen KVM-fähigen Host und die in `appliance/images/toolchain/` festgelegte Toolchain. Folgen Sie
`appliance/images/toolchain/README.md`.

## Editionen

Das Image, das dieses Rezept baut, ist die Community-Edition. Der Lizenzdienst, die Business- und Enterprise-Funktionen
und die Pakete, die sie verwenden, sind eigene, lizenzierte Produkte und nicht Teil dieses Repositorys. Ist eine
Business-Lizenz installiert, lässt der Helfer `olivares-entitled-repo` des Images den Paketmanager diese Pakete
aus dem Kanal abrufen, zu dem die Lizenz berechtigt, und `olivares-edition.service` tauscht auf der laufenden Appliance das Community-Paket gegen das Business-Paket
aus und behält dabei deren Daten. Wird die Lizenz entfernt, wird zurückgetauscht. Kein Image enthält ein Business-Paket.

## Wie dieses Repository entsteht

Dieses Repository wird bei jedem Release aus dem Olivares-Entwicklungsquellcode erzeugt. Eröffnen Sie hier keine Pull Requests:
Eine hier vorgenommene Änderung wird mit dem nächsten Release entfernt. Melden Sie Probleme und schlagen Sie Änderungen in
[olivaresai/olivares](https://github.com/olivaresai/olivares/issues) vor.

## Lizenz

AGPL-3.0-only. Siehe `LICENSE`, `DISCLAIMER.md` und `NOTICE`. Um eine Schwachstelle zu melden, folgen Sie `SECURITY.md`.

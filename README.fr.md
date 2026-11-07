<!-- SPDX-FileCopyrightText: 2026 Olivares.AI -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

**Langues :** [English](./README.md) · [Español](./README.es.md) · [简体中文](./README.zh.md) · [Русский](./README.ru.md) · [日本語](./README.ja.md) · [Deutsch](./README.de.md) · **Français** · [Українська](./README.uk.md) · [한국어](./README.ko.md) · [Português](./README.pt.md)

# Olivares Server

Olivares Server est l'appliance Olivares : une image Linux qui installe le moteur et la console Olivares, une console
locale pour l'hôte lui-même, et la configuration au premier démarrage qui lance le produit.

Ce dépôt contient la **recette** de l'appliance Community : les sources, les définitions d'image, les unités de
service, la politique SELinux et les tests à partir desquels l'image est construite.

## Contenu du dépôt

| Chemin | Contenu |
| --- | --- |
| `appliance/answers/` | L'outil hors ligne de réponses. Il valide un document de réponses et affiche un plan. |
| `appliance/cmd/`, `appliance/layer/` | Le premier démarrage, la console de l'appliance (`:9443`), la console de réparation et les assistants root qu'elle utilise. |
| `appliance/images/` | La recette de l'image (KIWI), l'assemblage de l'ISO, du qcow2 et de l'OVA, et la chaîne d'outils de construction figée. |
| `appliance/selinux/` | Le module de politique SELinux et les outils qui le génèrent et le vérifient. |
| `appliance/test/` | La batterie de tests de démarrage et les tests de la recette. |
| `packaging/nfpm/`, `scripts/` | Les deux définitions de paquet et le script qui construit la charge utile de la console de l'appliance. |

`appliance/README.md` décrit en détail le document de réponses, le premier démarrage et la console.

## Construction et tests

La recette est écrite pour le code source du produit dans [olivaresai/olivares](https://github.com/olivaresai/olivares) : son
code Go importe des paquets du répertoire `core/` de ce dépôt. Copiez les répertoires de premier niveau de ce dépôt dans une copie
de travail de l'autre dépôt, aux mêmes chemins, puis exécutez les tests du module depuis `appliance/`, qui dispose de son propre
espace de travail Go à cet effet :

```sh
git clone https://github.com/olivaresai/olivares-server
git clone --branch "$(cat olivares-server/RELEASE-VERSION)" https://github.com/olivaresai/olivares
cp -r olivares-server/appliance olivares-server/packaging olivares-server/scripts olivares/
cd olivares/appliance && go test ./...
```

Certains tests de la recette lisent les workflows de publication de la construction qui publie les images. Ces workflows et leurs
assistants de publication sont maintenus avec la distribution sous licence ; ces tests sont donc ignorés ici et s'exécutent dans cette construction.

Construire une image demande un hôte compatible KVM et la chaîne d'outils figée dans `appliance/images/toolchain/`. Suivez
`appliance/images/toolchain/README.md`.

## Éditions

L'image que construit cette recette est l'édition Community. Le service de licences, les fonctions Business et Enterprise
et les paquets qu'elles utilisent sont des produits distincts, sous licence, et ne font pas partie de ce dépôt. Lorsqu'une
licence Business est installée, l'assistant `olivares-entitled-repo` de l'image permet au gestionnaire de paquets de récupérer ces paquets
depuis le canal auquel la licence donne droit, et `olivares-edition.service` remplace le paquet Community par le paquet Business
sur l'appliance en fonctionnement, en conservant ses données. La suppression de la licence rétablit le paquet Community. Aucune image ne contient de paquet Business.

## Comment ce dépôt est produit

Ce dépôt est généré à partir du code source de développement d'Olivares à chaque version. N'ouvrez pas de pull requests ici :
une modification faite ici est supprimée à la version suivante. Signalez les problèmes et proposez les modifications dans
[olivaresai/olivares](https://github.com/olivaresai/olivares/issues).

## Licence

AGPL-3.0-only. Voir `LICENSE`, `DISCLAIMER.md` et `NOTICE`. Pour signaler une vulnérabilité, suivez `SECURITY.md`.

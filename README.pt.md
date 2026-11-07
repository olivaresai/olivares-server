<!-- SPDX-FileCopyrightText: 2026 Olivares.AI -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

**Idiomas:** [English](./README.md) · [Español](./README.es.md) · [简体中文](./README.zh.md) · [Русский](./README.ru.md) · [日本語](./README.ja.md) · [Deutsch](./README.de.md) · [Français](./README.fr.md) · [Українська](./README.uk.md) · [한국어](./README.ko.md) · **Português**

# Olivares Server

O Olivares Server é o appliance do Olivares: uma imagem Linux que instala o motor e a consola do Olivares, uma consola
local para o próprio anfitrião e a configuração do primeiro arranque, que inicia o produto.

Este repositório contém a **receita** do appliance Community: as fontes, as definições de imagem, as unidades de serviço,
a política SELinux e os testes a partir dos quais a imagem é construída.

## O que existe aqui

| Caminho | Conteúdo |
| --- | --- |
| `appliance/answers/` | A ferramenta offline de respostas. Valida um documento de respostas e apresenta um plano. |
| `appliance/cmd/`, `appliance/layer/` | O primeiro arranque, a Appliance Console (`:9443`), a consola de reparação e os auxiliares de root que esta utiliza. |
| `appliance/images/` | A receita da imagem (KIWI), a montagem de ISO, qcow2 e OVA, e a cadeia de ferramentas de construção fixada. |
| `appliance/selinux/` | O módulo de política SELinux e as ferramentas que o geram e verificam. |
| `appliance/test/` | A bateria de testes de arranque e os testes da receita. |
| `packaging/nfpm/`, `scripts/` | As duas definições de pacote e o script que constrói a carga útil da Appliance Console. |

O `appliance/README.md` documenta em pormenor o documento de respostas, o primeiro arranque e a consola.

## Construir e testar

A receita é escrita em função do código-fonte do produto em [olivaresai/olivares](https://github.com/olivaresai/olivares): o seu
código Go importa pacotes do `core/` desse repositório. Copiem-se os diretórios de nível superior deste repositório para uma
cópia de trabalho desse repositório, nos mesmos caminhos, e execute-se depois os testes do módulo a partir de `appliance/`, que traz o seu próprio espaço de
trabalho Go para este fim:

```sh
git clone https://github.com/olivaresai/olivares-server
git clone --branch "$(cat olivares-server/RELEASE-VERSION)" https://github.com/olivaresai/olivares
cp -r olivares-server/appliance olivares-server/packaging olivares-server/scripts olivares/
cd olivares/appliance && go test ./...
```

Alguns testes da receita leem os fluxos de trabalho de lançamento da construção que publica as imagens. Esses fluxos e os
respetivos auxiliares de publicação são mantidos com a distribuição licenciada, pelo que esses testes são ignorados aqui e são executados nessa construção.

Construir uma imagem exige um anfitrião com capacidade KVM e a cadeia de ferramentas fixada em `appliance/images/toolchain/`. Siga-se
`appliance/images/toolchain/README.md`.

## Edições

A imagem que esta receita constrói é a edição Community. O serviço de licenciamento, as capacidades Business e Enterprise e
os pacotes que estas utilizam são produtos distintos, licenciados, e não fazem parte deste repositório. Com uma licença
Business instalada, o auxiliar `olivares-entitled-repo` da imagem permite que o gestor de pacotes obtenha esses pacotes
do canal a que a licença dá direito, e o `olivares-edition.service` substitui o pacote Community pelo Business
no appliance em execução, mantendo os respetivos dados. Ao remover a licença, a substituição é revertida. Nenhuma imagem contém um pacote Business.

## Como este repositório é feito

Este repositório é gerado a partir do código-fonte de desenvolvimento do Olivares em cada lançamento. Não abra pull requests aqui:
uma alteração feita aqui é removida pelo lançamento seguinte. Comunique problemas e proponha alterações em
[olivaresai/olivares](https://github.com/olivaresai/olivares/issues).

## Licença

AGPL-3.0-only. Consulte `LICENSE`, `DISCLAIMER.md` e `NOTICE`. Para comunicar uma vulnerabilidade, siga `SECURITY.md`.

<!-- SPDX-FileCopyrightText: 2026 Olivares.AI -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

**言語:** [English](./README.md) · [Español](./README.es.md) · [简体中文](./README.zh.md) · [Русский](./README.ru.md) · **日本語** · [Deutsch](./README.de.md) · [Français](./README.fr.md) · [Українська](./README.uk.md) · [한국어](./README.ko.md) · [Português](./README.pt.md)

# Olivares Server

Olivares Server は Olivares のアプライアンスです。Olivares のエンジンとコンソール、ホスト自身のためのローカルコンソール、そして製品を起動する初回起動時のセットアップをインストールする Linux イメージです。

このリポジトリには、Community アプライアンスの**レシピ**があります。イメージのビルド元となるソース、イメージ定義、サービスユニット、SELinux ポリシー、テストです。

## ここにあるもの

| パス | 内容 |
| --- | --- |
| `appliance/answers/` | オフラインの回答ツールです。回答ドキュメントを一つ検証し、計画を表示します。 |
| `appliance/cmd/`, `appliance/layer/` | 初回起動、アプライアンスコンソール (`:9443`)、リペアコンソール、およびそれらが使う root ヘルパーです。 |
| `appliance/images/` | イメージのレシピ (KIWI)、ISO、qcow2、OVA の組み立て、そして固定されたビルドツールチェーンです。 |
| `appliance/selinux/` | SELinux ポリシーモジュールと、それを生成して検査するツールです。 |
| `appliance/test/` | 起動テスト群とレシピのテストです。 |
| `packaging/nfpm/`, `scripts/` | 二つのパッケージ定義と、アプライアンスコンソールのペイロードをビルドするスクリプトです。 |

`appliance/README.md` には、回答ドキュメント、初回起動、コンソールの詳細を記載しています。

## ビルドとテスト

このレシピは [olivaresai/olivares](https://github.com/olivaresai/olivares) の製品ソースを前提に書かれています。Go コードはそのリポジトリの `core/` からパッケージをインポートします。このリポジトリのトップレベルのディレクトリを、そのリポジトリのチェックアウトに同じパスでコピーし、`appliance/` からモジュールのテストを実行してください。このディレクトリには、この目的のための独自の Go ワークスペースがあります。

```sh
git clone https://github.com/olivaresai/olivares-server
git clone --branch "$(cat olivares-server/RELEASE-VERSION)" https://github.com/olivaresai/olivares
cp -r olivares-server/appliance olivares-server/packaging olivares-server/scripts olivares/
cd olivares/appliance && go test ./...
```

一部のレシピのテストは、イメージを公開するビルドのリリースワークフローを読み取ります。それらのワークフローと公開用ヘルパーはライセンス版ディストリビューションとともに管理されているため、これらのテストはここではスキップされ、そのビルドで実行されます。

イメージのビルドには、KVM を使えるホストと、`appliance/images/toolchain/` に固定されたツールチェーンが必要です。`appliance/images/toolchain/README.md` に従ってください。

## エディション

このレシピがビルドするイメージは Community エディションです。ライセンスサービス、Business と Enterprise の機能、およびそれらが使うパッケージは、別個のライセンス製品であり、このリポジトリには含まれません。Business のライセンスをインストールすると、イメージの `olivares-entitled-repo` ヘルパーにより、パッケージマネージャーがそのライセンスで利用できるチャネルからそれらのパッケージを取得できるようになり、`olivares-edition.service` が、稼働中のアプライアンスで Community パッケージを Business のパッケージに入れ替えます。データはそのまま保持されます。ライセンスを削除すると元に戻ります。Business のパッケージを含むイメージはありません。

## このリポジトリの作られ方

このリポジトリは、リリースごとに Olivares の開発ソースから生成されます。ここにプルリクエストを送らないでください。ここで行った変更は次のリリースで削除されます。問題の報告と変更の提案は [olivaresai/olivares](https://github.com/olivaresai/olivares/issues) にお願いします。

## ライセンス

AGPL-3.0-only です。`LICENSE`、`DISCLAIMER.md`、`NOTICE` を参照してください。脆弱性を報告するには、`SECURITY.md` に従ってください。

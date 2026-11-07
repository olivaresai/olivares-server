<!-- SPDX-FileCopyrightText: 2026 Olivares.AI -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

**语言:** [English](./README.md) · [Español](./README.es.md) · **简体中文** · [Русский](./README.ru.md) · [日本語](./README.ja.md) · [Deutsch](./README.de.md) · [Français](./README.fr.md) · [Українська](./README.uk.md) · [한국어](./README.ko.md) · [Português](./README.pt.md)

# Olivares Server

Olivares Server 是 Olivares 一体机：一个 Linux 镜像，安装 Olivares 引擎和控制台、供主机本身使用的本地控制台，以及启动产品的首次启动设置。

本仓库存放 Community 一体机的**配方**：构建该镜像所用的源码、镜像定义、服务单元、SELinux 策略和测试。

## 这里有什么

| 路径 | 内容 |
| --- | --- |
| `appliance/answers/` | 离线应答工具。它验证一份应答文档并输出计划。 |
| `appliance/cmd/`, `appliance/layer/` | 首次启动、一体机控制台（`:9443`）、修复控制台及其使用的 root 辅助程序。 |
| `appliance/images/` | 镜像配方（KIWI）、ISO、qcow2 和 OVA 的组装，以及固定版本的构建工具链。 |
| `appliance/selinux/` | SELinux 策略模块，以及生成和检查它的工具。 |
| `appliance/test/` | 启动测试集和配方测试。 |
| `packaging/nfpm/`, `scripts/` | 两个软件包定义，以及构建一体机控制台载荷的脚本。 |

`appliance/README.md` 详细说明应答文档、首次启动和控制台。

## 构建和测试

该配方是针对产品源码 [olivaresai/olivares](https://github.com/olivaresai/olivares) 编写的：其 Go 代码从该仓库的 `core/` 导入软件包。请把本仓库的顶层目录按相同路径复制到该仓库的检出副本中，然后在 `appliance/` 下运行该模块的测试；该目录为此带有自己的 Go 工作区：

```sh
git clone https://github.com/olivaresai/olivares-server
git clone --branch "$(cat olivares-server/RELEASE-VERSION)" https://github.com/olivaresai/olivares
cp -r olivares-server/appliance olivares-server/packaging olivares-server/scripts olivares/
cd olivares/appliance && go test ./...
```

部分配方测试会读取发布镜像的构建所用的发布工作流。这些工作流及其发布辅助程序随许可分发版本一同维护，因此这些测试在此处跳过，在该构建中运行。

构建镜像需要支持 KVM 的主机，以及固定在 `appliance/images/toolchain/` 中的工具链。请按照 `appliance/images/toolchain/README.md` 操作。

## 版本

此配方构建的镜像是 Community 版。许可服务、Business 和 Enterprise 的功能及其使用的软件包是独立的许可产品，不属于本仓库。安装 Business 许可证后，镜像的 `olivares-entitled-repo` 辅助程序会让软件包管理器从该许可证所授权的渠道获取这些软件包，而 `olivares-edition.service` 会在运行中的一体机上把 Community 软件包换成 Business 软件包，并保留其数据。移除许可证后会换回。没有任何镜像包含 Business 软件包。

## 本仓库如何生成

本仓库在每次发布时由 Olivares 开发源码生成。请不要在此处提交拉取请求：在此处所做的更改会被下一次发布删除。请在 [olivaresai/olivares](https://github.com/olivaresai/olivares/issues) 报告问题并提出更改建议。

## 许可证

AGPL-3.0-only。参见 `LICENSE`、`DISCLAIMER.md` 和 `NOTICE`。要报告漏洞，请按照 `SECURITY.md` 操作。

<!-- SPDX-FileCopyrightText: 2026 Olivares.AI -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

**언어:** [English](./README.md) · [Español](./README.es.md) · [简体中文](./README.zh.md) · [Русский](./README.ru.md) · [日本語](./README.ja.md) · [Deutsch](./README.de.md) · [Français](./README.fr.md) · [Українська](./README.uk.md) · **한국어** · [Português](./README.pt.md)

# Olivares Server

Olivares Server는 Olivares 어플라이언스입니다. Olivares 엔진과 콘솔, 호스트 자체를 위한 로컬 콘솔, 제품을 시작하는 최초 부팅 설정을 설치하는 Linux 이미지입니다.

이 저장소에는 Community 어플라이언스의 **레시피**가 들어 있습니다. 이미지를 빌드하는 데 쓰이는 소스, 이미지 정의, 서비스 유닛, SELinux 정책, 테스트입니다.

## 구성 내용

| 경로 | 내용 |
| --- | --- |
| `appliance/answers/` | 오프라인 answers 도구입니다. answers 문서 하나를 검증하고 계획을 출력합니다. |
| `appliance/cmd/`, `appliance/layer/` | 최초 부팅, 어플라이언스 콘솔(`:9443`), 복구 콘솔, 그리고 이들이 사용하는 root 헬퍼입니다. |
| `appliance/images/` | 이미지 레시피(KIWI), ISO, qcow2, OVA 조립, 그리고 고정된 빌드 툴체인입니다. |
| `appliance/selinux/` | SELinux 정책 모듈과 이를 생성하고 검사하는 도구입니다. |
| `appliance/test/` | 부팅 테스트 묶음과 레시피 테스트입니다. |
| `packaging/nfpm/`, `scripts/` | 두 개의 패키지 정의와 어플라이언스 콘솔 페이로드를 빌드하는 스크립트입니다. |

`appliance/README.md`에 answers 문서, 최초 부팅, 콘솔이 자세히 설명되어 있습니다.

## 빌드와 테스트

이 레시피는 [olivaresai/olivares](https://github.com/olivaresai/olivares)의 제품 소스를 기준으로 작성되었습니다. Go 코드가 해당 저장소의 `core/`에 있는 패키지를 임포트합니다. 이 저장소의 최상위 디렉터리를 해당 저장소의 체크아웃에 같은 경로로 복사한 다음, 이 용도로 자체 Go 워크스페이스를 갖춘 `appliance/`에서 모듈의 테스트를 실행하세요.

```sh
git clone https://github.com/olivaresai/olivares-server
git clone --branch "$(cat olivares-server/RELEASE-VERSION)" https://github.com/olivaresai/olivares
cp -r olivares-server/appliance olivares-server/packaging olivares-server/scripts olivares/
cd olivares/appliance && go test ./...
```

일부 레시피 테스트는 이미지를 게시하는 빌드의 릴리스 워크플로를 읽습니다. 그 워크플로와 게시 헬퍼는 라이선스가 적용되는 배포판과 함께 관리되므로, 해당 테스트는 여기서는 건너뛰고 그 빌드에서 실행됩니다.

이미지를 빌드하려면 KVM을 지원하는 호스트와 `appliance/images/toolchain/`에 고정된 툴체인이 필요합니다. `appliance/images/toolchain/README.md`를 따르세요.

## 에디션

이 레시피가 빌드하는 이미지는 Community 에디션입니다. 라이선스 서비스, Business와 Enterprise 기능, 그리고 그 기능이 사용하는 패키지는 별도의 라이선스 제품이며 이 저장소에 포함되지 않습니다. Business 라이선스가 설치되어 있으면 이미지의 `olivares-entitled-repo` 헬퍼가 패키지 관리자로 하여금 라이선스가 사용 권한을 부여하는 채널에서 해당 패키지를 가져오게 하고, `olivares-edition.service`가 실행 중인 어플라이언스에서 Community 패키지를 Business 패키지로 교체하며 데이터는 그대로 유지합니다. 라이선스를 제거하면 다시 원래대로 교체됩니다. 어떤 이미지에도 Business 패키지는 들어 있지 않습니다.

## 이 저장소가 만들어지는 방식

이 저장소는 릴리스마다 Olivares 개발 소스에서 생성됩니다. 여기에 풀 리퀘스트를 열지 마세요. 여기서 한 변경은 다음 릴리스에서 제거됩니다. 문제 보고와 변경 제안은 [olivaresai/olivares](https://github.com/olivaresai/olivares/issues)에 해 주세요.

## 라이선스

AGPL-3.0-only입니다. `LICENSE`, `DISCLAIMER.md`, `NOTICE`를 참조하세요. 취약점을 신고하려면 `SECURITY.md`를 따르세요.

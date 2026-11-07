<!-- SPDX-FileCopyrightText: 2026 Olivares.AI -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

**Idiomas:** [English](./README.md) · **Español** · [简体中文](./README.zh.md) · [Русский](./README.ru.md) · [日本語](./README.ja.md) · [Deutsch](./README.de.md) · [Français](./README.fr.md) · [Українська](./README.uk.md) · [한국어](./README.ko.md) · [Português](./README.pt.md)

# Olivares Server

Olivares Server es el appliance de Olivares: una imagen de Linux que instala el motor y la consola de Olivares, una
consola local para el propio host y la configuración del primer arranque que pone en marcha el producto.

Este repositorio contiene la **receta** del appliance Community: las fuentes, las definiciones de imagen, las unidades
de servicio, la política de SELinux y las pruebas con las que se construye la imagen.

## Qué hay aquí

| Ruta | Contenido |
| --- | --- |
| `appliance/answers/` | La herramienta de respuestas sin conexión. Valida un documento de respuestas e imprime un plan. |
| `appliance/cmd/`, `appliance/layer/` | El primer arranque, la Appliance Console (`:9443`), la consola de reparación y los ayudantes de root que usa. |
| `appliance/images/` | La receta de la imagen (KIWI), el ensamblado de ISO, qcow2 y OVA, y la cadena de herramientas de compilación fijada. |
| `appliance/selinux/` | El módulo de política de SELinux y las herramientas que lo generan y lo comprueban. |
| `appliance/test/` | La batería de arranque y las pruebas de la receta. |
| `packaging/nfpm/`, `scripts/` | Las dos definiciones de paquete y el script que construye la carga de la Appliance Console. |

`appliance/README.md` documenta con detalle el documento de respuestas, el primer arranque y la consola.

## Compilar y probar

La receta está escrita contra el código fuente del producto en [olivaresai/olivares](https://github.com/olivaresai/olivares): su
código Go importa paquetes del directorio `core/` de ese repositorio. Copia los directorios de primer nivel de este repositorio en una copia
de aquel, en las mismas rutas, y ejecuta después las pruebas del módulo desde `appliance/`, que incluye su propio espacio
de trabajo de Go para este fin:

```sh
git clone https://github.com/olivaresai/olivares-server
git clone --branch "$(cat olivares-server/RELEASE-VERSION)" https://github.com/olivaresai/olivares
cp -r olivares-server/appliance olivares-server/packaging olivares-server/scripts olivares/
cd olivares/appliance && go test ./...
```

Algunas pruebas de la receta leen los flujos de trabajo de versión de la compilación que publica las imágenes. Esos flujos y sus
ayudantes de publicación se mantienen con la distribución con licencia, así que esas pruebas se omiten aquí y se ejecutan en esa compilación.

Construir una imagen requiere un host compatible con KVM y la cadena de herramientas fijada en `appliance/images/toolchain/`. Sigue
`appliance/images/toolchain/README.md`.

## Ediciones

La imagen que construye esta receta es la edición Community. El servicio de licencias, las funciones de Business y Enterprise
y los paquetes que usan son productos independientes, con licencia, y no forman parte de este repositorio. Con una
licencia de Business instalada, el ayudante `olivares-entitled-repo` de la imagen permite que el gestor de paquetes descargue esos paquetes
del canal al que da derecho la licencia, y `olivares-edition.service` cambia el paquete de Community por el de Business
en el appliance en ejecución, conservando sus datos. Al quitar la licencia, se vuelve al paquete anterior. Ninguna imagen contiene un paquete de Business.

## Cómo se genera este repositorio

Este repositorio se genera a partir del código fuente de desarrollo de Olivares en cada versión. No abras pull requests aquí:
el siguiente lanzamiento elimina cualquier cambio hecho aquí. Comunica los problemas y propón cambios en
[olivaresai/olivares](https://github.com/olivaresai/olivares/issues).

## Licencia

AGPL-3.0-only. Consulta `LICENSE`, `DISCLAIMER.md` y `NOTICE`. Para comunicar una vulnerabilidad, sigue `SECURITY.md`.

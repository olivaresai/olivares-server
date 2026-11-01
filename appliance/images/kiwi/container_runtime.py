#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
"""container_runtime.py — Docker's RPMs as the stage step takes them into the image: the locked files, nothing else.

The image reads AlmaLinux's two trees and the product's own repositories, and no third one. The container runtime the
optional apps need (docker-ce, docker-ce-cli, containerd.io, docker-compose-plugin) is not in AlmaLinux, so the lock
(input-lock.json, container_runtime) pins each RPM of Docker's rhel/10 repository by sha256, and this module downloads
exactly those files into the directory the stage step signs and indexes. A mirror that serves other bytes after a push is
refused, not followed. The RPMs keep Docker's own signature: the stage step checks it against Docker's release key
(rpm-payload-sign.py --verify-with), and the build repository names that key beside the per-build one, so dnf checks it
again when it installs them.

stage(SECTION, KEY, DESTINATION) -> the paths written; it writes all four or none.
Refused: the lock pins no package, the key file is not the locked bytes, a download is not the locked sha256 or size, or a
file already exists.
Unable: a download could not be read (a connection error or a stream that ends early)."""
import hashlib
import http.client
import os
from pathlib import Path
import urllib.request

CHUNK = 1 << 20


class Refused(Exception):
    pass


class Unable(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def fetch(name, entry, opener):
    """The bytes of the locked URL, read up to the locked size and one byte more, so a stream that does not end is refused."""
    try:
        with opener(entry["url"], timeout=600) as response:
            body = bytearray()
            while len(body) <= entry["size"]:
                chunk = response.read(CHUNK)
                if not chunk:
                    return bytes(body)
                body += chunk
    except (OSError, http.client.HTTPException) as issue:
        raise Unable("%s: cannot read %s: %s" % (name, entry["url"], issue))
    raise Refused("%s: %s serves more than the locked %d bytes" % (name, entry["url"], entry["size"]))


def stage(section, key, destination, opener=urllib.request.urlopen):
    try:
        data = Path(key).read_bytes()
    except OSError as issue:
        raise Unable("the vendor key %s cannot be read: %s" % (key, issue))
    if sha256(data) != section["key"]["sha256"]:
        raise Refused("the vendor key %s has sha256 %s; the lock pins %s" % (key, sha256(data), section["key"]["sha256"]))
    if not section["packages"]:
        raise Refused("the lock pins no container runtime package")
    written = []
    try:
        for name, entry in sorted(section["packages"].items()):
            path = Path(destination) / Path(entry["href"]).name
            if path.exists():
                raise Refused("%s already exists" % path)
            body = fetch(name, entry, opener)
            if sha256(body) != entry["sha256"]:
                raise Refused("%s: %s has sha256 %s; the lock pins %s" % (name, entry["url"], sha256(body), entry["sha256"]))
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            written.append(path)
            with os.fdopen(descriptor, "wb") as out:
                out.write(body)
    except BaseException:
        for path in written:
            path.unlink(missing_ok=True)
        raise
    return written

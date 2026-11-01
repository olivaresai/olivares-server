#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
"""write_delivery.py — the RPM main-header reader release_outputs.py imports (header_fields).

delivery.json has one writer: scripts/render-rpm-repodata.py render (qualification-delivery.sh and stage_almalinux.py run it).
This module writes nothing."""

# Main header tags (rpmtag.h): NAME 1000, VERSION 1001, RELEASE 1002, EPOCH 1003 (int32), ARCH 1022.
NAME, VERSION, RELEASE, EPOCH, ARCH = 1000, 1001, 1002, 1003, 1022


def header_fields(data):
    if data[:4] != b"\xed\xab\xee\xdb":
        raise ValueError("not an RPM file")
    offset = 96
    for which in ("signature", "main"):
        if data[offset:offset + 3] != b"\x8e\xad\xe8":
            raise ValueError("no %s header" % which)
        count = int.from_bytes(data[offset + 8:offset + 12], "big")
        size = int.from_bytes(data[offset + 12:offset + 16], "big")
        store = offset + 16 + 16 * count
        if which == "signature":
            offset = store + size + (-(store + size) % 8)
            continue
        fields = {}
        for i in range(count):
            tag, kind, where, _ = (int.from_bytes(data[offset + 16 + 16 * i + 4 * j:offset + 20 + 16 * i + 4 * j], "big")
                                   for j in range(4))
            if kind == 6:
                end = data.index(b"\0", store + where)
                fields[tag] = data[store + where:end].decode()
            elif kind == 4:
                fields[tag] = int.from_bytes(data[store + where:store + where + 4], "big")
        return fields
    raise ValueError("unreachable")

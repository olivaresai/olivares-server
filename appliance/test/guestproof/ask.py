#!/usr/bin/python3
# SPDX-FileCopyrightText: 2026 Olivares.AI
# SPDX-License-Identifier: AGPL-3.0-only
# Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.
"""Guest fixture of the helper seam's proof: send one document to a helper's socket.

ask.py SOCKET DOCUMENT          print the helper's one answer line
ask.py SOCKET DOCUMENT --leave  write the document, record this process's pid in the file named by
                                GUESTPROOF_PIDFILE and exit without reading, so the connection's peer
                                is a dead process by the time the helper instance looks at it
Never shipped; runs in a disposable guest.
"""
import os
import socket
import sys


def main():
    path, document = sys.argv[1], sys.argv[2]
    leave = len(sys.argv) > 3 and sys.argv[3] == "--leave"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(path)
    s.sendall(document.encode() + b"\n")
    if leave:
        with open(os.environ["GUESTPROOF_PIDFILE"], "w") as f:
            f.write(str(os.getpid()))
        os._exit(0)
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    sys.stdout.write(data.decode())


main()

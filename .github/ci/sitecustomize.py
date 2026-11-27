"""CI-only Python network guard, inherited by ordinary Python subprocesses."""
import ipaddress
import os
from pathlib import Path
import socket
import sys

ACTIVE = False
if os.environ.get("WG_CI_EVIDENCE"):
    _log = Path(os.environ["WG_CI_EVIDENCE"]) / "blocked-network.txt"
    _resolve = socket.getaddrinfo

    def _guard(event, args):
        if event in {"socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg"}:
            address = args[1]
            host = address[0] if isinstance(address, tuple) else None
        elif event in {"socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr"}:
            host = args[0]
        elif event == "socket.getnameinfo":
            host = args[0][0]
        else:
            return
        try:
            local = ipaddress.ip_address(host).is_loopback
        except (TypeError, ValueError):
            local = False
        if not local:
            try:
                with _log.open("a", encoding="utf-8") as evidence:
                    evidence.write(event + "\n")
            finally:
                raise AssertionError("Non-loopback network operation blocked by CI")

    def _loopback_lookup(host, *args, **kwargs):
        return _resolve("127.0.0.1" if host == "localhost" else host, *args, **kwargs)

    sys.addaudithook(_guard)
    socket.getaddrinfo = _loopback_lookup
    ACTIVE = True

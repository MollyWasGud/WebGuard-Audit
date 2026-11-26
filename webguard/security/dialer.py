"""Bind an operation to one explicitly approved numeric socket address."""

import ipaddress
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass
from math import isfinite
from time import monotonic


class UnauthorizedDial(PermissionError):
    """An operation did not match its transport authorization."""


def _identity(host: str) -> str:
    if type(host) is not str or not host or "%" in host:
        raise UnauthorizedDial("Invalid transport hostname")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        name = host.removesuffix(".").lower()
        labels = name.split(".")
        if (
            len(name) > 253
            or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in labels
            )
            or all(re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]+)", label) for label in labels)
        ):
            raise UnauthorizedDial("Invalid transport hostname") from None
        return name


@dataclass(frozen=True)
class AuthorizedTransport:
    """Use a peer already approved for this origin."""

    scheme: str
    hostname: str
    port: int
    peer: str
    deadline: float | None = None
    cancelled: Callable[[], bool] | None = None

    def __post_init__(self) -> None:
        if (
            type(self.scheme) is not str
            or self.scheme not in ("http", "https")
            or type(self.port) is not int
            or not 1 <= self.port <= 65535
            or (
                self.deadline is not None
                and (
                    type(self.deadline) not in (int, float)
                    or not isfinite(self.deadline)
                )
            )
            or (self.cancelled is not None and not callable(self.cancelled))
        ):
            raise UnauthorizedDial("Invalid transport authorization")
        identity = _identity(self.hostname)
        if type(self.peer) is not str or "%" in self.peer:
            raise UnauthorizedDial("Transport peer must be an unscoped numeric address")
        try:
            address = ipaddress.ip_address(self.peer)
        except ValueError:
            raise UnauthorizedDial("Transport peer must be numeric") from None
        if (
            address.is_unspecified
            or address.is_multicast
            or (address.version == 6 and address.is_link_local)
        ):
            raise UnauthorizedDial("Invalid transport peer")
        try:
            literal = ipaddress.ip_address(identity)
        except ValueError:
            pass
        else:
            if address != literal:
                raise UnauthorizedDial(
                    "Transport peer does not match the numeric origin"
                )
        object.__setattr__(self, "hostname", identity)
        object.__setattr__(self, "peer", str(address))

    def checkpoint(self, timeout: float) -> float:
        if self.cancelled is not None and self.cancelled():
            raise KeyboardInterrupt
        if type(timeout) not in (int, float) or not isfinite(timeout) or timeout <= 0:
            raise UnauthorizedDial("Invalid transport timeout")
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - monotonic())
            if timeout <= 0:
                raise TimeoutError("Audit deadline expired")
        return timeout

    def connect(
        self, scheme: str, hostname: str, port: int, timeout: float
    ) -> socket.socket:
        if type(port) is not int or (scheme, _identity(hostname), port) != (
            self.scheme,
            self.hostname,
            self.port,
        ):
            raise UnauthorizedDial("Operation does not match its authorized origin")
        remaining = self.checkpoint(timeout)
        ipv6 = ":" in self.peer
        address = (self.peer, self.port, 0, 0) if ipv6 else (self.peer, self.port)
        peer = socket.socket(
            socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM
        )
        try:
            peer.settimeout(remaining)
            peer.connect(address)
        except BaseException:
            try:
                peer.close()
            except OSError:
                pass
            raise
        return peer

"""Loopback-only TCP relay from the Windows Wazuh Agent to a dynamic WSL2 manager.

The relay resolves the selected WSL distribution for every new connection, so a WSL2 NAT address
change does not require rewriting the Windows Agent configuration. It does not terminate or weaken
Wazuh's authenticated transport; bytes pass through unchanged.
"""

from __future__ import annotations

import argparse
import ipaddress
import selectors
import socket
import socketserver
import subprocess
import threading
from collections.abc import Sequence


BUFFER_BYTES = 65_536
MAX_CONNECTIONS = 8
RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def choose_wsl_address(output: str) -> str:
    """Select one private, non-loopback IPv4 address from `hostname -I` output."""

    for candidate in output.split():
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if (
            isinstance(address, ipaddress.IPv4Address)
            and not address.is_loopback
            and any(address in network for network in RFC1918_NETWORKS)
        ):
            return str(address)
    raise RuntimeError("WSL did not report a private IPv4 address")


def resolve_wsl_address(distro: str) -> str:
    result = subprocess.run(
        ["wsl.exe", "-d", distro, "--", "hostname", "-I"],
        capture_output=True,
        check=False,
        text=True,
        timeout=5,
    )
    if result.returncode != 0:
        raise RuntimeError("Unable to resolve the WSL manager address")
    return choose_wsl_address(result.stdout)


def relay_sockets(client: socket.socket, upstream: socket.socket) -> None:
    selector = selectors.DefaultSelector()
    selector.register(client, selectors.EVENT_READ, upstream)
    selector.register(upstream, selectors.EVENT_READ, client)
    try:
        while True:
            events = selector.select(timeout=60)
            if not events:
                continue
            for key, _ in events:
                source = key.fileobj
                destination = key.data
                data = source.recv(BUFFER_BYTES)
                if not data:
                    return
                destination.sendall(data)
    finally:
        selector.close()


class RelayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], handler: type[socketserver.BaseRequestHandler], *, distro: str, manager_port: int) -> None:
        super().__init__(address, handler)
        self.distro = distro
        self.manager_port = manager_port
        self.capacity = threading.BoundedSemaphore(MAX_CONNECTIONS)


class RelayHandler(socketserver.BaseRequestHandler):
    server: RelayServer

    def handle(self) -> None:
        if not self.server.capacity.acquire(blocking=False):
            return
        try:
            manager_address = resolve_wsl_address(self.server.distro)
            with socket.create_connection((manager_address, self.server.manager_port), timeout=5) as upstream:
                self.request.settimeout(None)
                upstream.settimeout(None)
                relay_sockets(self.request, upstream)
        except (OSError, RuntimeError, subprocess.SubprocessError):
            # No telemetry or credentials are logged. The Wazuh Agent performs its own retry.
            return
        finally:
            self.server.capacity.release()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--distro", default="Ubuntu-24.04")
    result.add_argument("--listen-address", default="127.0.0.1")
    result.add_argument("--listen-port", type=int, default=2514)
    result.add_argument("--manager-port", type=int, default=1514)
    return result


def main(arguments: Sequence[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    listen_address = ipaddress.ip_address(args.listen_address)
    if not listen_address.is_loopback:
        raise SystemExit("--listen-address must be loopback")
    if not 1024 <= args.listen_port <= 65_535:
        raise SystemExit("--listen-port must be between 1024 and 65535")
    if not 1 <= args.manager_port <= 65_535:
        raise SystemExit("--manager-port must be between 1 and 65535")
    with RelayServer(
        (str(listen_address), args.listen_port),
        RelayHandler,
        distro=args.distro,
        manager_port=args.manager_port,
    ) as server:
        server.serve_forever(poll_interval=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Tabla de vecinos del kernel: lectura, sondeo y vigilancia por netlink.

NETLINK_ROUTE no requiere CAP_NET_RAW, así que en esta VM es la única fuente de
verdad ARP en vivo. Se usa para descubrir equipos y para detectar cambios de
binding (IP -> MAC), que es la huella de un ARP spoofing dirigido al sensor.
"""
from __future__ import annotations

import errno
import ipaddress
import logging
import selectors
import socket
import struct
import subprocess
import threading
import time
from typing import Callable, Iterator

from batrade.detect.observation import NEIGH, Observation
from batrade.net.iputil import normalize_mac, valid_ipv4
from batrade.net.proc import env_minimo

log = logging.getLogger("batrade.neigh")

AF_NETLINK = 16
NETLINK_ROUTE = 0
RTMGRP_NEIGH = 4
RTM_NEWNEIGH = 28
RTM_DELNEIGH = 29
NLMSG_DONE = 3
NDA_DST = 1
NDA_LLADDR = 2
NUD_DEAD = 1 | 32  # INCOMPLETE | FAILED

VALID_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP"}


# --------------------------------------------------------------------------- #
# Lectura y sondeo
# --------------------------------------------------------------------------- #
def read_neighbors(iface: str | None = None) -> dict[str, str]:
    """IP -> MAC según el kernel. Sólo entradas resueltas y usables."""
    cmd = ["ip", "-4", "neigh", "show"]
    if iface:
        cmd += ["dev", iface]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=8,
                             check=False, env=env_minimo()).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("no se pudo leer la tabla de vecinos: %s", exc)
        return {}
    result: dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        ip = valid_ipv4(parts[0])
        if not ip or "lladdr" not in parts:
            continue
        try:
            mac = normalize_mac(parts[parts.index("lladdr") + 1])
        except (ValueError, IndexError):
            continue
        state = parts[-1].upper()
        if mac and state in VALID_STATES:
            result[ip] = mac
    return result


def probe_cidr(cidr: str, *, port: int = 9, timeout: float = 0.35,
               concurrency: int = 128) -> int:
    """Fuerza la resolución ARP de cada IP sin CAP_NET_RAW.

    Un connect TCP no privilegiado obliga al kernel a resolver el vecino antes
    de enviar el SYN. Aunque el puerto esté cerrado, un host vivo aparece en la
    tabla de vecinos. Devuelve cuántos sockets llegaron a conectar.

    Usa ``selectors`` (epoll) en vez de ``select.select``: aquel revienta con
    más de ``FD_SETSIZE`` descriptores. El cierre va en ``finally`` para que un
    fallo del selector no deje sockets abiertos.
    """
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return 0
    targets = [str(h) for h in net.hosts()
               if h != ipaddress.IPv4Address("255.255.255.255")]
    lote = max(1, min(int(concurrency), 1024))
    connected = 0
    for start in range(0, len(targets), lote):
        batch = targets[start:start + lote]
        socks: list[socket.socket] = []
        try:
            for ip in batch:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setblocking(False)
                try:
                    sock.connect((ip, port))
                except BlockingIOError:
                    socks.append(sock)
                except OSError:
                    sock.close()
                    continue
            if socks:
                with selectors.DefaultSelector() as selector:
                    for sock in socks:
                        selector.register(sock, selectors.EVENT_WRITE)
                    for clave, _eventos in selector.select(timeout):
                        sock = clave.fileobj
                        try:
                            error = sock.getsockopt(socket.SOL_SOCKET,
                                                    socket.SO_ERROR)
                        except OSError:
                            continue
                        # 0 = conectado; ECONNREFUSED = host vivo con el puerto
                        # cerrado. El resto (sin ruta, inalcanzable) no cuenta.
                        if error in (0, errno.ECONNREFUSED):
                            connected += 1
        except (OSError, ValueError):
            # Un fallo del selector no puede tumbar el barrido; se cierra abajo.
            pass
        finally:
            for sock in socks:
                try:
                    sock.close()
                except OSError:
                    pass
    return connected


# --------------------------------------------------------------------------- #
# Netlink
# --------------------------------------------------------------------------- #
def _align(length: int) -> int:
    return (length + 3) & ~3


def _parse_attrs(body: bytes, offset: int) -> tuple[str | None, str | None]:
    ip: str | None = None
    mac: str | None = None
    while offset + 4 <= len(body):
        alen, atype = struct.unpack_from("=HH", body, offset)
        if alen < 4:
            break
        payload = body[offset + 4:offset + alen]
        if atype == NDA_DST and len(payload) >= 4:
            ip = socket.inet_ntop(socket.AF_INET, payload[:4])
        elif atype == NDA_LLADDR and len(payload) >= 6:
            mac = ":".join(f"{b:02x}" for b in payload[:6])
        offset += _align(alen)
    return ip, mac


def parse_netlink(data: bytes) -> Iterator[tuple[str, str]]:
    """Extrae (ip, mac) de un datagrama NETLINK_ROUTE."""
    offset = 0
    total = len(data)
    while offset + 16 <= total:
        nl_len, nl_type, _flags, _seq, _pid = struct.unpack_from("=IHHII", data, offset)
        if nl_len < 16 or offset + nl_len > total:
            break
        body = data[offset + 16:offset + nl_len]
        offset += _align(nl_len)
        if nl_type not in (RTM_NEWNEIGH, RTM_DELNEIGH):
            continue
        if len(body) < 12:
            continue
        family, _p1, _p2, _ifindex, state = struct.unpack_from("=BBHiH", body, 0)
        if family != socket.AF_INET:
            continue
        if nl_type == RTM_DELNEIGH:
            continue
        if state & NUD_DEAD or state == 0:
            continue
        ip, mac = _parse_attrs(body, 12)
        if ip and mac:
            yield (ip, mac)


class NeighborWatcher(threading.Thread):
    """Hilo que entrega cambios de binding IP/MAC en tiempo real.

    Primero intenta netlink; si el grupo no está disponible cae a sondeo de la
    tabla de vecinos cada ``poll_interval``. Ambas rutas son sin privilegios.
    """

    def __init__(self, on_observation: Callable[[Observation], None],
                 iface: str | None = None, poll_interval: float = 2.0,
                 stop_event: threading.Event | None = None):
        super().__init__(name="batrade-neigh", daemon=True)
        self.on_observation = on_observation
        self.iface = iface
        self.poll_interval = poll_interval
        self.stop_event = stop_event or threading.Event()
        self.backend = "unknown"
        self._known: dict[str, str] = {}

    def run(self) -> None:
        try:
            self._run_netlink()
        except Exception as exc:  # noqa: BLE001 - cualquier fallo cae a sondeo
            log.warning("netlink no disponible (%s); se usa sondeo", exc)
            self.backend = "poll"
            self._run_poll()

    def _run_netlink(self) -> None:
        sock = socket.socket(AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
        try:
            sock.bind((0, RTMGRP_NEIGH))
            sock.settimeout(1.0)
            self.backend = "netlink"
            log.info("vigilancia de vecinos por netlink activa")
            while not self.stop_event.is_set():
                try:
                    data, _ = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    raise
                for ip, mac in parse_netlink(data):
                    self._emit(ip, mac)
        finally:
            sock.close()

    def _run_poll(self) -> None:
        while not self.stop_event.is_set():
            for ip, mac in read_neighbors(self.iface).items():
                self._emit(ip, mac)
            self.stop_event.wait(self.poll_interval)

    def _emit(self, ip: str, mac: str) -> None:
        mac_n = normalize_mac(mac)
        if not mac_n:
            return
        previous = self._known.get(ip)
        self._known[ip] = mac_n
        if previous == mac_n:
            return  # sin cambio: ni inventario ni evento
        event = "new" if previous is None else "change"
        try:
            self.on_observation(Observation(kind=NEIGH, ts=int(time.time() * 1000),
                                            ip_src=ip, mac_src=mac_n,
                                            extra={"event": event, "iface": self.iface}))
        except Exception:
            log.exception("fallo procesando evento de vecino")

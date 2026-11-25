"""Detección de interfaces IPv4 (Ethernet y Wi-Fi) sin privilegios.

El sensor debe poder arrancar en cualquier portátil, VM o mini-PC sin editar
``config.yaml`` a mano. La regla es simple: se usa la interfaz de la ruta por
defecto (la red que el equipo utiliza de verdad) y, si no hay ruta por defecto,
se prefiere una interfaz cableada con dirección privada frente a una Wi-Fi o un
puente virtual de Docker/libvirt.

Todo se apoya en ``ip`` (iproute2) con respaldo de ``/sys/class/net``; nunca se
abren sockets ni se requieren privilegios.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from batrade.net.iputil import (interface_ipv4, is_multicast_mac, normalize_mac,
                                rfc1918, valid_ipv4)
from batrade.net.proc import env_minimo

log = logging.getLogger("batrade.ifaces")

SYSFS = Path("/sys/class/net")

# Nombres de interfaces de virtualización/contendores que no son la LAN del
# operador. ``vmnet*`` y ``vmbr*`` se dejan fuera a propósito: pueden ser la red
# que se quiere vigilar en un laboratorio.
VIRTUAL_PREFIXES = (
    "docker", "veth", "virbr", "br-", "tap", "tun", "vnet",
    "cni", "flannel", "kube", "podman", "tailscale", "zt",
)

AUTO_VALUES = ("", "auto", "any", "detect", "detectar")

# ``ip -o``: "2: wlp2s0    inet 192.168.0.50/24 brd ... scope global ..."
_O_LINE = re.compile(r"^\d+:\s+([^:\s@]+)(?:@[^:\s]+)?\s+")
_INET = re.compile(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)")
_ROUTE_DEV = re.compile(r"\bdev\s+(\S+)")


@dataclass(slots=True)
class IfaceInfo:
    """Una interfaz IPv4 con lo mínimo para decidir y mostrarla en el panel."""

    name: str
    ip: str | None = None
    prefixlen: int | None = None
    mac: str | None = None
    up: bool = False
    wireless: bool = False
    default: bool = False

    @property
    def cidr(self) -> str | None:
        """Subred derivada de la IP y la máscara, ya normalizada."""
        if not self.ip or self.prefixlen is None:
            return None
        try:
            return str(ipaddress.IPv4Network(f"{self.ip}/{self.prefixlen}", strict=False))
        except ValueError:
            return None

    @property
    def kind(self) -> str:
        if self.loopback:
            return "loopback"
        return "wi-fi" if self.wireless else "ethernet"

    @property
    def virtual(self) -> bool:
        return self.name.startswith(VIRTUAL_PREFIXES)

    @property
    def loopback(self) -> bool:
        return self.name == "lo" or bool(self.ip and self.ip.startswith("127."))

    def address(self) -> str:
        if not self.ip:
            return "sin IPv4"
        return f"{self.ip}/{self.prefixlen}" if self.prefixlen is not None else self.ip


# --------------------------------------------------------------------------- #
# Sondas del sistema
# --------------------------------------------------------------------------- #
def _run(argv: list[str], timeout: float = 5.0) -> str | None:
    """Ejecuta una consulta de ``ip`` y devuelve stdout. Nunca lanza."""
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False,
            env=env_minimo(),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def mac_of(name: str | None) -> str | None:
    if not name:
        return None
    try:
        raw = (SYSFS / name / "address").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    mac = normalize_mac(raw)
    return None if is_multicast_mac(mac) else mac


def is_wireless(name: str | None) -> bool:
    """Wi-Fi si el kernel expone ``wireless``/``phy80211`` para esa interfaz."""
    if not name:
        return False
    base = SYSFS / name
    return (base / "wireless").exists() or (base / "phy80211").exists()


def exists(name: str | None) -> bool:
    return bool(name) and (SYSFS / str(name)).exists()


# --------------------------------------------------------------------------- #
# Parseo de ``ip``
# --------------------------------------------------------------------------- #
def _parse_json(raw: str) -> list[IfaceInfo]:
    rows: list[IfaceInfo] = []
    for entry in json.loads(raw):
        name = entry.get("ifname")
        if not name:
            continue
        flags = set(entry.get("flags") or [])
        up = "UP" in flags or entry.get("operstate") == "UP"
        mac = mac_of(name)
        wireless = is_wireless(name)
        for addr in entry.get("addr_info") or []:
            if addr.get("family") != "inet":
                continue
            ip = valid_ipv4(addr.get("local"))
            plen = addr.get("prefixlen")
            if not ip or plen is None:
                continue
            rows.append(IfaceInfo(name=name, ip=ip, prefixlen=int(plen), mac=mac,
                                  up=up, wireless=wireless))
            break
    return rows


def _parse_text(raw: str) -> list[IfaceInfo]:
    rows: list[IfaceInfo] = []
    for line in raw.splitlines():
        match = _O_LINE.match(line)
        addr = _INET.search(line)
        if not match or not addr:
            continue
        name = match.group(1)
        ip = valid_ipv4(addr.group(1))
        if not ip:
            continue
        rows.append(IfaceInfo(
            name=name, ip=ip, prefixlen=int(addr.group(2)), mac=mac_of(name),
            up="UP" in line, wireless=is_wireless(name),
        ))
    return rows


def list_ipv4(include_loopback: bool = False) -> list[IfaceInfo]:
    """Interfaces con dirección IPv4. Silencioso si ``ip`` no está disponible."""
    rows: list[IfaceInfo] = []
    raw = _run(["ip", "-j", "-4", "addr", "show"])
    if raw:
        try:
            rows = _parse_json(raw)
        except (json.JSONDecodeError, TypeError):
            rows = []
    if not rows:
        rows = _parse_text(_run(["ip", "-o", "-4", "addr", "show"]) or "")
    return [r for r in rows if include_loopback or not r.loopback]


def default_iface() -> str | None:
    """Interfaz de la ruta por defecto IPv4, si existe."""
    raw = _run(["ip", "-j", "-4", "route", "show", "default"])
    if raw:
        try:
            routes = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            routes = []
        for route in routes if isinstance(routes, list) else []:
            if route.get("dst") in ("default", None) and route.get("dev"):
                return str(route["dev"])
    text = _run(["ip", "-4", "route", "show", "default"]) or ""
    match = _ROUTE_DEV.search(text)
    return match.group(1) if match else None


def find(name: str | None) -> IfaceInfo | None:
    """Busca una interfaz por nombre; acepta interfaces sin IPv4."""
    if not name:
        return None
    for row in list_ipv4(include_loopback=True):
        if row.name == name:
            return row
    if not exists(name):
        return None
    return IfaceInfo(name=name, ip=interface_ipv4(name), prefixlen=None,
                     mac=mac_of(name), up=True, wireless=is_wireless(name))


# --------------------------------------------------------------------------- #
# Selección
# --------------------------------------------------------------------------- #
def pick(configured: str | None = None) -> tuple[IfaceInfo | None, str]:
    """Elige la interfaz a vigilar. Devuelve (info, motivo legible).

    Prioridad: la configurada explícitamente > la de la ruta por defecto >
    cableada con IP privada > cualquier interfaz no virtual con IPv4.
    """
    requested = (configured or "").strip()
    if requested.lower() not in AUTO_VALUES:
        info = find(requested)
        return info, f"configurada en config.yaml: {requested}"

    name = default_iface()
    if name:
        info = find(name)
        # Una VPN o un puente de contenedores puede llevar la ruta por defecto;
        # en ese caso no representa la LAN que queremos vigilar.
        if info and info.ip and not info.loopback and not info.virtual:
            info.default = True
            return info, f"ruta por defecto ({info.kind})"

    candidates = [r for r in list_ipv4() if r.ip and not r.virtual and r.up]
    if not candidates:
        candidates = [r for r in list_ipv4() if r.ip and not r.virtual]
    if not candidates:
        return None, "sin interfaces IPv4 utilizables"
    candidates.sort(key=lambda r: (r.wireless, not rfc1918(r.ip), r.name))
    best = candidates[0]
    if best.wireless:
        return best, "única interfaz con IPv4 (wi-fi)"
    return best, f"{best.kind} con IP privada"

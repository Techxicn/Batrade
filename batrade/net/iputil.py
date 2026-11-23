"""Utilidades de IP/MAC y descubrimiento de red sin privilegios."""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import time
from collections.abc import Iterable

from batrade.net.proc import env_minimo

MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")

# Bit 0x02 del primer octeto: "locally administered".
# OJO: no equivale a "MAC aleatoria". También lo llevan MACs estáticas, veth de
# Docker (02:42:*), QEMU (52:54:*) y otros NICs virtuales. Se usa solo como
# indicio, nunca como prueba (ver C4 del análisis).
LOCAL_ADMIN_BIT = 0x02
MULTICAST_BIT = 0x01


def now_ms() -> int:
    return int(time.time() * 1000)


def normalize_mac(raw: str | None) -> str | None:
    """Acepta aa:bb:cc:dd:ee:ff, aa-bb-..., aabb.ccdd.eeff. Devuelve forma canónica."""
    if not raw:
        return None
    val = str(raw).strip().lower().replace("-", ":").replace(".", "")
    if ":" not in val and len(val) == 12:
        val = ":".join(val[i:i + 2] for i in range(0, 12, 2))
    if not MAC_RE.match(val):
        return None
    return val


def is_multicast_mac(mac: str | None) -> bool:
    mac = normalize_mac(mac)
    return bool(mac) and (int(mac[:2], 16) & MULTICAST_BIT) == MULTICAST_BIT


def is_locally_administered(mac: str | None) -> bool:
    mac = normalize_mac(mac)
    return bool(mac) and (int(mac[:2], 16) & LOCAL_ADMIN_BIT) == LOCAL_ADMIN_BIT


def oui_prefix(mac: str | None) -> str | None:
    mac = normalize_mac(mac)
    return mac.replace(":", "")[:6].upper() if mac else None


def valid_ipv4(raw: str | None) -> str | None:
    if not raw:
        return None
    try:
        return str(ipaddress.IPv4Address(str(raw).strip()))
    except ValueError:
        return None


def ip_in_cidr(ip: str | None, cidr: str) -> bool:
    """Valida que un objetivo esté dentro del CIDR configurado (RNF-05)."""
    addr = valid_ipv4(ip)
    if not addr:
        return False
    try:
        return ipaddress.IPv4Address(addr) in ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return False


def cidr_size(cidr: str) -> int:
    try:
        return ipaddress.IPv4Network(cidr, strict=False).num_addresses
    except ValueError:
        return 0


def ip_excluded(ip: str | None, entries: Iterable[str]) -> bool:
    """True si ``ip`` cae en alguna entrada de ``scan.exclude``.

    Cada entrada es una IPv4 suelta o una red CIDR; se aceptan ambas porque el
    operador quiere poder excluir «ese trasto» o una VLAN entera.
    """
    addr = valid_ipv4(ip)
    if not addr:
        return False
    for entrada in entries:
        if "/" in str(entrada):
            if ip_in_cidr(addr, str(entrada)):
                return True
        elif str(entrada).strip() == addr:
            return True
    return False


def default_gateway() -> str | None:
    """Puerta de enlace por defecto según la tabla de rutas del kernel."""
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=5, check=False,
            env=env_minimo(),
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        parts = line.split()
        if "via" in parts:
            return valid_ipv4(parts[parts.index("via") + 1])
    return None


def interface_ipv4(iface: str) -> str | None:
    """IPv4 local de una interfaz, sin invocar herramientas externas."""
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", iface],
            capture_output=True, text=True, timeout=5, check=False,
            env=env_minimo(),
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for token in out.split():
        if "/" in token:
            ip = valid_ipv4(token.split("/")[0])
            if ip:
                return ip
    return None


def local_ip_for(target: str) -> str | None:
    """IP origen que el kernel elegiría para hablar con target (sin enviar tráfico)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((target, 9))
            return valid_ipv4(s.getsockname()[0])
    except OSError:
        return None


def rfc1918(ip: str | None) -> bool:
    addr = valid_ipv4(ip)
    if not addr:
        return False
    return ipaddress.IPv4Address(addr).is_private

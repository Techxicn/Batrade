"""Observaciones normalizadas.

El motor de reglas no sabe si un paquete llegó por sniffing, por replay de un
pcap o por la tabla de vecinos del kernel. Esa indirección es lo que permite
probar y demostrar las detecciones en una VM sin CAP_NET_RAW.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# kinds
ARP = "arp"
SYN = "syn"
DHCP = "dhcp"
NEIGH = "neigh"


@dataclass(slots=True)
class Observation:
    kind: str
    ts: int
    iface: str | None = None
    ip_src: str | None = None
    mac_src: str | None = None
    ip_dst: str | None = None
    mac_dst: str | None = None
    port_dst: int | None = None
    op: str | None = None          # arp: request|reply   dhcp: offer|ack
    extra: dict[str, Any] = field(default_factory=dict)
    # "in" | "out" | None. Relativo al sensor y solo cuando la trama lo toca:
    # en un puerto espejo casi todo es tráfico de terceros y queda en None.
    direction: str | None = None

    @property
    def gratuitous(self) -> bool:
        return bool(self.extra.get("gratuitous"))

    @property
    def flags(self) -> str:
        return str(self.extra.get("flags") or "")

    def __repr__(self) -> str:  # pragma: no cover - sólo depuración
        return (f"Observation({self.kind} {self.ip_src}/{self.mac_src} -> "
                f"{self.ip_dst}:{self.port_dst} op={self.op})")


@dataclass(slots=True)
class Finding:
    tipo: str
    severidad: str
    clave: str
    ip_origen: str | None = None
    mac_origen: str | None = None
    ip_destino: str | None = None
    detalle: dict[str, Any] = field(default_factory=dict)
    notificar: bool = True
    verified: bool = False
    # El motor pide verificación activa de forma asíncrona (C2)
    needs_verify: str | None = None

    @property
    def notify(self) -> bool:
        return self.notificar and self.severidad in ("warn", "crit")

"""Un flujo: la conversación entre dos extremos durante una ventana."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Flow:
    """Resumen acumulado de una conversación.

    ``src_*`` es el extremo que envió el primer paquete (el iniciador). El flujo
    es bidireccional: los paquetes de vuelta suman en ``packets``/``bytes`` y en
    ``bytes_dst``, no en ``bytes_src``.
    """

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str                     # "tcp" | "udp" | "arp"
    ts_start: int                  # ms UTC del primer paquete
    ts_end: int = 0                # ms UTC del último paquete
    packets: int = 0
    bytes: int = 0
    syn_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    ack_count: int = 0
    packet_sizes: list[int] = field(default_factory=list)
    inter_arrival_ms: list[int] = field(default_factory=list)
    # Reparto necesario para ``bytes_por_direccion``: lo que va del iniciador
    # al respondedor y lo que vuelve.
    bytes_src: int = 0
    bytes_dst: int = 0

    @property
    def clave(self) -> str:
        """Clave de dedupe del evento, igual que la usan las reglas."""
        return f"flow:{self.src_ip}:{self.dst_ip}:{self.dst_port}"

    @property
    def duracion_ms(self) -> int:
        return max(0, self.ts_end - self.ts_start)

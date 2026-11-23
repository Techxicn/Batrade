"""Agrupación de paquetes en flujos por ventana de tiempo.

La ventana se mide desde el primer paquete del flujo: cuando llega un paquete
``window_s`` después del inicio, el flujo se cierra y se entrega. El cierre por
tiempo se comprueba al añadir y en cada vuelta del motor (``expire``), para que
un flujo que dejó de hablar también se cierre sin esperar tráfico nuevo.
"""
from __future__ import annotations

import logging
from typing import Any

from batrade.flow.flow import Flow

log = logging.getLogger("batrade.flow.collector")

# Extremo de un flujo: IP y puerto, en orden canónico para que ida y vuelta
# caigan en el mismo flujo.
Extremo = tuple[str, int]


def _canonica(src_ip: str, src_port: int, dst_ip: str, dst_port: int,
              proto: str) -> tuple[Extremo, Extremo, str]:
    a: Extremo = (src_ip, src_port)
    b: Extremo = (dst_ip, dst_port)
    return (a, b, proto) if a <= b else (b, a, proto)


class FlowCollector:
    """Agrupa paquetes en flujos y los cierra por ventana.

    El flujo es **bidireccional**: la 5-tupla se ordena de forma canónica, de
    modo que la respuesta de un servidor cae en el mismo flujo que la petición.
    Sin eso, cada conversación serían dos flujos y las características (bytes
    por dirección, ratio SYN/ACK) no dirían nada.
    """

    def __init__(self, window_s: float = 60.0):
        self.window_ms = max(1000, int(float(window_s) * 1000))
        self._abiertos: dict[tuple[Extremo, Extremo, str], Flow] = {}

    # ------------------------------------------------------------------ API
    def add(self, packet, ts: int) -> list[Flow]:
        """Suma un paquete y devuelve los flujos que se cerraron con él."""
        cerrados = self.expire(ts)
        datos = _parse(packet)
        if datos is None:
            return cerrados
        src_ip, src_port, dst_ip, dst_port, proto, tam, flags = datos
        clave = _canonica(src_ip, src_port, dst_ip, dst_port, proto)
        flujo = self._abiertos.get(clave)
        if flujo is None:
            flujo = Flow(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port,
                         dst_port=dst_port, proto=proto, ts_start=ts)
            self._abiertos[clave] = flujo
        elif flujo.packets:
            flujo.inter_arrival_ms.append(ts - flujo.ts_end)

        flujo.packets += 1
        flujo.bytes += tam
        flujo.packet_sizes.append(tam)
        flujo.ts_end = ts
        if (src_ip, src_port) == (flujo.src_ip, flujo.src_port):
            flujo.bytes_src += tam
        else:
            flujo.bytes_dst += tam
        if flags:
            flujo.syn_count += int("S" in flags)
            flujo.rst_count += int("R" in flags)
            flujo.fin_count += int("F" in flags)
            flujo.ack_count += int("A" in flags)
        return cerrados

    def expire(self, ts: int) -> list[Flow]:
        """Cierra los flujos que ya cumplieron la ventana (sin esperar tráfico)."""
        vencidos = [f for f in self._abiertos.values()
                    if ts - f.ts_start >= self.window_ms]
        for flujo in vencidos:
            self._abiertos.pop(
                _canonica(flujo.src_ip, flujo.src_port,
                          flujo.dst_ip, flujo.dst_port, flujo.proto), None)
        return vencidos

    def flush(self, ts: int | None = None) -> list[Flow]:
        """Devuelve todo lo abierto (parada del motor). Cierra la ventana."""
        flujos = list(self._abiertos.values())
        self._abiertos.clear()
        if ts is not None:
            for flujo in flujos:
                flujo.ts_end = max(flujo.ts_end, ts)
        return flujos

    @property
    def abiertos(self) -> int:
        return len(self._abiertos)


def _parse(packet: Any) -> tuple[str, int, str, int, str, int, str] | None:
    """(src_ip, src_port, dst_ip, dst_port, proto, tamaño, flags) o None."""
    try:
        from scapy.all import ARP as ScapyARP
        from scapy.all import IP, TCP, UDP
    except Exception:  # noqa: BLE001 - sin scapy no hay flujos
        return None
    try:
        tam = len(packet)
    except TypeError:
        return None
    if packet.haslayer(ScapyARP):
        arp = packet[ScapyARP]
        return str(arp.psrc), 0, str(arp.pdst), 0, "arp", tam, ""
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip, tcp = packet[IP], packet[TCP]
        return str(ip.src), int(tcp.sport), str(ip.dst), int(tcp.dport), "tcp", tam, str(tcp.flags)
    if packet.haslayer(IP) and packet.haslayer(UDP):
        ip, udp = packet[IP], packet[UDP]
        return str(ip.src), int(udp.sport), str(ip.dst), int(udp.dport), "udp", tam, ""
    return None

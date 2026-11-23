"""Características de un flujo, listas para puntuar o serializar."""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field

from batrade.flow.flow import Flow


@dataclass(slots=True)
class FlowFeatures:
    """Números que describen un flujo. Todos serializables a JSON."""

    packets: int
    bytes: int
    bytes_por_direccion: dict[str, int] = field(default_factory=dict)
    tamano_medio: float = 0.0
    desviacion_estandar_tiempo_entre_paquetes: float = 0.0
    ratio_syn_ack: float = 0.0
    puertos_distintos_por_ip_origen: int = 0
    destinos_distintos_por_ip_origen: int = 0


def extract(flujo: Flow) -> FlowFeatures:
    """Calcula las características de un flujo.

    Las dos últimas son por flujo (una IP de origen, un puerto, un destino). El
    agregado por origen —cuántos puertos y destinos toca un mismo equipo— llega
    cuando se puntúe la ventana completa, no aquí.

    Nunca lanza con un flujo vacío: devuelve ceros, que es lo que un modelo
    entrenado espera ver y lo que evita dividir por cero al calcular medias.
    """
    paquetes = max(0, flujo.packets)
    por_direccion: dict[str, int] = {}
    if paquetes:
        if flujo.bytes_src:
            por_direccion[flujo.src_ip] = flujo.bytes_src
        if flujo.bytes_dst:
            por_direccion[flujo.dst_ip] = flujo.bytes_dst

    # pstdev no necesita dos muestras y no falla con una; con cero, 0.0.
    desviacion = (statistics.pstdev(flujo.inter_arrival_ms)
                  if len(flujo.inter_arrival_ms) > 1 else 0.0)
    # Sin ACK no hay denominador: el valor es el número de SYN vistos, que es
    # justo la señal de un barrido (muchos SYN y ninguna respuesta).
    ratio = (flujo.syn_count / flujo.ack_count if flujo.ack_count
             else float(flujo.syn_count))

    return FlowFeatures(
        packets=paquetes,
        bytes=max(0, flujo.bytes),
        bytes_por_direccion=por_direccion,
        tamano_medio=(flujo.bytes / paquetes) if paquetes else 0.0,
        desviacion_estandar_tiempo_entre_paquetes=float(desviacion),
        ratio_syn_ack=float(ratio),
        puertos_distintos_por_ip_origen=1 if paquetes else 0,
        destinos_distintos_por_ip_origen=1 if paquetes else 0,
    )

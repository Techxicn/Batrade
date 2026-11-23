"""Características de un flujo, listas para puntuar o serializar."""
from __future__ import annotations

import statistics
from dataclasses import dataclass

from batrade.flow.flow import Flow

# Tope del ratio SYN/ACK. Un barrido produce cientos de SYN sin respuesta; sin
# tope, ese valor se come al resto de features al normalizar y el modelo aprende
# "todo lo que no es un barrido es igual". Con el tope, 10 SYN por ACK ya es el
# máximo de sospecha que un flujo puede aportar: los barridos los detecta
# SynScanRule, no este módulo (D-09).
RATIO_SYN_ACK_MAX = 10.0


@dataclass(slots=True)
class FlowFeatures:
    """Números que describen un flujo. Todos serializables a JSON."""

    packets: int
    bytes: int
    # None cuando no se puede atribuir el tráfico a cada extremo: en un puerto
    # espejo no hay forma de saber quién inició, y un flujo de una sola
    # dirección no distingue "sin respuesta" de "el espejo no lo mostró".
    # Un dict con ceros fingiría un dato que no tenemos.
    bytes_por_direccion: dict[str, int] | None = None
    tamano_medio: float = 0.0
    desviacion_estandar_tiempo_entre_paquetes: float = 0.0
    # Media del hueco entre paquetes y su coeficiente de variación (desviación
    # / media). Un balizamiento C2 es un flujo con muchos paquetes, hueco
    # grande y variación casi nula; sin estas dos, ese perfil se confunde con
    # un flujo de un solo paquete (que también tiene desviación cero).
    intervalo_medio_ms: float = 0.0
    regularidad_intervalos: float = 0.0
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
    # Sólo hay reparto cuando se vieron las dos direcciones: con una sola no se
    # puede afirmar quién envió qué (el espejo pudo perder la vuelta, o el
    # equipo no contestó). Un dict con ceros fingiría un dato que no tenemos.
    por_direccion: dict[str, int] | None = None
    if paquetes and flujo.bytes_src > 0 and flujo.bytes_dst > 0:
        por_direccion = {flujo.src_ip: flujo.bytes_src,
                         flujo.dst_ip: flujo.bytes_dst}

    # pstdev no necesita dos muestras y no falla con una; con cero, 0.0.
    intervalos = flujo.inter_arrival_ms
    desviacion = statistics.pstdev(intervalos) if len(intervalos) > 1 else 0.0
    intervalo_medio = (sum(intervalos) / len(intervalos)) if intervalos else 0.0
    # Coeficiente de variación: 0 = perfectamente periódico. Con media 0 no se
    # puede dividir y se deja 0 (flujo de un paquete).
    regularidad = (desviacion / intervalo_medio) if intervalo_medio > 0 else 0.0
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
        intervalo_medio_ms=float(intervalo_medio),
        regularidad_intervalos=float(regularidad),
        ratio_syn_ack=min(float(ratio), RATIO_SYN_ACK_MAX),
        puertos_distintos_por_ip_origen=1 if paquetes else 0,
        destinos_distintos_por_ip_origen=1 if paquetes else 0,
    )

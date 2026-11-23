"""Entrenamiento del modelo de flujos a partir de un pcap de tráfico normal.

Se separa del motor y de la CLI para poder probarlo sin entrenar de verdad:
el script ``scripts/train_baseline.py`` es un envoltorio de estas funciones.
"""
from __future__ import annotations

from pathlib import Path

from batrade.flow.collector import FlowCollector
from batrade.flow.features import FlowFeatures, extract
from batrade.flow.scorer import MIN_PAQUETES_ENTRENAMIENTO


def features_from_pcap(pcap: str | Path, window_s: float = 60.0,
                       min_packets: int = MIN_PAQUETES_ENTRENAMIENTO) -> list[FlowFeatures]:
    """Agrupa el pcap en flujos y devuelve sus características.

    Se leen paquetes crudos (no ``observations_from_pcap``): el colector
    necesita tamaño, puertos y flags, que la observación normalizada ya no
    conserva.

    Se descartan los flujos con menos de ``min_packets``: un flujo de uno o dos
    paquetes no tiene dos huecos que medir, su desviación es trivialmente cero y
    enseñaría al modelo que "sin jitter" es normal. Esos flujos los cubren las
    reglas de escaneo (D-09).
    """
    from scapy.all import PcapReader

    colector = FlowCollector(window_s)
    features: list[FlowFeatures] = []
    ultimo = 0
    with PcapReader(str(pcap)) as lector:
        for paquete in lector:
            ts = int(float(paquete.time) * 1000)
            ultimo = ts
            for flujo in colector.add(paquete, ts):
                features.append(extract(flujo))
    for flujo in colector.flush(ultimo):
        features.append(extract(flujo))
    return [f for f in features if f.packets >= min_packets]

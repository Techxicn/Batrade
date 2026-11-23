#!/usr/bin/env python3
"""Entrena el modelo de flujos (Isolation Forest, con o sin segmentador).

Lee el pcap paquete a paquete, agrupa conversaciones con ``FlowCollector``,
extrae características y guarda ``<out>.npz`` (árboles) y ``<out>.json``
(metadatos). Necesita el extra ``[ml]`` (numpy).

    python scripts/train_baseline.py --pcap fixtures/pcaps/baseline.pcap \\
        --out var/flow_model --segmenter segmentado
"""
from __future__ import annotations

import argparse
import hashlib
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from batrade.flow.scorer import (IsolationForestScorer,  # noqa: E402
                                 KMeansSegmenter, SegmentadoScorer,
                                 guardar_artefacto)
from batrade.flow.training import features_from_pcap  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Entrena el modelo de flujos con un pcap de tráfico normal.")
    parser.add_argument("--pcap", required=True, help="pcap de tráfico normal")
    parser.add_argument("--out", default="var/flow_model",
                        help="ruta base del modelo, sin extensión")
    parser.add_argument("--window-s", type=int, default=60,
                        help="ventana de agrupación de flujos (default 60)")
    parser.add_argument("--estimators", type=int, default=100,
                        help="número de árboles de aislamiento (default 100)")
    parser.add_argument("--seed", type=int, default=42,
                        help="semilla del bosque (default 42, determinista)")
    parser.add_argument("--segmenter", default="kmeans",
                        choices=("none", "kmeans", "segmentado"),
                        help="none: sólo IF global · kmeans: segmentador sin "
                             "cambiar el score · segmentado: un IF por segmento "
                             "(default kmeans)")
    parser.add_argument("--k", type=int, default=None,
                        help="número de segmentos; si se omite se elige por silueta (2..8)")
    args = parser.parse_args(argv)

    pcap = Path(args.pcap)
    if not pcap.is_file():
        print(f"no existe el pcap: {pcap}", file=sys.stderr)
        return 2

    features = features_from_pcap(pcap, args.window_s)
    if not features:
        print("el pcap no produjo flujos TCP/UDP/ARP; no hay nada que entrenar",
              file=sys.stderr)
        return 1

    huella = hashlib.sha256(pcap.read_bytes()).hexdigest()[:16]
    try:
        if args.segmenter == "segmentado":
            modelo: IsolationForestScorer | SegmentadoScorer = SegmentadoScorer(
                random_state=args.seed)
            modelo.fit(features, k=args.k, pcap_hash=huella)
        else:
            modelo = IsolationForestScorer(n_estimators=args.estimators,
                                           random_state=args.seed)
            modelo.fit(features, pcap_hash=huella)
            if args.segmenter == "kmeans":
                modelo.segmenter = KMeansSegmenter(random_state=args.seed)
                modelo.segmenter.fit(features, k=args.k)
    except RuntimeError as exc:      # numpy ausente
        print(exc, file=sys.stderr)
        return 1
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 1

    salida = Path(args.out)
    salida.parent.mkdir(parents=True, exist_ok=True)
    ruta_npz = Path(str(salida) + ".npz")
    ruta_json = Path(str(salida) + ".json")
    if isinstance(modelo, SegmentadoScorer):
        modelo.save(ruta_npz, ruta_json)
    else:
        guardar_artefacto(ruta_npz, ruta_json, modelo,
                          segmenter=modelo.segmenter)

    if isinstance(modelo, SegmentadoScorer):
        global_if, segmentador = modelo.global_scorer, modelo.segmenter
    else:
        global_if, segmentador = modelo, modelo.segmenter
    scores = sorted(modelo.score(f) for f in features)
    mediana = statistics.median(scores)
    sobre_umbral = sum(1 for s in scores if s > 0.99)
    print(f"pcap            : {pcap}  (sha256 {huella})")
    print(f"flujos          : {len(features)}")
    print(f"árboles         : {global_if.n_estimators} · muestras "
          f"{global_if.max_samples} · semilla {args.seed}")
    print(f"segmentador     : {args.segmenter}")
    if segmentador is not None:
        assert isinstance(segmentador, KMeansSegmenter)
        print(f"  k             : {segmentador.k}  (inercia {segmentador.inertia:.1f}"
              f" · silueta {segmentador.silhouette:.3f})")
    if isinstance(modelo, SegmentadoScorer):
        reparto = [0 if m is None else m.n_flows for m in modelo.por_segmento]
        print(f"  flujos/seg    : {reparto}  (0 = sin IF propio, cae al global)")
    print(f"score línea base: mediana {mediana:.3f} · máx {scores[-1]:.3f}")
    print(f"sobre 0.99      : {sobre_umbral} flujo(s) (debe ser 0: es su propia línea base)")
    print("umbral sugerido : 0.95 — dentro de la línea base el score no pasa de 0.9,")
    print("                  así que 0.95 sólo dispara con flujos fuera de ella")
    print(f"modelo          : {ruta_npz}")
    print(f"metadatos       : {ruta_json}")
    print("\nPara usarlo: flow.enabled: true en config.yaml y reiniciar el sensor.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

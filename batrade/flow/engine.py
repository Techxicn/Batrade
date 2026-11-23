"""Motor de flujos: cola de paquetes, colector, puntuación y hallazgos.

Corre en su propio hilo y no toca el ``Engine`` de reglas. El sniffer entrega
paquetes crudos con ``enqueue`` (nunca bloquea: si la cola está llena se
descartan y se cuentan); aquí se agrupan en flujos, se extraen características
y se puntúan. Un hallazgo se entrega a ``on_finding`` para que el sensor lo
persista por el mismo camino que los de reglas.
"""
from __future__ import annotations

import dataclasses
import logging
import queue
import threading
import time
from pathlib import Path

from batrade.config import Config
from batrade.detect.observation import Finding
from batrade.flow.collector import FlowCollector
from batrade.flow.features import extract
from batrade.flow.flow import Flow
from batrade.flow.scorer import (DummyScorer, Scorer, SegmentadoScorer,
                                 leer_artefacto)

log = logging.getLogger("batrade.flow.engine")

COLA_MAX = 10_000
# Cada cuánto despierta del `get` para cerrar flujos vencidos aunque no llegue
# tráfico (un flujo que se queda callado también debe cerrarse).
SIN_TRÁFICO_S = 0.5


def _now_ms() -> int:
    return int(time.time() * 1000)


class FlowEngine:
    """Consume paquetes, cierra flujos y emite ``flow_anomaly``."""

    def __init__(self, cfg: Config, scorer: Scorer | None = None,
                 on_finding=None):
        self.cfg = cfg
        self.scorer: Scorer = scorer if scorer is not None else self._scorer_por_defecto()
        self.on_finding = on_finding
        self.threshold = float(cfg.flow.anomaly_threshold)
        self.collector = FlowCollector(cfg.flow.window_s)
        self.cola: queue.Queue = queue.Queue(maxsize=COLA_MAX)
        self._parar = threading.Event()
        self._hilo: threading.Thread | None = None
        # Hallazgos cuando no hay callback (depuración y tests).
        self.emitted: list[Finding] = []
        self.descartados = 0

    def _scorer_por_defecto(self) -> Scorer:
        """Isolation Forest (global o por segmento) si hay modelo entrenado.

        Sin modelo el motor sigue arrancando (colector, features, cola) pero no
        emite nada: es preferible a puntuar con un modelo inventado.
        """
        if not self.cfg.flow.enabled:
            return DummyScorer()
        base = Path(str(self.cfg.flow.model_path))
        ruta_npz, ruta_json = Path(str(base) + ".npz"), Path(str(base) + ".json")
        if not (ruta_npz.is_file() and ruta_json.is_file()):
            log.warning("modelo no entrenado; el motor no emitirá nada (%s)", base)
            return DummyScorer()
        try:
            artefacto = leer_artefacto(ruta_npz, ruta_json)
        except Exception as exc:  # noqa: BLE001 - fichero roto o numpy ausente
            log.warning("no se pudo cargar el modelo de flujos (%s): %s", base, exc)
            return DummyScorer()

        modo = self.cfg.flow.segmenter
        if modo == "segmentado" and artefacto["segmentado"] is not None:
            modelo = SegmentadoScorer.desde_artefacto(artefacto)
            log.info("modelo de flujos segmentado cargado: %s (k=%d, %d flujos)",
                     base, modelo.segmenter.k, modelo.global_scorer.n_flows)
            return modelo
        if modo == "segmentado":
            log.info("el modelo no trae IF por segmento; se usa el IF global (%s)", base)
        modelo = artefacto["global"]
        if modo == "kmeans" and artefacto["segmenter"] is not None:
            log.info("modelo de flujos cargado con segmentador k=%d: %s (%d flujos)",
                     artefacto["segmenter"].k, base, modelo.n_flows)
        else:
            log.info("modelo de flujos cargado: %s (%d flujos de entrenamiento)",
                     base, modelo.n_flows)
        return modelo

    # --------------------------------------------------------------- ciclo
    def enqueue(self, packet, ts: int) -> bool:
        """Entrega un paquete crudo. Devuelve False si la cola está llena."""
        try:
            self.cola.put_nowait((packet, ts))
            return True
        except queue.Full:
            self.descartados += 1
            if self.descartados % 1000 == 1:
                log.warning("cola de flujos llena: %d paquetes descartados",
                            self.descartados)
            return False

    def start(self) -> None:
        if self._hilo is not None and self._hilo.is_alive():
            return
        self._parar.clear()
        self._hilo = threading.Thread(target=self._run, name="batrade-flow",
                                      daemon=True)
        self._hilo.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._parar.set()
        try:
            self.cola.put_nowait(None)      # despierta al hilo
        except queue.Full:
            pass
        if self._hilo is not None:
            self._hilo.join(timeout=timeout)
            self._hilo = None

    def _run(self) -> None:
        try:
            while not self._parar.is_set():
                try:
                    item = self.cola.get(timeout=SIN_TRÁFICO_S)
                except queue.Empty:
                    self._cerrar(_now_ms())
                    continue
                if item is None:
                    break
                paquete, ts = item
                for flujo in self.collector.add(paquete, ts):
                    self._evaluar(flujo)
                self._cerrar(_now_ms())
        except Exception:  # noqa: BLE001 - el hilo no puede morir en silencio
            log.exception("motor de flujos detenido por error")
        finally:
            for flujo in self.collector.flush(_now_ms()):
                self._evaluar(flujo)

    def _cerrar(self, ts: int) -> None:
        for flujo in self.collector.expire(ts):
            self._evaluar(flujo)

    def _segmento(self, caracteristicas) -> int | None:
        """Segmento del flujo, si el modelo cargado trae segmentador."""
        if isinstance(self.scorer, SegmentadoScorer):
            return self.scorer.segment(caracteristicas)
        segmentador = getattr(self.scorer, "segmenter", None)
        if segmentador is not None and getattr(segmentador, "trained", False):
            return segmentador.segment(caracteristicas)
        return None

    # ------------------------------------------------------------ puntuación
    def _evaluar(self, flujo: Flow) -> Finding | None:
        """Puntúa un flujo cerrado y devuelve el hallazgo si supera el umbral."""
        caracteristicas = extract(flujo)
        score = float(self.scorer.score(caracteristicas))
        if score <= self.threshold:
            return None
        detalle = {
            "resumen": (f"Flujo anómalo {flujo.src_ip} → {flujo.dst_ip}:"
                        f"{flujo.dst_port} ({flujo.proto}, {flujo.packets} "
                        f"paquetes, {flujo.bytes} B), puntuación {score:.2f}"),
            "por_que": ("El modelo de flujos puntuó esta conversación por "
                        "encima de flow.anomaly_threshold; su forma se "
                        "parece poco a la de los flujos normales."),
            "accion": ("Revisa el equipo de origen y confirma si ese tráfico "
                       "es legítimo; si lo es, márcalo como falso positivo."),
            "features": dataclasses.asdict(caracteristicas),
            "score": round(score, 4),
        }
        # El segmento no cambia el score en modo `kmeans`, pero es la traza que
        # hace útil tenerlo cargado: se ve contra qué grupo se comparó el flujo.
        segmento = self._segmento(caracteristicas)
        if segmento is not None:
            detalle["segmento"] = segmento
        hallazgo = Finding(
            tipo="flow_anomaly",
            severidad="warn",
            clave=flujo.clave,
            ip_origen=flujo.src_ip,
            ip_destino=flujo.dst_ip,
            detalle=detalle,
        )
        self.emitted.append(hallazgo)
        if self.on_finding is not None:
            try:
                self.on_finding(hallazgo)
            except Exception:  # noqa: BLE001
                log.exception("no se pudo entregar el hallazgo de flujo")
        return hallazgo

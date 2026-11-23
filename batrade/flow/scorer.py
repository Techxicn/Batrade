"""Puntuación de flujos: interfaz, centinela e Isolation Forest propio.

La interfaz existe para que el motor no sepa qué implementación tiene delante.
``DummyScorer`` es el fallback (sin extra ``[ml]`` o sin modelo entrenado) y
``IsolationForestScorer`` el scorer principal (D-07), implementado con numpy y
sin scikit-learn.
"""
from __future__ import annotations

import json
import math
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

try:                       # numpy es opcional: sólo lo necesita el IF real
    import numpy as np
except ImportError:        # pragma: no cover - se prueba con el extra instalado
    np = None              # type: ignore[assignment]

from batrade.flow.features import FlowFeatures

# Orden fijo del vector. Va en el JSON del modelo: si cambia el orden sin subir
# la versión del formato, los scores dejan de significar lo mismo.
FEATURE_ORDER = (
    "packets",
    "bytes",
    "tamano_medio",
    "desviacion_estandar_tiempo_entre_paquetes",
    "intervalo_medio_ms",
    "regularidad_intervalos",
    "ratio_syn_ack",
    "puertos_distintos_por_ip_origen",
    "destinos_distintos_por_ip_origen",
    "dos_direcciones",
)

MODEL_VERSION = 1
# Por debajo de esto no hay distribución que aprender: cada árbol vería casi la
# misma muestra y el modelo memorizaría el propio entrenamiento.
MIN_FLUJOS_ENTRENAMIENTO = 8
# Un flujo con menos de tres paquetes no tiene dos huecos que medir: su
# desviación sería trivialmente cero y contaminaría la línea base.
MIN_PAQUETES_ENTRENAMIENTO = 3


class Scorer(ABC):
    """Contrato mínimo: aprender de lo normal y puntuar lo desconocido."""

    @abstractmethod
    def fit(self, flows_normales: Sequence[FlowFeatures], **kwargs: Any) -> None:
        """Ajusta el modelo con flujos normales (sin supervisión)."""

    @abstractmethod
    def score(self, flow: FlowFeatures) -> float:
        """Devuelve una puntuación en [0, 1]; mayor significa más anómalo."""


class DummyScorer(Scorer):
    """Fallback: no aprende nada y puntúa siempre 0.0.

    Con él el motor arranca y ejerce el camino completo (cola, colector,
    características), pero nunca supera el umbral y no emite hallazgos.
    """

    def fit(self, flows_normales: Sequence[FlowFeatures], **kwargs: Any) -> None:
        return None

    def score(self, flow: FlowFeatures) -> float:
        return 0.0


def _vector(caracteristicas: FlowFeatures) -> list[float]:
    """Vector numérico en el orden de ``FEATURE_ORDER``."""
    return [
        float(caracteristicas.packets),
        float(caracteristicas.bytes),
        float(caracteristicas.tamano_medio),
        float(caracteristicas.desviacion_estandar_tiempo_entre_paquetes),
        float(caracteristicas.intervalo_medio_ms),
        float(caracteristicas.regularidad_intervalos),
        float(caracteristicas.ratio_syn_ack),
        float(caracteristicas.puertos_distintos_por_ip_origen),
        float(caracteristicas.destinos_distintos_por_ip_origen),
        1.0 if caracteristicas.bytes_por_direccion else 0.0,
    ]


def _c_factor(n: int) -> float:
    """Profundidad media esperada de un BST con ``n`` nodos (Liu et al.).

    Normaliza la profundidad: sin esto, un árbol con muchas hojas parecería
    "más normal" que uno pequeño y los scores no serían comparables.
    """
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    armonico = math.log(n - 1) + 0.5772156649
    return 2.0 * armonico - 2.0 * (n - 1) / n


class IsolationForestScorer(Scorer):
    """Isolation Forest propio: bosque de árboles de aislamiento aleatorios.

    Cada árbol parte un subconjunto aleatorio del entrenamiento eligiendo una
    feature y un umbral al azar; un flujo anómalo se aísla en pocas particiones
    y acaba cerca de la raíz (profundidad pequeña). La puntuación cruda es
    ``2 ** (-E[h(x)] / c(max_samples))``, en ``(0, 1]``.

    Sobre esa base se aplica una calibración: el score final es el percentil del
    flujo dentro de la línea base, escalado a ``[0, 0.9]``, y por encima del
    máximo visto al entrenar sube hacia ``1.0`` según cuánto se aleja. Así el
    umbral ``0.95`` (el de por defecto) significa "más anómalo que todo lo que
    había en la línea base" y un flujo normal nunca lo roza por construcción.
    """

    def __init__(self, n_estimators: int = 100, max_samples: int = 256,
                 random_state: int = 42):
        if np is None:
            raise RuntimeError(
                "IsolationForestScorer necesita numpy: instala el extra ml "
                "(pip install 'batrade[ml]')")
        self.n_estimators = max(1, int(n_estimators))
        self.max_samples = max(2, int(max_samples))
        self.random_state = int(random_state)
        self.trained = False
        self.pcap_hash: str | None = None
        self.trained_at_iso: str | None = None
        self.n_flows = 0
        self._arboles: list[dict[str, Any]] = []
        self._c_max = 1.0
        self._scores_base = np.zeros(0, dtype=np.float64)
        self._spread = 1.0

    # ------------------------------------------------------------- entrenar
    def fit(self, flows_normales: Sequence[FlowFeatures], *,
            pcap_hash: str | None = None) -> None:
        """Entrena con flujos normales. Determinista para un ``random_state``."""
        X = np.asarray([_vector(f) for f in flows_normales], dtype=np.float64)
        if len(X) < MIN_FLUJOS_ENTRENAMIENTO:
            raise ValueError(
                f"hacen falta al menos {MIN_FLUJOS_ENTRENAMIENTO} flujos para "
                f"entrenar (llegaron {len(X)})")
        rng = np.random.default_rng(self.random_state)
        n = len(X)
        # Con menos flujos que `max_samples` se muestrea CON reemplazo: si no,
        # el árbol ve el dataset completo, casi todas las muestras acaban a la
        # altura límite y el score deja de discriminar (todo ~0.5).
        tam_muestra = self.max_samples
        con_reemplazo = n < tam_muestra
        self._c_max = _c_factor(tam_muestra) or 1.0
        self._arboles = []
        for _ in range(self.n_estimators):
            muestra = rng.choice(n, size=tam_muestra, replace=con_reemplazo)
            self._arboles.append(self._construir(X[muestra], rng))
        # Línea base: con qué scores crudos se queda el propio entrenamiento.
        crudos = self._crudos(X)
        self._scores_base = np.sort(crudos)
        base_std = float(np.std(crudos)) or 1.0
        self._spread = max(1e-6, base_std)
        self.trained = True
        self.n_flows = n
        self.pcap_hash = pcap_hash
        self.trained_at_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _construir(self, X, rng) -> dict[str, Any]:
        """Árbol de aislamiento hasta la altura límite ``ceil(log2(n))``."""
        features: list[int] = []
        thresholds: list[float] = []
        left: list[int] = []
        right: list[int] = []
        sizes: list[int] = []
        limite = int(math.ceil(math.log2(len(X)))) if len(X) > 1 else 0

        def nodo(indices, profundidad) -> int:
            actual = len(features)
            features.append(-1)
            thresholds.append(0.0)
            left.append(-1)
            right.append(-1)
            sizes.append(len(indices))
            if profundidad >= limite or len(indices) <= 1:
                return actual
            sub = X[indices]
            minimos, maximos = sub.min(axis=0), sub.max(axis=0)
            rango = maximos - minimos
            validas = np.flatnonzero(rango > 0)
            if len(validas) == 0:          # todas las columnas constantes
                return actual
            f = int(rng.choice(validas))
            umbral = float(rng.uniform(minimos[f], maximos[f]))
            mascara = sub[:, f] < umbral
            izq, der = indices[mascara], indices[~mascara]
            if len(izq) == 0 or len(der) == 0:
                return actual
            features[actual] = f
            thresholds[actual] = umbral
            left[actual] = nodo(izq, profundidad + 1)
            right[actual] = nodo(der, profundidad + 1)
            return actual

        nodo(np.arange(len(X)), 0)
        return {
            "feature": np.asarray(features, dtype=np.int16),
            "threshold": np.asarray(thresholds, dtype=np.float64),
            "left": np.asarray(left, dtype=np.int32),
            "right": np.asarray(right, dtype=np.int32),
            "size": np.asarray(sizes, dtype=np.int32),
        }

    # -------------------------------------------------------------- puntuar
    def _profundidad(self, arbol: dict[str, Any], x) -> float:
        nodo = 0
        profundidad = 0
        while arbol["feature"][nodo] >= 0:
            f = int(arbol["feature"][nodo])
            nodo = (int(arbol["left"][nodo]) if x[f] < arbol["threshold"][nodo]
                    else int(arbol["right"][nodo]))
            profundidad += 1
        return profundidad + _c_factor(int(arbol["size"][nodo]))

    def _crudo(self, x) -> float:
        if not self._arboles:
            return 0.0
        media = sum(self._profundidad(a, x) for a in self._arboles) / len(self._arboles)
        return float(2.0 ** (-media / self._c_max))

    def _crudos(self, X) -> "np.ndarray":
        return np.asarray([self._crudo(x) for x in X], dtype=np.float64)

    def score(self, flow: FlowFeatures) -> float:
        """Score en [0, 1]; 1.0 = más anómalo que la línea base completa."""
        if not self.trained:
            return 0.0
        crudo = self._crudo(np.asarray(_vector(flow), dtype=np.float64))
        base = self._scores_base
        # Percentil dentro de la línea base, escalado a 0..0.9.
        posicion = int(np.searchsorted(base, crudo, side="right"))
        dentro = 0.9 * posicion / len(base)
        maximo = float(base[-1])
        if crudo <= maximo:
            return max(0.0, min(0.9, dentro))
        # Por encima de todo lo visto: 0.9 -> 1.0, sin saltos. La cola satura
        # a media desviación típica por unidad, de modo que 0.99 se alcanza con
        # ~2 desviaciones por encima del máximo de la línea base: más allá de
        # eso ya no hay nada con lo que comparar y el score debe ser concluyente.
        exceso = (crudo - maximo) / (self._spread * 0.5)
        return float(min(1.0, 0.9 + 0.1 * (1.0 - math.exp(-exceso))))

    # ------------------------------------------------------------ persistir
    def save(self, path_npz: str | Path, path_json: str | Path) -> None:
        """Guarda árboles en ``.npz`` y metadatos en ``.json`` (D-08)."""
        if not self.trained:
            raise ValueError("no se puede guardar un modelo sin entrenar")
        import numpy as _np
        _np.savez_compressed(
            Path(path_npz),
            offsets=_np.cumsum([0] + [len(a["feature"]) for a in self._arboles]),
            feature=_np.concatenate([a["feature"] for a in self._arboles]),
            threshold=_np.concatenate([a["threshold"] for a in self._arboles]),
            left=_np.concatenate([a["left"] for a in self._arboles]),
            right=_np.concatenate([a["right"] for a in self._arboles]),
            size=_np.concatenate([a["size"] for a in self._arboles]),
            scores_base=self._scores_base,
            c_max=_np.asarray([self._c_max]),
            spread=_np.asarray([self._spread]),
        )
        from batrade import __version__
        Path(path_json).write_text(json.dumps({
            "version": MODEL_VERSION,
            "n_estimators": self.n_estimators,
            "max_samples": self.max_samples,
            "random_state": self.random_state,
            "trained_at_iso": self.trained_at_iso,
            "pcap_hash": self.pcap_hash,
            "batrade_version": __version__,
            "feature_order": list(FEATURE_ORDER),
            "n_flows": self.n_flows,
        }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path_npz: str | Path, path_json: str | Path) -> "IsolationForestScorer":
        """Carga un modelo guardado; valida versión y orden de features."""
        import numpy as _np
        meta = json.loads(Path(path_json).read_text(encoding="utf-8"))
        if int(meta.get("version", 0)) != MODEL_VERSION:
            raise ValueError(
                f"modelo de flujos con versión {meta.get('version')!r}; "
                f"este Batrade espera {MODEL_VERSION} (reentrena)")
        if tuple(meta.get("feature_order") or ()) != FEATURE_ORDER:
            raise ValueError("el modelo se entrenó con otro orden de features (reentrena)")
        modelo = cls(n_estimators=int(meta["n_estimators"]),
                     max_samples=int(meta["max_samples"]),
                     random_state=int(meta["random_state"]))
        with _np.load(Path(path_npz)) as datos:
            offsets = datos["offsets"]
            modelo._arboles = []
            for i in range(len(offsets) - 1):
                desde, hasta = int(offsets[i]), int(offsets[i + 1])
                modelo._arboles.append({
                    "feature": datos["feature"][desde:hasta],
                    "threshold": datos["threshold"][desde:hasta],
                    "left": datos["left"][desde:hasta],
                    "right": datos["right"][desde:hasta],
                    "size": datos["size"][desde:hasta],
                })
            modelo._scores_base = datos["scores_base"].astype(_np.float64)
            modelo._c_max = float(datos["c_max"][0])
            modelo._spread = float(datos["spread"][0])
        modelo.trained = True
        modelo.pcap_hash = meta.get("pcap_hash")
        modelo.trained_at_iso = meta.get("trained_at_iso")
        modelo.n_flows = int(meta.get("n_flows", 0))
        return modelo

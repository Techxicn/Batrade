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
        # Los rellena `load`/el motor cuando el artefacto trae segmentación:
        # el IF global sigue puntuando, el segmentador sólo etiqueta.
        self.segmenter: "KMeansSegmenter | None" = None
        self.por_segmento: list[IsolationForestScorer | None] | None = None

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
        guardar_artefacto(path_npz, path_json, self,
                          segmenter=self.segmenter, segmentado=self.por_segmento)

    @classmethod
    def load(cls, path_npz: str | Path, path_json: str | Path) -> "IsolationForestScorer":
        """Carga un modelo guardado; valida versión y orden de features."""
        artefacto = leer_artefacto(path_npz, path_json)
        return artefacto["global"]


# --------------------------------------------------------------------------- #
# Persistencia compartida (D-08): un .npz + un .json para todo el artefacto
# --------------------------------------------------------------------------- #
def _paquete_arboles(arboles: list[dict[str, Any]]) -> dict[str, Any]:
    """Aplana los árboles de un bosque en arrays contiguos + offsets."""
    return {
        "offsets": np.cumsum([0] + [len(a["feature"]) for a in arboles]),
        "feature": np.concatenate([a["feature"] for a in arboles]),
        "threshold": np.concatenate([a["threshold"] for a in arboles]),
        "left": np.concatenate([a["left"] for a in arboles]),
        "right": np.concatenate([a["right"] for a in arboles]),
        "size": np.concatenate([a["size"] for a in arboles]),
    }


def _if_a_arrays(modelo: IsolationForestScorer, prefijo: str = "") -> dict[str, Any]:
    out = {f"{prefijo}{k}": v for k, v in _paquete_arboles(modelo._arboles).items()}
    out[f"{prefijo}scores_base"] = modelo._scores_base
    out[f"{prefijo}c_max"] = np.asarray([modelo._c_max])
    out[f"{prefijo}spread"] = np.asarray([modelo._spread])
    return out


def _if_de_arrays(datos, meta: dict[str, Any], prefijo: str = "") -> IsolationForestScorer:
    modelo = IsolationForestScorer(n_estimators=int(meta["n_estimators"]),
                                   max_samples=int(meta["max_samples"]),
                                   random_state=int(meta["random_state"]))
    offsets = datos[f"{prefijo}offsets"]
    modelo._arboles = []
    for i in range(len(offsets) - 1):
        desde, hasta = int(offsets[i]), int(offsets[i + 1])
        modelo._arboles.append({
            clave: datos[f"{prefijo}{clave}"][desde:hasta]
            for clave in ("feature", "threshold", "left", "right", "size")
        })
    modelo._scores_base = datos[f"{prefijo}scores_base"].astype(np.float64)
    modelo._c_max = float(datos[f"{prefijo}c_max"][0])
    modelo._spread = float(datos[f"{prefijo}spread"][0])
    modelo.trained = True
    modelo.n_flows = int(meta.get("n_flows", 0))
    return modelo


def guardar_artefacto(path_npz: str | Path, path_json: str | Path,
                      global_if: IsolationForestScorer, *,
                      segmenter: "KMeansSegmenter | None" = None,
                      segmentado: "list[IsolationForestScorer | None] | None" = None) -> None:
    """Escribe el artefacto completo: IF global + segmentador + IF por segmento.

    Todo va al mismo par ``.npz``/``.json``: los arrays del IF global sin
    prefijo (un lector antiguo sigue pudiendo cargarlo), los del segmentador con
    prefijo ``kmeans_`` y los de cada segmento con ``s<i>_``.
    """
    from batrade import __version__
    if not global_if.trained:
        raise ValueError("no se puede guardar un modelo sin entrenar")
    arrays: dict[str, Any] = _if_a_arrays(global_if)
    meta: dict[str, Any] = {
        "version": MODEL_VERSION,
        "n_estimators": global_if.n_estimators,
        "max_samples": global_if.max_samples,
        "random_state": global_if.random_state,
        "trained_at_iso": global_if.trained_at_iso,
        "pcap_hash": global_if.pcap_hash,
        "batrade_version": __version__,
        "feature_order": list(FEATURE_ORDER),
        "n_flows": global_if.n_flows,
    }
    if segmenter is not None:
        arrays.update(segmenter.to_arrays())
        meta["segmenter"] = segmenter.to_meta()
    if segmentado is not None:
        meta["segmentado"] = []
        for i, modelo in enumerate(segmentado):
            if modelo is None:
                meta["segmentado"].append(None)
                continue
            arrays.update(_if_a_arrays(modelo, prefijo=f"s{i}_"))
            meta["segmentado"].append({
                "n_estimators": modelo.n_estimators,
                "max_samples": modelo.max_samples,
                "random_state": modelo.random_state,
                "n_flows": modelo.n_flows,
            })
    np.savez_compressed(Path(path_npz), **arrays)
    Path(path_json).write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n",
                               encoding="utf-8")


def leer_artefacto(path_npz: str | Path, path_json: str | Path) -> dict[str, Any]:
    """Lee el artefacto completo. Valida versión y orden de features."""
    meta = json.loads(Path(path_json).read_text(encoding="utf-8"))
    if int(meta.get("version", 0)) != MODEL_VERSION:
        raise ValueError(
            f"modelo de flujos con versión {meta.get('version')!r}; "
            f"este Batrade espera {MODEL_VERSION} (reentrena)")
    if tuple(meta.get("feature_order") or ()) != FEATURE_ORDER:
        raise ValueError("el modelo se entrenó con otro orden de features (reentrena)")
    with np.load(Path(path_npz)) as datos:
        global_if = _if_de_arrays(datos, meta)
        global_if.pcap_hash = meta.get("pcap_hash")
        global_if.trained_at_iso = meta.get("trained_at_iso")
        segmenter = None
        if meta.get("segmenter"):
            segmenter = KMeansSegmenter.from_arrays(datos, meta["segmenter"])
        segmentado = None
        if meta.get("segmentado") is not None:
            segmentado = [
                None if m is None else _if_de_arrays(datos, m, prefijo=f"s{i}_")
                for i, m in enumerate(meta["segmentado"])
            ]
        global_if.segmenter = segmenter
        global_if.por_segmento = segmentado
    return {"global": global_if, "segmenter": segmenter,
            "segmentado": segmentado, "meta": meta}


# --------------------------------------------------------------------------- #
# K-Means: segmentador, no scorer
# --------------------------------------------------------------------------- #
def _kmeans(Z, k: int, rng, n_init: int = 10, max_iter: int = 100):
    """k-means++ con ``n_init`` arranques; devuelve (inercia, centroides, etiquetas)."""
    mejor: tuple[float, Any, Any] | None = None
    for _ in range(n_init):
        centroides = Z[rng.choice(len(Z), size=k, replace=False)].copy()
        etiquetas = np.zeros(len(Z), dtype=np.int64)
        for _ in range(max_iter):
            distancias = ((Z[:, None, :] - centroides[None, :, :]) ** 2).sum(axis=2)
            etiquetas = distancias.argmin(axis=1)
            nuevos = centroides.copy()
            for j in range(k):
                del_grupo = Z[etiquetas == j]
                if len(del_grupo):
                    nuevos[j] = del_grupo.mean(axis=0)
            if np.allclose(nuevos, centroides):
                break
            centroides = nuevos
        inercia = float(((Z - centroides[etiquetas]) ** 2).sum())
        if mejor is None or inercia < mejor[0]:
            mejor = (inercia, centroides, etiquetas.copy())
    return mejor


def _etiquetas_de(Z, centroides):
    return ((Z[:, None, :] - centroides[None, :, :]) ** 2).sum(axis=2).argmin(axis=1)


def _silueta(Z, etiquetas, k: int) -> float:
    """Coeficiente de silueta medio; 0 si no se puede calcular."""
    n = len(Z)
    if n < 3 or k < 2:
        return 0.0
    distancias = np.sqrt(((Z[:, None, :] - Z[None, :, :]) ** 2).sum(axis=2))
    valores = []
    for i in range(n):
        propias = distancias[i][etiquetas == etiquetas[i]]
        if len(propias) <= 1:
            valores.append(0.0)          # un punto solo en su cluster no se evalúa
            continue
        a = propias.sum() / (len(propias) - 1)
        b = min(distancias[i][etiquetas == j].mean()
                for j in range(k) if j != etiquetas[i] and np.any(etiquetas == j))
        valores.append((b - a) / max(a, b) if max(a, b) > 0 else 0.0)
    return float(np.mean(valores))


class KMeansSegmenter:
    """Agrupa tráfico normal en ``k`` segmentos. No puntúa (D-07).

    Antes de agrupar se estandariza cada feature (media 0, desviación 1): sin
    eso, ``bytes`` e ``intervalo_medio_ms`` —con rangos de miles— se comen al
    resto en una distancia euclídea.

    Con ``k=None`` se prueba 2..8 y se elige el que maximiza la silueta sobre
    una muestra (máx. 400 flujos para no hacer O(n²) con miles). La silueta
    mide cuánto mejor encaja cada flujo en su cluster que en el vecino: es la
    opción estándar cuando no se quiere fijar ``k`` a ojo y se prefiere un
    criterio reproducible. El ``k`` elegido queda en el JSON del modelo.
    """

    RANGO_K = (2, 8)
    MAX_SILUETA = 400

    def __init__(self, random_state: int = 42, n_init: int = 10,
                 max_iter: int = 100):
        if np is None:
            raise RuntimeError(
                "KMeansSegmenter necesita numpy: instala el extra ml "
                "(pip install 'batrade[ml]')")
        self.random_state = int(random_state)
        self.n_init = max(1, int(n_init))
        self.max_iter = max(1, int(max_iter))
        self.k = 0
        self.inertia = 0.0
        self.silhouette = 0.0
        self.trained = False
        self._centroides = np.zeros((0, len(FEATURE_ORDER)), dtype=np.float64)
        self._media = np.zeros(len(FEATURE_ORDER), dtype=np.float64)
        self._desviacion = np.ones(len(FEATURE_ORDER), dtype=np.float64)

    # ------------------------------------------------------------- entrenar
    def fit(self, flows_normales: Sequence[FlowFeatures], k: int | None = None) -> None:
        """Agrupa los flujos; con ``k=None`` lo elige por silueta en 2..8."""
        X = np.asarray([_vector(f) for f in flows_normales], dtype=np.float64)
        if len(X) < 2:
            raise ValueError("hacen falta al menos 2 flujos para segmentar")
        self._media = X.mean(axis=0)
        desviacion = X.std(axis=0)
        self._desviacion = np.where(desviacion > 0, desviacion, 1.0)
        Z = (X - self._media) / self._desviacion
        self.k = int(k) if k is not None else self._elegir_k(Z)
        rng = np.random.default_rng(self.random_state)
        self.inertia, self._centroides, _ = _kmeans(Z, self.k, rng,
                                                    self.n_init, self.max_iter)
        self.silhouette = _silueta(Z, _etiquetas_de(Z, self._centroides), self.k)
        self.trained = True

    def _elegir_k(self, Z) -> int:
        n = len(Z)
        # No se eligen más segmentos de los que caben con el mínimo de
        # entrenamiento del IF por segmento: un k mayor produciría clusters que
        # caen al global y segmentar no serviría de nada.
        max_k = min(self.RANGO_K[1], max(2, n // MIN_FLUJOS_ENTRENAMIENTO))
        if n < 4:
            return 2
        muestra = (Z if n <= self.MAX_SILUETA
                   else Z[np.linspace(0, n - 1, self.MAX_SILUETA).astype(int)])
        mejor_k, mejor_silueta = 2, -2.0
        for candidato in range(self.RANGO_K[0], max_k + 1):
            rng = np.random.default_rng(self.random_state)
            _, centroides, _ = _kmeans(Z, candidato, rng, self.n_init, self.max_iter)
            silueta = _silueta(muestra, _etiquetas_de(muestra, centroides), candidato)
            if silueta > mejor_silueta + 1e-12:
                mejor_k, mejor_silueta = candidato, silueta
        return mejor_k

    # -------------------------------------------------------------- usar
    def segment(self, flow: FlowFeatures) -> int:
        """Índice de cluster del flujo (0..k-1)."""
        if not self.trained:
            return 0
        x = (np.asarray(_vector(flow), dtype=np.float64) - self._media) / self._desviacion
        distancias = ((self._centroides - x) ** 2).sum(axis=1)
        return int(distancias.argmin())

    # ------------------------------------------------------------ persistir
    def to_arrays(self) -> dict[str, Any]:
        return {
            "kmeans_centroides": self._centroides,
            "kmeans_media": self._media,
            "kmeans_desviacion": self._desviacion,
        }

    def to_meta(self) -> dict[str, Any]:
        return {
            "tipo": "kmeans",
            "k": self.k,
            "inertia": self.inertia,
            "silhouette": self.silhouette,
            "random_state": self.random_state,
            "feature_order": list(FEATURE_ORDER),
        }

    @classmethod
    def from_arrays(cls, datos, meta: dict[str, Any]) -> "KMeansSegmenter":
        if tuple(meta.get("feature_order") or ()) != FEATURE_ORDER:
            raise ValueError("el segmentador se entrenó con otro orden de features")
        segmentador = cls(random_state=int(meta.get("random_state", 42)))
        segmentador._centroides = datos["kmeans_centroides"].astype(np.float64)
        segmentador._media = datos["kmeans_media"].astype(np.float64)
        segmentador._desviacion = datos["kmeans_desviacion"].astype(np.float64)
        segmentador.k = int(meta.get("k", len(segmentador._centroides)))
        segmentador.inertia = float(meta.get("inertia", 0.0))
        segmentador.silhouette = float(meta.get("silhouette", 0.0))
        segmentador.trained = True
        return segmentador


class SegmentadoScorer(Scorer):
    """Segmentador K-Means + un Isolation Forest por segmento.

    El score de un flujo es el del IF de su segmento: cada tipo de tráfico
    (web, DNS, sesiones cortas...) se compara contra su propia línea base en
    lugar de contra una mezcla. Un segmento con muy pocos flujos no tiene
    distribución que aprender y cae al IF global, que sigue entrenado con todo.
    """

    def __init__(self, random_state: int = 42):
        self.random_state = int(random_state)
        self.segmenter = KMeansSegmenter(random_state=self.random_state)
        self.global_scorer = IsolationForestScorer(random_state=self.random_state)
        self.por_segmento: list[IsolationForestScorer | None] = []
        self.trained = False

    def fit(self, flows_normales: Sequence[FlowFeatures], k: int | None = None,
            *, pcap_hash: str | None = None) -> None:
        flujos = list(flows_normales)
        self.global_scorer.fit(flujos, pcap_hash=pcap_hash)
        self.segmenter.fit(flujos, k=k)
        grupos: list[list[FlowFeatures]] = [[] for _ in range(self.segmenter.k)]
        for flujo in flujos:
            grupos[self.segmenter.segment(flujo)].append(flujo)
        # El IF necesita su propio mínimo (8); el umbral de 3 paquetes de la
        # línea base queda cubierto porque 3 < 8.
        minimo = max(MIN_PAQUETES_ENTRENAMIENTO, MIN_FLUJOS_ENTRENAMIENTO)
        self.por_segmento = []
        for grupo in grupos:
            if len(grupo) < minimo:
                self.por_segmento.append(None)
                continue
            modelo = IsolationForestScorer(random_state=self.random_state)
            modelo.fit(grupo)
            self.por_segmento.append(modelo)
        self.trained = True

    def segment(self, flow: FlowFeatures) -> int:
        return self.segmenter.segment(flow)

    def score(self, flow: FlowFeatures) -> float:
        if not self.trained:
            return 0.0
        segmento = self.segmenter.segment(flow)
        if 0 <= segmento < len(self.por_segmento):
            modelo = self.por_segmento[segmento]
            if modelo is not None:
                return modelo.score(flow)
        return self.global_scorer.score(flow)

    # ------------------------------------------------------------ persistir
    def save(self, path_npz: str | Path, path_json: str | Path) -> None:
        guardar_artefacto(path_npz, path_json, self.global_scorer,
                          segmenter=self.segmenter, segmentado=self.por_segmento)

    @classmethod
    def desde_artefacto(cls, artefacto: dict[str, Any]) -> "SegmentadoScorer":
        if artefacto.get("segmenter") is None or artefacto.get("segmentado") is None:
            raise ValueError(
                "el modelo no trae segmentación; reentrena con --segmenter segmentado")
        modelo = cls(random_state=artefacto["global"].random_state)
        modelo.global_scorer = artefacto["global"]
        modelo.segmenter = artefacto["segmenter"]
        modelo.por_segmento = artefacto["segmentado"]
        modelo.trained = True
        return modelo

    @classmethod
    def load(cls, path_npz: str | Path, path_json: str | Path) -> "SegmentadoScorer":
        return cls.desde_artefacto(leer_artefacto(path_npz, path_json))

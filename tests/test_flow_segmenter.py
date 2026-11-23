"""K-Means como segmentador y SegmentadoScorer (un IF por segmento)."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

np = pytest.importorskip("numpy")

from batrade.config import ConfigError, load_config  # noqa: E402
from batrade.detect.scenarios import write_baseline_pcap  # noqa: E402
from batrade.flow import Flow, FlowFeatures, extract  # noqa: E402
from batrade.flow.engine import FlowEngine  # noqa: E402
from batrade.flow.scorer import (IsolationForestScorer,  # noqa: E402
                                 KMeansSegmenter, SegmentadoScorer,
                                 guardar_artefacto)
from batrade.flow.training import features_from_pcap  # noqa: E402


def _cfg(raiz: Path, extra: str = "") -> Path:
    ruta = Path(raiz) / "c.yaml"
    ruta.write_text("network: { interface: lo, cidr: 10.10.10.0/24 }\n" + extra,
                    encoding="utf-8")
    return ruta


def _flujo(**cambios) -> Flow:
    datos: dict[str, Any] = dict(
        src_ip="10.0.0.9", dst_ip="10.0.0.2", src_port=40000, dst_port=80,
        proto="tcp", ts_start=0, ts_end=1000, packets=7, bytes=1500,
        syn_count=2, ack_count=5, fin_count=1, packet_sizes=[60] * 7,
        inter_arrival_ms=[120, 150, 200, 260, 90, 340], bytes_src=900,
        bytes_dst=600)
    datos.update(cambios)
    return Flow(**datos)


def _c2(paquetes: int = 12, intervalo: int = 60_000) -> FlowFeatures:
    return extract(_flujo(
        packets=paquetes, bytes=60 * paquetes, packet_sizes=[60] * paquetes,
        inter_arrival_ms=[intervalo] * (paquetes - 1), syn_count=1,
        ack_count=paquetes - 1, fin_count=0, bytes_src=30 * paquetes,
        bytes_dst=30 * paquetes, ts_end=intervalo * (paquetes - 1)))


@pytest.fixture(scope="module")
def baseline(tmp_path_factory) -> list[FlowFeatures]:
    raiz = tmp_path_factory.mktemp("seg-baseline")
    cfg = load_config(_cfg(raiz), raiz)
    pcap = raiz / "baseline.pcap"
    write_baseline_pcap(str(pcap), cfg, clientes=12)
    return features_from_pcap(pcap)


# --------------------------------------------------------------------------- #
# KMeansSegmenter
# --------------------------------------------------------------------------- #
def test_kmeans_es_determinista(baseline):
    a = KMeansSegmenter(random_state=42)
    b = KMeansSegmenter(random_state=42)
    a.fit(baseline)
    b.fit(baseline)

    assert (a.k, a.inertia) == (b.k, b.inertia)
    assert [a.segment(f) for f in baseline] == [b.segment(f) for f in baseline]


def test_k_se_elige_en_el_rango(baseline):
    segmentador = KMeansSegmenter(random_state=42)
    segmentador.fit(baseline)          # k=None

    assert 2 <= segmentador.k <= 8
    assert segmentador.inertia > 0
    assert -1.0 <= segmentador.silhouette <= 1.0


def test_k_explicito_se_respeta(baseline):
    segmentador = KMeansSegmenter(random_state=42)
    segmentador.fit(baseline, k=2)
    assert segmentador.k == 2
    assert set(segmentador.segment(f) for f in baseline) <= {0, 1}


def test_flujos_identicos_caen_en_el_mismo_segmento(baseline):
    segmentador = KMeansSegmenter(random_state=42)
    segmentador.fit(baseline)
    normal = extract(_flujo())
    assert segmentador.segment(normal) == segmentador.segment(extract(_flujo()))


# --------------------------------------------------------------------------- #
# SegmentadoScorer
# --------------------------------------------------------------------------- #
def test_segmentado_no_empeora_la_separacion(baseline):
    modelo = SegmentadoScorer(random_state=42)
    modelo.fit(baseline)

    scores = [modelo.score(f) for f in baseline]
    assert max(scores) <= 0.9
    assert modelo.score(_c2()) > 0.95
    assert modelo.score(_c2()) > max(scores)


def test_segmentado_guarda_y_carga_con_los_mismos_scores(baseline, tmp_path):
    modelo = SegmentadoScorer(random_state=42)
    modelo.fit(baseline, pcap_hash="abc")
    ruta_npz, ruta_json = tmp_path / "m.npz", tmp_path / "m.json"
    modelo.save(ruta_npz, ruta_json)

    cargado = SegmentadoScorer.load(ruta_npz, ruta_json)
    meta = json.loads(ruta_json.read_text(encoding="utf-8"))

    assert cargado.segmenter.k == modelo.segmenter.k
    assert meta["segmenter"]["k"] == modelo.segmenter.k
    assert meta["segmenter"]["inertia"] == pytest.approx(modelo.segmenter.inertia)
    for flujo in [_c2(), extract(_flujo()), *baseline[:5]]:
        assert cargado.score(flujo) == pytest.approx(modelo.score(flujo))


def test_un_segmento_pequeno_cae_al_if_global():
    """Un grupo con menos flujos que el mínimo no entrena IF: usa el global."""
    normales = [extract(_flujo(inter_arrival_ms=[80 + i * 5 for i in range(6)],
                               bytes=1500 + i)) for i in range(30)]
    raros = [extract(_flujo(bytes=9_000_000, packet_sizes=[3_000_000] * 7,
                            bytes_src=8_000_000, bytes_dst=1_000_000,
                            inter_arrival_ms=[30] * 6)) for _ in range(3)]
    modelo = SegmentadoScorer(random_state=42)
    modelo.fit(normales + raros, k=3)          # k forzado: un grupo queda diminuto

    assert any(m is None for m in modelo.por_segmento)
    pequeno = next(i for i, m in enumerate(modelo.por_segmento) if m is None)
    del_grupo = next(f for f in raros + normales if modelo.segment(f) == pequeno)
    assert modelo.score(del_grupo) == pytest.approx(
        modelo.global_scorer.score(del_grupo))


# --------------------------------------------------------------------------- #
# Artefacto y motor
# --------------------------------------------------------------------------- #
def _entrenar_artefacto(tmp_path: Path, con_segmentado: bool) -> Path:
    base = tmp_path / "var" / "flow_model"
    base.parent.mkdir(parents=True, exist_ok=True)
    normales = [extract(_flujo(inter_arrival_ms=[90 + i * 7 + j for j in range(6)],
                               bytes=1200 + i * 10)) for i in range(40)]
    if con_segmentado:
        modelo = SegmentadoScorer(random_state=42)
        modelo.fit(normales, k=2)
        modelo.save(str(base) + ".npz", str(base) + ".json")
    else:
        global_if = IsolationForestScorer(n_estimators=30, random_state=42)
        global_if.fit(normales)
        guardar_artefacto(str(base) + ".npz", str(base) + ".json", global_if)
    return base


def test_el_motor_carga_el_modelo_segmentado(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="batrade.flow.engine")
    _entrenar_artefacto(tmp_path, con_segmentado=True)
    cfg = load_config(_cfg(
        tmp_path, "flow: { enabled: true, segmenter: segmentado, "
                  "model_path: var/flow_model }\n"), tmp_path)

    motor = FlowEngine(cfg)

    assert isinstance(motor.scorer, SegmentadoScorer)
    assert "modelo de flujos segmentado cargado" in caplog.text


def test_el_motor_usa_el_if_global_en_modo_kmeans(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="batrade.flow.engine")
    _entrenar_artefacto(tmp_path, con_segmentado=True)
    cfg = load_config(_cfg(
        tmp_path, "flow: { enabled: true, segmenter: kmeans, "
                  "model_path: var/flow_model }\n"), tmp_path)

    motor = FlowEngine(cfg)

    assert isinstance(motor.scorer, IsolationForestScorer)
    assert motor.scorer.segmenter is not None     # cargado, pero no cambia el score
    assert "con segmentador" in caplog.text


def test_segmentado_sin_if_por_segmento_cae_al_global(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="batrade.flow.engine")
    _entrenar_artefacto(tmp_path, con_segmentado=False)
    cfg = load_config(_cfg(
        tmp_path, "flow: { enabled: true, segmenter: segmentado, "
                  "model_path: var/flow_model }\n"), tmp_path)

    motor = FlowEngine(cfg)

    assert isinstance(motor.scorer, IsolationForestScorer)
    assert "no trae IF por segmento" in caplog.text


def test_el_hallazgo_lleva_el_segmento(tmp_path):
    _entrenar_artefacto(tmp_path, con_segmentado=True)
    cfg = load_config(_cfg(
        tmp_path, "flow: { enabled: true, segmenter: segmentado, "
                  "anomaly_threshold: 0.0, model_path: var/flow_model }\n"), tmp_path)
    motor = FlowEngine(cfg)

    flujo = _flujo(packets=12, bytes=720, packet_sizes=[60] * 12,
                   inter_arrival_ms=[60_000] * 11, syn_count=1, ack_count=11,
                   fin_count=0, bytes_src=360, bytes_dst=360, ts_end=660_000)
    hallazgo = motor._evaluar(flujo)

    assert hallazgo is not None
    assert isinstance(hallazgo.detalle["segmento"], int)


def test_segmenter_invalido_es_error(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load_config(_cfg(tmp_path, "flow: { segmenter: magia }\n"), tmp_path)
    assert any("flow.segmenter" in e for e in exc.value.errors)

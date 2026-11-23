"""Isolation Forest propio: determinismo, separación, persistencia y carga."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

np = pytest.importorskip("numpy")

from batrade.config import load_config  # noqa: E402
from batrade.detect.scenarios import write_baseline_pcap  # noqa: E402
from batrade.flow import Flow, FlowFeatures, extract  # noqa: E402
from batrade.flow.engine import FlowEngine  # noqa: E402
from batrade.flow.scorer import (MODEL_VERSION, DummyScorer,  # noqa: E402
                                 IsolationForestScorer)
from batrade.flow.training import features_from_pcap  # noqa: E402


# --------------------------------------------------------------------------- #
# Utilidades
# --------------------------------------------------------------------------- #
def _flujo(**cambios) -> Flow:
    datos: dict[str, Any] = dict(src_ip="10.0.0.9", dst_ip="10.0.0.2", src_port=40000,
                 dst_port=80, proto="tcp", ts_start=0, ts_end=1000,
                 packets=7, bytes=1500, syn_count=2, ack_count=5, fin_count=1,
                 packet_sizes=[60] * 7,
                 inter_arrival_ms=[120, 150, 200, 260, 90, 340],
                 bytes_src=900, bytes_dst=600)
    datos.update(cambios)
    return Flow(**datos)


def _c2(intervalo_ms: int = 60_000, paquetes: int = 12) -> FlowFeatures:
    """Baliza C2: muchos paquetes pequeños, hueco enorme y sin jitter."""
    huecos = [intervalo_ms] * (paquetes - 1)
    return extract(_flujo(
        packets=paquetes, bytes=60 * paquetes,
        packet_sizes=[60] * paquetes, inter_arrival_ms=huecos,
        syn_count=1, ack_count=paquetes - 1, fin_count=0,
        bytes_src=30 * paquetes, bytes_dst=30 * paquetes,
        ts_end=intervalo_ms * (paquetes - 1)))


@pytest.fixture(scope="module")
def baseline(tmp_path_factory) -> list[FlowFeatures]:
    """Características del pcap de tráfico normal que usa el entrenamiento."""
    raiz = tmp_path_factory.mktemp("baseline")
    from batrade.config import Config
    cfg = load_config(_escribir_cfg(raiz), raiz)
    pcap = raiz / "baseline.pcap"
    write_baseline_pcap(str(pcap), cfg, clientes=12)
    return features_from_pcap(pcap)


@pytest.fixture(scope="module")
def modelo(baseline) -> IsolationForestScorer:
    entrenado = IsolationForestScorer(n_estimators=100, random_state=42)
    entrenado.fit(baseline, pcap_hash="deadbeefdeadbeef")
    return entrenado


def _escribir_cfg(raiz: Path, extra: str = "") -> Path:
    ruta = Path(raiz) / "c.yaml"
    ruta.write_text("network: { interface: lo, cidr: 10.10.10.0/24 }\n" + extra,
                    encoding="utf-8")
    return ruta


# --------------------------------------------------------------------------- #
# Determinismo y separación
# --------------------------------------------------------------------------- #
def test_el_entrenamiento_es_determinista(baseline):
    a = IsolationForestScorer(random_state=42)
    b = IsolationForestScorer(random_state=42)
    a.fit(baseline)
    b.fit(baseline)
    muestra = [_c2(), extract(_flujo())]
    assert [a.score(f) for f in muestra] == pytest.approx([b.score(f) for f in muestra])

    otro = IsolationForestScorer(random_state=7)
    otro.fit(baseline)
    assert otro.score(_c2()) != pytest.approx(a.score(_c2()))


def test_el_trafico_normal_puntua_bajo(modelo, baseline):
    scores = [modelo.score(f) for f in baseline]
    assert max(scores) <= 0.9          # dentro de la línea base: nunca supera 0.9
    assert sorted(scores)[len(scores) // 2] < 0.5


def test_una_baliza_c2_puntua_alto(modelo, baseline):
    score = modelo.score(_c2())
    assert score > 0.95
    assert score > max(modelo.score(f) for f in baseline)


def test_el_score_queda_en_rango_unitario(modelo, baseline):
    for features in [_c2(), extract(_flujo()), *baseline[:10]]:
        assert 0.0 <= modelo.score(features) <= 1.0


# --------------------------------------------------------------------------- #
# Persistencia
# --------------------------------------------------------------------------- #
def test_save_load_da_los_mismos_scores(modelo, tmp_path):
    ruta_npz, ruta_json = tmp_path / "modelo.npz", tmp_path / "modelo.json"
    modelo.save(ruta_npz, ruta_json)
    cargado = IsolationForestScorer.load(ruta_npz, ruta_json)

    for features in [_c2(), _c2(300_000, 8), extract(_flujo())]:
        assert cargado.score(features) == pytest.approx(modelo.score(features))
    assert cargado.n_flows == modelo.n_flows


def test_los_metadatos_llevan_lo_que_exige_el_formato(modelo, tmp_path):
    ruta_npz, ruta_json = tmp_path / "modelo.npz", tmp_path / "modelo.json"
    modelo.save(ruta_npz, ruta_json)
    meta = json.loads(ruta_json.read_text(encoding="utf-8"))

    assert meta["version"] == MODEL_VERSION
    assert meta["n_estimators"] == modelo.n_estimators
    assert meta["max_samples"] == modelo.max_samples
    assert meta["random_state"] == modelo.random_state
    assert meta["trained_at_iso"] and meta["trained_at_iso"].endswith("+00:00")
    assert meta["pcap_hash"] == "deadbeefdeadbeef"
    assert meta["batrade_version"]
    assert meta["feature_order"]


def test_load_rechaza_otra_version(modelo, tmp_path):
    ruta_npz, ruta_json = tmp_path / "modelo.npz", tmp_path / "modelo.json"
    modelo.save(ruta_npz, ruta_json)
    meta = json.loads(ruta_json.read_text(encoding="utf-8"))
    meta["version"] = MODEL_VERSION + 1
    ruta_json.write_text(json.dumps(meta), encoding="utf-8")

    with pytest.raises(ValueError) as exc:
        IsolationForestScorer.load(ruta_npz, ruta_json)
    assert "versión" in str(exc.value)


def test_sin_entrenar_no_guarda_ni_puntua(tmp_path):
    vacio = IsolationForestScorer()
    assert vacio.score(_c2()) == 0.0
    with pytest.raises(ValueError):
        vacio.save(tmp_path / "m.npz", tmp_path / "m.json")


def test_fit_exige_un_minimo_de_flujos():
    with pytest.raises(ValueError):
        IsolationForestScorer().fit([extract(_flujo())] * 3)


# --------------------------------------------------------------------------- #
# Características: las dos correcciones
# --------------------------------------------------------------------------- #
def test_bytes_por_direccion_es_none_sin_atribucion():
    solo_ida = extract(_flujo(bytes_dst=0))
    assert solo_ida.bytes_por_direccion is None

    dos_direcciones = extract(_flujo())
    assert dos_direcciones.bytes_por_direccion == {"10.0.0.9": 900, "10.0.0.2": 600}

    vacio = Flow(src_ip="10.0.0.9", dst_ip="10.0.0.2", src_port=1,
                 dst_port=2, proto="tcp", ts_start=0)
    assert extract(vacio).bytes_por_direccion is None


def test_ratio_syn_ack_esta_acotado():
    barrido = extract(_flujo(syn_count=500, ack_count=0))
    assert barrido.ratio_syn_ack == 10.0

    normal = extract(_flujo(syn_count=2, ack_count=5))
    assert normal.ratio_syn_ack == pytest.approx(0.4)


# --------------------------------------------------------------------------- #
# Carga del modelo desde el motor
# --------------------------------------------------------------------------- #
def test_el_motor_carga_el_modelo_si_existe(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="batrade.flow.engine")
    raiz = tmp_path
    modelo_path = raiz / "var" / "flow_model"
    modelo = IsolationForestScorer(random_state=42, n_estimators=20)
    modelo.fit([extract(_flujo(inter_arrival_ms=[60 + i * 7 for i in range(6)]))
                for i in range(20)], pcap_hash="x")
    modelo_path.parent.mkdir(parents=True, exist_ok=True)
    modelo.save(str(modelo_path) + ".npz", str(modelo_path) + ".json")

    cfg = load_config(_escribir_cfg(
        raiz, "flow: { enabled: true, model_path: var/flow_model }\n"), raiz)
    motor = FlowEngine(cfg)

    assert isinstance(motor.scorer, IsolationForestScorer)
    assert "modelo de flujos cargado" in caplog.text


def test_el_motor_usa_dummy_si_no_hay_modelo(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="batrade.flow.engine")
    cfg = load_config(_escribir_cfg(
        tmp_path, "flow: { enabled: true, model_path: var/no_existe }\n"), tmp_path)
    motor = FlowEngine(cfg)

    assert isinstance(motor.scorer, DummyScorer)
    assert "modelo no entrenado" in caplog.text


def test_el_motor_no_avisa_si_el_modulo_esta_apagado(tmp_path, caplog):
    cfg = load_config(_escribir_cfg(
        tmp_path, "flow: { enabled: false, model_path: var/no_existe }\n"), tmp_path)
    motor = FlowEngine(cfg)

    assert isinstance(motor.scorer, DummyScorer)
    assert "modelo no entrenado" not in caplog.text

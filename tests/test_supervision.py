"""Supervisión de hilos y observabilidad de la captura (R-01, D-01)."""
from __future__ import annotations

import json
import queue
import sqlite3
import threading
from typing import Any

import pytest

from batrade import db, store
from batrade.net.caps import Capabilities
from batrade.sensor import Sensor


class _NotifierFalso:
    def __init__(self) -> None:
        self.stop_event = threading.Event()
        self.encoladas: list[int] = []
        self.sent = self.failed = 0

    def enqueue(self, conn, event_id: int, ts: int) -> int:
        self.encoladas.append(event_id)
        return 1

    def run(self) -> None:  # pragma: no cover - no se usa
        pass


class _EngineFalso:
    def snapshot(self) -> dict:
        return {"ok": True}


def _sensor(cfg, conn, modo: str = "live") -> Any:
    """Sensor mínimo con lo que usan el guardián, el latido y la captura."""
    sensor: Any = object.__new__(Sensor)
    sensor.cfg = cfg
    sensor.mode = modo
    sensor.caps = Capabilities()
    sensor._local = threading.local()
    sensor._threads = []
    sensor._supervisados = {}
    sensor._lock = threading.RLock()
    sensor.stop_event = threading.Event()
    sensor.conn = conn
    sensor.notifier = _NotifierFalso()
    sensor.engine = _EngineFalso()
    sensor.scan_queue = queue.Queue(maxsize=8)
    sensor._contadores = {"arp": 0, "syn": 0, "dhcp": 0, "neigh": 0}
    sensor._ultima_obs_ts = None
    sensor._hb_ts = 0
    sensor._reinicios_programados = []
    sensor._schedule_restart = (  # type: ignore[method-assign]
        lambda nombre, ms: sensor._reinicios_programados.append((nombre, ms))
    )
    return sensor


def _evento(conn, tipo: str = "thread_died"):
    return conn.execute(
        "SELECT * FROM events WHERE tipo = ? ORDER BY id DESC LIMIT 1", (tipo,)
    ).fetchone()


# --------------------------------------------------------------------------- #
# Muerte de un hilo
# --------------------------------------------------------------------------- #
def test_hilo_que_falla_emite_evento_y_cierra_su_conexion(conn, cfg):
    sensor = _sensor(cfg, conn)
    propias: list[sqlite3.Connection] = []

    def objetivo() -> None:
        propia = db.connect(cfg.paths.db)
        sensor._local.conn = propia
        propias.append(propia)
        raise RuntimeError("boom en el barrido")

    sensor._spawn(objetivo, "batrade-sweep")
    hilo = sensor._supervisados["batrade-sweep"]["hilo"]
    hilo.join(5)
    assert not hilo.is_alive()

    fila = _evento(conn)
    assert fila is not None, "no se registró thread_died"
    assert fila["severidad"] == "crit"
    detalle = json.loads(fila["detalle_json"])
    assert "batrade-sweep" in detalle["resumen"]
    assert "RuntimeError" in detalle["resumen"]
    # Nada de datos sensibles: sólo el nombre del hilo y el tipo de excepción.
    assert "boom" not in fila["detalle_json"]

    # La conexión propia del hilo se cerró en el finally.
    with pytest.raises(sqlite3.ProgrammingError):
        propias[0].execute("SELECT 1")


@pytest.mark.parametrize("nombre,severidad", [
    ("batrade-sniff", "crit"),
    ("batrade-sweep", "crit"),
    ("batrade-neigh", "crit"),
    ("batrade-notify", "crit"),
    ("batrade-main", "warn"),
    ("batrade-scan-0", "warn"),
    ("batrade-feed", "warn"),
])
def test_severidad_segun_el_hilo(conn, cfg, nombre, severidad):
    sensor = _sensor(cfg, conn)
    sensor._on_thread_death(nombre, RuntimeError("x"), 1_000_000)

    fila = conn.execute(
        "SELECT * FROM events WHERE tipo = 'thread_died' AND clave_dedupe = ?",
        (f"thread:died:{nombre}",),
    ).fetchone()
    assert fila is not None
    assert fila["severidad"] == severidad


def test_muerte_repetida_deduplica_por_hilo(conn, cfg):
    sensor = _sensor(cfg, conn)
    sensor._on_thread_death("batrade-main", RuntimeError("x"), 1_000_000)
    sensor._on_thread_death("batrade-main", RuntimeError("y"), 1_000_100)

    filas = conn.execute(
        "SELECT * FROM events WHERE clave_dedupe = 'thread:died:batrade-main'"
    ).fetchall()
    assert len(filas) == 1
    assert filas[0]["repeat_count"] == 2


def test_reinicio_exponencial_y_limite_por_hora(conn, cfg):
    sensor = _sensor(cfg, conn)
    base = 1_000_000
    esperas = []
    for i in range(5):
        sensor._on_thread_death("batrade-sniff", RuntimeError("x"), base + i)
        esperas.append(sensor._reinicios_programados[-1][1])
    assert esperas == [5_000, 10_000, 20_000, 40_000, 80_000]

    reinicios_antes = len(sensor._reinicios_programados)
    sensor._on_thread_death("batrade-sniff", RuntimeError("x"), base + 10)
    assert len(sensor._reinicios_programados) == reinicios_antes  # no hay 6.º

    escalado = conn.execute(
        "SELECT * FROM events WHERE clave_dedupe = 'thread:stopped:batrade-sniff'"
    ).fetchone()
    assert escalado is not None
    assert escalado["severidad"] == "crit"
    assert json.loads(escalado["detalle_json"])["reinicios"] == 5


def test_un_hilo_no_critico_no_se_reinicia(conn, cfg):
    sensor = _sensor(cfg, conn)
    sensor._on_thread_death("batrade-scan-0", RuntimeError("x"), 1_000_000)
    assert sensor._reinicios_programados == []


# --------------------------------------------------------------------------- #
# Latido con estado de captura
# --------------------------------------------------------------------------- #
def test_latido_incluye_estado_de_captura(conn, cfg):
    sensor = _sensor(cfg, conn, modo="live")
    for _ in range(3):
        sensor._note_observation("arp", 1_000_000)
    sensor._note_observation("neigh", 1_000_100)

    sensor._heartbeat(conn, 1_000_200)
    detalle = json.loads(store.get_heartbeat(conn, "sensor")["detalle"])
    captura = detalle["captura"]
    assert captura["contadores"] == {"arp": 3, "syn": 0, "dhcp": 0, "neigh": 1}
    assert captura["ultima_obs_ts"] == 1_000_100
    assert captura["idle_s"] == 0
    assert captura["estado"] in ("viva", "detenida")


def test_captura_no_aplica_fuera_de_live(conn, cfg):
    sensor = _sensor(cfg, conn, modo="replay")
    sensor._note_observation("arp", 1_000_000)
    assert sensor._capture_state(1_000_500)["estado"] == "no_aplica"


def test_sin_observaciones_avisa_sin_notificar(conn, cfg):
    cfg.sensor.capture_idle_warn_s = 600
    sensor = _sensor(cfg, conn, modo="live")
    sensor._note_observation("arp", 1_000_000)

    assert sensor._check_capture_idle(conn, 1_000_000 + 300_000) is False
    assert sensor._check_capture_idle(conn, 1_000_000 + 700_000) is True

    fila = _evento(conn, "capture_idle")
    assert fila is not None
    assert fila["severidad"] == "info"
    assert sensor.notifier.encoladas == []      # info no se notifica


def test_captura_inactiva_no_aplica_sin_modo_live(conn, cfg):
    sensor = _sensor(cfg, conn, modo="simulate")
    assert sensor._check_capture_idle(conn, 9_000_000) is False


def test_capture_idle_warn_s_tiene_minimo(tmp_path):
    from batrade.config import ConfigError, load_config

    ruta = tmp_path / "c.yaml"
    ruta.write_text(
        "network: { interface: lo, cidr: 10.10.10.0/24 }\n"
        "sensor: { capture_idle_warn_s: 30 }\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError) as exc:
        load_config(ruta, tmp_path)
    assert any("capture_idle_warn_s" in e for e in exc.value.errors)


# --------------------------------------------------------------------------- #
# /health
# --------------------------------------------------------------------------- #
def _latido(conn, **captura) -> None:
    from batrade.net.iputil import now_ms as _now

    store.heartbeat(conn, "sensor", _now(), json.dumps({
        "mode": "live", "state": "running", "captura": captura}))


def test_health_muestra_la_linea_de_captura(conn, cfg):
    from batrade.dashboard.app import create_app

    _latido(conn, estado="viva", ultima_obs_ts=1_000, idle_s=5,
            contadores={"arp": 2, "syn": 0, "dhcp": 0, "neigh": 1})
    html = create_app(cfg).test_client().get("/health").data.decode()
    assert "Captura" in html
    assert "arp 2" in html and "neigh 1" in html
    assert "Sin tráfico capturado" not in html


def test_health_avisa_si_la_captura_esta_callada(conn, cfg):
    from batrade.dashboard.app import create_app

    cfg.sensor.capture_idle_warn_s = 600
    _latido(conn, estado="viva", ultima_obs_ts=1_000, idle_s=9_000,
            contadores={"arp": 4, "syn": 0, "dhcp": 0, "neigh": 0})
    html = create_app(cfg).test_client().get("/health").data.decode()
    assert "Sin tráfico capturado desde hace 150 min" in html
    assert "CAP_NET_RAW" in html


def test_health_avisa_si_el_sniffer_esta_detenido(conn, cfg):
    from batrade.dashboard.app import create_app

    _latido(conn, estado="detenida", ultima_obs_ts=1_000, idle_s=30,
            contadores={"arp": 1, "syn": 0, "dhcp": 0, "neigh": 0})
    html = create_app(cfg).test_client().get("/health").data.decode()
    assert "Captura detenida" in html
    assert "thread_died" in html

"""Pool de verificación ARP: concurrencia acotada sin perder el evento."""
from __future__ import annotations

import queue
import threading
import time
from typing import Any

from batrade import db, sensor as sensor_mod
from batrade.detect.engine import Engine
from batrade.detect.state import Baseline
from batrade.net.caps import Capabilities
from batrade.sensor import Sensor
from tests.conftest import GW_IP, GW_MAC


def _sensor(cfg) -> Any:
    db.initialize(cfg.paths.db)
    sensor: Any = object.__new__(Sensor)
    sensor.cfg = cfg
    sensor.caps = Capabilities(raw_capture=True)
    sensor.stop_event = threading.Event()
    sensor._lock = threading.RLock()
    sensor._threads = []
    sensor._verify_queue = queue.Queue(maxsize=sensor_mod.VERIFY_QUEUE_MAX)
    sensor._verify_started = False
    sensor.engine = Engine(cfg, Baseline(gateway_ip=GW_IP, gateway_mac=GW_MAC))
    return sensor


def test_pool_respects_concurrency_cap(cfg, monkeypatch):
    sensor = _sensor(cfg)
    activos = 0
    maximo = 0
    completados = 0
    lock = threading.Lock()

    def fake_probe(ip, iface=None, timeout=1.5):
        nonlocal activos, maximo, completados
        with lock:
            activos += 1
            maximo = max(maximo, activos)
        time.sleep(0.05)
        with lock:
            activos -= 1
            completados += 1
        return set()

    monkeypatch.setattr(sensor_mod, "probe_binding", fake_probe)
    for i in range(24):
        sensor._spawn_verification(i + 1, f"10.10.10.{i + 1}")

    limite = time.time() + 15
    while time.time() < limite and completados < 24:
        time.sleep(0.02)
    sensor.stop_event.set()

    assert completados == 24
    assert maximo <= sensor_mod.VERIFY_WORKERS
    assert maximo > 1          # el pool sí trabaja en paralelo


def test_pool_is_created_once(cfg, monkeypatch):
    monkeypatch.setattr(sensor_mod, "probe_binding", lambda *a, **k: None)
    sensor = _sensor(cfg)
    sensor._spawn_verification(1, GW_IP)
    primera = list(sensor._threads)
    sensor._spawn_verification(2, GW_IP)
    assert sensor._threads == primera
    assert len(primera) == sensor_mod.VERIFY_WORKERS
    sensor.stop_event.set()


def test_full_queue_does_not_raise_or_block(cfg):
    sensor = _sensor(cfg)
    sensor._ensure_verify_pool = lambda: None      # sin workers: la cola no drena
    while True:
        try:
            sensor._verify_queue.put_nowait((0, GW_IP))
        except queue.Full:
            break
    inicio = time.monotonic()
    sensor._spawn_verification(99, GW_IP)          # no debe lanzar ni bloquear
    assert time.monotonic() - inicio < 1.0
    assert sensor._verify_queue.qsize() == sensor_mod.VERIFY_QUEUE_MAX


def test_worker_survives_probe_errors(cfg, monkeypatch):
    sensor = _sensor(cfg)
    llamadas = []

    def rota(ip, iface=None, timeout=1.5):
        llamadas.append(ip)
        raise RuntimeError("sonda rota")

    monkeypatch.setattr(sensor_mod, "probe_binding", rota)
    for i in range(6):
        sensor._spawn_verification(i + 1, f"10.10.10.{i + 1}")

    limite = time.time() + 10
    while time.time() < limite and len(llamadas) < 6:
        time.sleep(0.02)
    sensor.stop_event.set()
    assert len(llamadas) == 6        # el pool sigue vivo tras cada excepción


def test_un_error_de_sqlite_no_escapa_de_la_verificacion(cfg, monkeypatch, caplog):
    """F-02: una base ocupada no puede tumbar la verificación ni callarse el evento."""
    import sqlite3

    sensor = _sensor(cfg)

    def bloqueada(*_args, **_kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr("batrade.store.set_event_verified", bloqueada)
    monkeypatch.setattr("batrade.sensor.probe_binding",
                        lambda *_a, **_k: [GW_MAC])

    with caplog.at_level("WARNING", logger="batrade.sensor"):
        sensor._run_verification(4242, "10.10.10.50")   # no debe lanzar

    texto = caplog.text
    assert "4242" in texto
    assert "database is locked" in texto


def test_stop_deja_sin_hilos_de_verificacion(cfg, monkeypatch):
    """F-03: con un pool real, stop() no deja hilos batrade-verify-* vivos."""
    sensor = _sensor(cfg)
    sensor.scan_queue = queue.Queue(maxsize=8)
    sensor.conn = db.connect(cfg.paths.db)
    sensor._closed = False
    sensor.mode = "degraded"
    sensor.notifier = type("NotifierFalso", (), {
        "stop_event": threading.Event(), "sent": 0, "failed": 0})()

    antes = {id(t) for t in threading.enumerate()}
    sensor._ensure_verify_pool()
    del_pool = [t for t in threading.enumerate()
                if id(t) not in antes and t.name.startswith("batrade-verify")]
    assert len(del_pool) == sensor_mod.VERIFY_WORKERS

    sensor.stop()

    assert [t for t in del_pool if t.is_alive()] == []

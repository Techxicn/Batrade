"""Programación automática de escaneos: primeras visitas, quick y semanal (RF-10)."""
from __future__ import annotations

import queue
import threading
from typing import Any

from batrade import store
from batrade.sensor import Sensor

HORA_MS = 3600_000
DIA_MS = 24 * HORA_MS


def _sensor(cfg, sensor_ip: str = "10.10.10.200") -> Any:
    """Sensor mínimo: sólo lo que usa ``_schedule_scans`` (sin red ni hilos)."""
    sensor: Any = object.__new__(Sensor)
    sensor.cfg = cfg
    sensor.sensor_ip = sensor_ip
    sensor._lock = threading.RLock()
    sensor._pending = set()
    sensor.scan_queue = queue.Queue(maxsize=64)
    return sensor


def _jobs(sensor) -> list[tuple[str, str]]:
    out = []
    while not sensor.scan_queue.empty():
        job = sensor.scan_queue.get_nowait()
        out.append((job.ip, job.profile))
    return out


def _device(conn, mac: str, ip: str, *, confianza: str = "desconocido") -> int:
    res = store.upsert_device(conn, mac=mac, ip=ip, ts=1_000)
    store.set_device_state(conn, res["device_id"], estado=confianza)
    return res["device_id"]


def _scan(conn, device_id: int, perfil: str, ts: int, estado: str = "ok") -> None:
    scan_id = store.start_scan(conn, device_id, perfil, perfil, f"nmap {perfil}", ts)
    store.finish_scan(conn, scan_id, ts=ts, estado=estado)


def test_first_sighting_gets_standard_scan(conn, cfg):
    cfg.scan.enabled = True
    did = _device(conn, "3c:22:fb:11:22:33", "10.10.10.50")
    sensor = _sensor(cfg)
    sensor._schedule_scans(conn, {"10.10.10.50": "3c:22:fb:11:22:33"}, 1_000_000)
    assert _jobs(sensor) == [("10.10.10.50", "standard")]
    assert did


def test_quick_rescan_uses_configured_hours(conn, cfg):
    cfg.scan.enabled = True
    cfg.scan.quick_periodic_hours = 2
    _device(conn, "3c:22:fb:11:22:33", "10.10.10.50")
    did = store.get_device_by_ip(conn, "10.10.10.50")["id"]
    _scan(conn, did, "quick", ts=1_000_000)

    # 1 h después: nada que hacer todavía.
    sensor = _sensor(cfg)
    sensor._schedule_scans(conn, {"10.10.10.50": "x"}, 1_000_000 + HORA_MS)
    assert _jobs(sensor) == []

    # 3 h después: quick vencido (el plazo configurado es 2 h, no 24 h).
    sensor = _sensor(cfg)
    sensor._schedule_scans(conn, {"10.10.10.50": "x"}, 1_000_000 + 3 * HORA_MS)
    assert _jobs(sensor) == [("10.10.10.50", "quick")]


def test_recent_quick_scan_schedules_nothing(conn, cfg):
    cfg.scan.enabled = True
    _device(conn, "3c:22:fb:11:22:33", "10.10.10.50")
    did = store.get_device_by_ip(conn, "10.10.10.50")["id"]
    _scan(conn, did, "quick", ts=1_000_000)
    sensor = _sensor(cfg)
    sensor._schedule_scans(conn, {"10.10.10.50": "x"}, 1_000_000 + HORA_MS)
    assert _jobs(sensor) == []


def test_weekly_rescan_of_trusted_device(conn, cfg):
    cfg.scan.enabled = True
    _device(conn, "3c:22:fb:11:22:33", "10.10.10.50", confianza="confiable")
    did = store.get_device_by_ip(conn, "10.10.10.50")["id"]
    _scan(conn, did, "standard", ts=1_000_000)

    # 8 días: el standard semanal está vencido.
    sensor = _sensor(cfg)
    sensor._schedule_scans(conn, {"10.10.10.50": "x"}, 1_000_000 + 8 * DIA_MS)
    assert _jobs(sensor) == [("10.10.10.50", "standard")]


def test_weekly_rescan_not_due_yet(conn, cfg):
    cfg.scan.enabled = True
    _device(conn, "3c:22:fb:11:22:33", "10.10.10.50", confianza="confiable")
    did = store.get_device_by_ip(conn, "10.10.10.50")["id"]
    _scan(conn, did, "standard", ts=1_000_000)
    _scan(conn, did, "quick", ts=1_000_000 + 6 * DIA_MS)   # último escaneo reciente

    sensor = _sensor(cfg)
    sensor._schedule_scans(conn, {"10.10.10.50": "x"}, 1_000_000 + 6 * DIA_MS + HORA_MS)
    assert _jobs(sensor) == []


def test_untrusted_device_never_gets_weekly_standard(conn, cfg):
    cfg.scan.enabled = True
    _device(conn, "3c:22:fb:11:22:33", "10.10.10.50", confianza="desconocido")
    did = store.get_device_by_ip(conn, "10.10.10.50")["id"]
    _scan(conn, did, "standard", ts=1_000_000)

    sensor = _sensor(cfg)
    sensor._schedule_scans(conn, {"10.10.10.50": "x"}, 1_000_000 + 8 * DIA_MS)
    # Como el último escaneo tiene más de 24 h, corresponde un quick; nunca standard.
    assert _jobs(sensor) == [("10.10.10.50", "quick")]


def test_weekly_rescans_are_staggered(conn, cfg):
    cfg.scan.enabled = True
    cfg.scan.max_concurrent = 2
    ips = [f"10.10.10.{n}" for n in range(20, 26)]
    for i, ip in enumerate(ips):
        _device(conn, f"3c:22:fb:11:22:{i:02x}", ip, confianza="confiable")
        did = store.get_device_by_ip(conn, ip)["id"]
        _scan(conn, did, "standard", ts=1_000_000 - (len(ips) - i) * DIA_MS)

    sensor = _sensor(cfg)
    hosts = {ip: "x" for ip in ips}
    sensor._schedule_scans(conn, hosts, 10 * DIA_MS)
    primera = _jobs(sensor)
    assert len(primera) == 2                      # respeta max_concurrent
    assert [ip for ip, _p in primera] == ips[:2]  # los más atrasados primero

    sensor._schedule_scans(conn, hosts, 10 * DIA_MS)   # sin ráfaga: el siguiente par
    segunda = _jobs(sensor)
    assert [ip for ip, _p in segunda] == ips[2:4]


def test_sensor_ip_is_never_scanned(conn, cfg):
    cfg.scan.enabled = True
    sensor = _sensor(cfg, sensor_ip="10.10.10.50")
    _device(conn, "3c:22:fb:11:22:33", "10.10.10.50")
    sensor._schedule_scans(conn, {"10.10.10.50": "x"}, 1_000_000)
    assert _jobs(sensor) == []


def test_scan_disabled_does_nothing(conn, cfg):
    cfg.scan.enabled = False
    _device(conn, "3c:22:fb:11:22:33", "10.10.10.50")
    sensor = _sensor(cfg)
    sensor._schedule_scans(conn, {"10.10.10.50": "x"}, 1_000_000)
    assert _jobs(sensor) == []


def test_unknown_ip_is_ignored(conn, cfg):
    cfg.scan.enabled = True
    sensor = _sensor(cfg)
    sensor._schedule_scans(conn, {"10.10.10.77": "x"}, 1_000_000)
    assert _jobs(sensor) == []


def test_primer_standard_fallido_se_reintenta_como_standard(conn, cfg):
    """L-03: un equipo desconocido cuyo primer `standard` falla no se queda sin perfilar."""
    cfg.scan.enabled = True
    did = _device(conn, "3c:22:fb:11:22:33", "10.10.10.50")   # desconocido
    _scan(conn, did, "standard", ts=1_000_000, estado="error")

    # Justo después del fallo no se reintenta (mismo backoff que un confiable).
    sensor = _sensor(cfg)
    sensor._schedule_scans(conn, {"10.10.10.50": "x"}, 1_000_000 + 60_000)
    assert _jobs(sensor) == []

    # Pasada la ventana vuelve a pedir `standard`, no `quick`.
    sensor = _sensor(cfg)
    sensor._schedule_scans(conn, {"10.10.10.50": "x"}, 1_000_000 + DIA_MS + HORA_MS)
    assert _jobs(sensor) == [("10.10.10.50", "standard")]

"""Escaneo sin resultado: XML truncado o vacío es fallo del objetivo, no de nmap."""
from __future__ import annotations

import queue
import subprocess
import threading
from pathlib import Path
from typing import Any

import pytest

from batrade import store
from batrade.net import nmap_scan
from batrade.net.caps import Capabilities
from batrade.net.nmap_scan import (TARGET_UNREACHABLE, ScanResult, TargetScanError,
                                   run_scan)
from batrade.sensor import ScanJob, Sensor

HORA_MS = 3600_000

XML_OK = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap">
<host><status state="up"/>
<ports><port protocol="tcp" portid="22"><state state="open"/></port></ports>
</host></nmaprun>"""

# Lo que deja un nmap que murió a mitad: cabecera y host sin cerrar.
XML_TRUNCADO = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -Pn">
<host starttime="1" endtime="2"><status state="up"/>
<ports><port protocol="tcp" portid="22"><state state="open"/>"""


def _fake_nmap(contenido: str | None, *, crear: bool = True,
               returncode: int = 0):
    """Sustituye a nmap: escribe ``contenido`` en el XML y devuelve un proceso."""

    def fake_run(argv, **kwargs):
        ruta = Path(argv[argv.index("-oX") + 1])
        if crear and contenido is not None:
            ruta.write_text(contenido, encoding="utf-8")
        return subprocess.CompletedProcess(argv, returncode, "", "")

    return fake_run


def _imagen(cfg) -> Path:
    return cfg.paths.scans_dir


# --------------------------------------------------------------------------- #
# run_scan: clasificación y limpieza
# --------------------------------------------------------------------------- #
def test_xml_truncado_es_fallo_del_objetivo(cfg, monkeypatch):
    monkeypatch.setattr(nmap_scan.subprocess, "run", _fake_nmap(XML_TRUNCADO))

    with pytest.raises(TargetScanError) as exc:
        run_scan(cfg, "10.10.10.50", "quick", Capabilities())

    assert exc.value.motivo == "XML incompleto"
    assert exc.value.mensaje == TARGET_UNREACHABLE.format(ip="10.10.10.50")
    assert "no terminó" in exc.value.mensaje
    assert "scan.exclude" in exc.value.mensaje
    # El intento fallido no se queda en disco.
    assert list(_imagen(cfg).glob("*.xml")) == []


def test_xml_vacio_es_fallo_del_objetivo(cfg, monkeypatch):
    monkeypatch.setattr(nmap_scan.subprocess, "run", _fake_nmap(""))

    with pytest.raises(TargetScanError) as exc:
        run_scan(cfg, "10.10.10.51", "quick", Capabilities())

    assert exc.value.motivo == "XML incompleto"
    assert list(_imagen(cfg).glob("*.xml")) == []


def test_timeout_no_intenta_parsear_y_borra_el_xml(cfg, monkeypatch):
    def fake_run(argv, **kwargs):
        # Un nmap matado a mitad deja el archivo abierto y a medias.
        ruta = Path(argv[argv.index("-oX") + 1])
        ruta.write_text(XML_TRUNCADO[:80], encoding="utf-8")
        raise subprocess.TimeoutExpired(argv, kwargs.get("timeout") or 0)

    def parsear_prohibido(*_args, **_kwargs):
        raise AssertionError("no se debe parsear el XML de un nmap que expiró")

    monkeypatch.setattr(nmap_scan.subprocess, "run", fake_run)
    monkeypatch.setattr(nmap_scan, "parse_xml", parsear_prohibido)

    with pytest.raises(TargetScanError) as exc:
        run_scan(cfg, "10.10.10.52", "quick", Capabilities())

    assert exc.value.motivo == "timeout"
    assert list(_imagen(cfg).glob("*.xml")) == []


# --------------------------------------------------------------------------- #
# Sensor: ni tool_status ni eventos; sí fila `scans` en error
# --------------------------------------------------------------------------- #
def _sensor(cfg) -> Any:
    sensor: Any = object.__new__(Sensor)
    sensor.cfg = cfg
    sensor.caps = Capabilities()
    sensor.sensor_ip = "10.10.10.200"
    sensor._lock = threading.RLock()
    sensor._pending = set()
    sensor.scan_queue = queue.Queue(maxsize=64)
    return sensor


def _device(conn, ip: str = "10.10.10.50",
            mac: str = "3c:22:fb:11:22:33") -> int:
    return int(store.upsert_device(conn, mac=mac, ip=ip, ts=1_000)["device_id"])


def _eventos(conn) -> int:
    return int(conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"])


def test_fallo_del_objetivo_no_toca_el_contador_de_nmap(conn, cfg, monkeypatch):
    did = _device(conn)
    store.record_tool_status(conn, "nmap", 1_000, False, error="fallo previo")

    def falla(*_args, **_kwargs):
        raise TargetScanError("10.10.10.50", "timeout", "nmap excedió 120s")

    monkeypatch.setattr("batrade.sensor.run_scan", falla)
    sensor = _sensor(cfg)
    sensor._run_scan(conn, ScanJob(ip="10.10.10.50", profile="quick", device_id=did))

    fila = conn.execute("SELECT * FROM tool_status WHERE herramienta = 'nmap'").fetchone()
    assert fila["fallos_consecutivos"] == 1          # no sube por este fallo
    assert fila["error"] == "fallo previo"

    scan = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    assert scan["estado"] == "error"
    assert scan["error"].startswith("timeout: ")
    assert "no terminó" in scan["error"] and "scan.exclude" in scan["error"]
    assert _eventos(conn) == 0

    # El intento cuenta para el backoff del objetivo.
    assert store.get_device(conn, did)["last_scan_ts"] is not None


def test_xml_valido_tras_fallos_reinicia_contadores(conn, cfg, monkeypatch):
    did = _device(conn)
    store.record_tool_status(conn, "nmap", 1_000, False, error="timeout")
    store.record_tool_status(conn, "nmap", 2_000, False, error="timeout")
    assert conn.execute(
        "SELECT fallos_consecutivos FROM tool_status WHERE herramienta = 'nmap'"
    ).fetchone()[0] == 2

    monkeypatch.setattr(
        "batrade.sensor.run_scan",
        lambda *_a, **_k: ScanResult(target="10.10.10.50", profile="quick",
                                     ports=[], hostnames=[], xml_path=None),
    )
    sensor = _sensor(cfg)
    sensor._run_scan(conn, ScanJob(ip="10.10.10.50", profile="quick", device_id=did))

    fila = conn.execute("SELECT * FROM tool_status WHERE herramienta = 'nmap'").fetchone()
    assert fila["ok"] == 1
    assert fila["fallos_consecutivos"] == 0
    ultimo = conn.execute("SELECT estado FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    assert ultimo["estado"] == "ok"


def test_un_fallo_repetido_no_deja_xml_huerfanos(cfg, monkeypatch):
    """Tres intentos truncados seguidos: ningún archivo sobrevive."""
    monkeypatch.setattr(nmap_scan.subprocess, "run", _fake_nmap(XML_TRUNCADO))
    for _ in range(3):
        with pytest.raises(TargetScanError):
            run_scan(cfg, "10.10.10.53", "quick", Capabilities())
    assert list(_imagen(cfg).glob("*.xml")) == []


def test_health_muestra_que_paso_y_que_hacer(conn, cfg):
    """/health es donde el operador lee el motivo: frase completa, sin volcado."""
    from batrade.dashboard.app import create_app

    did = _device(conn)
    scan_id = store.start_scan(conn, did, "quick", "quick", "nmap", 1_000)
    store.finish_scan(conn, scan_id, ts=2_000, estado="error",
                      error=f"timeout: {TARGET_UNREACHABLE.format(ip='10.10.10.50')}")

    html = create_app(cfg).test_client().get("/health").data.decode()
    assert "Escaneos sin resultado" in html
    assert "no terminó (el equipo no responde o filtra paquetes)" in html
    assert "puedes excluirlo en scan.exclude" in html


# --------------------------------------------------------------------------- #
# Backoff del objetivo
# --------------------------------------------------------------------------- #
def test_standard_fallido_no_se_reintenta_en_cada_barrido(conn, cfg):
    cfg.scan.enabled = True
    did = _device(conn)
    store.set_device_state(conn, did, estado="confiable")
    scan_id = store.start_scan(conn, did, "standard", "standard", "nmap", 1_000_000)
    store.finish_scan(conn, scan_id, ts=1_000_000, estado="error",
                      error="timeout: El escaneo de 10.10.10.50 no terminó")

    sensor = _sensor(cfg)
    sensor._schedule_scans(conn, {"10.10.10.50": "3c:22:fb:11:22:33"}, 1_000_000 + 60_000)
    assert sensor.scan_queue.empty()

    # Pasada la ventana de reescaneo periódico sí vuelve a intentarlo.
    sensor = _sensor(cfg)
    sensor._schedule_scans(conn, {"10.10.10.50": "3c:22:fb:11:22:33"},
                           1_000_000 + 25 * HORA_MS)
    job = sensor.scan_queue.get_nowait()
    assert (job.ip, job.profile) == ("10.10.10.50", "standard")

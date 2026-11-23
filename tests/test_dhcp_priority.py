"""DHCP: la configuración manda sobre el aprendizaje (L-02)."""
from __future__ import annotations

import json
from typing import Any

from batrade import cli, db, store
from batrade.net.iputil import now_ms
from batrade.sensor import Sensor


def _sensor_minimo(cfg, conn) -> Any:
    sensor: Any = object.__new__(Sensor)
    sensor.cfg = cfg
    sensor.conn = conn
    return sensor


def test_la_config_gana_al_valor_aprendido(conn, cfg):
    cfg.network.dhcp_server_ip = "10.10.10.1"
    store.set_meta(conn, "dhcp_server_ip", "10.10.10.99", 1000)

    baseline = _sensor_minimo(cfg, conn)._load_baseline()

    assert baseline.dhcp_server_ip == "10.10.10.1"


def test_sin_config_se_usa_el_aprendido(conn, cfg):
    cfg.network.dhcp_server_ip = None
    store.set_meta(conn, "dhcp_server_ip", "10.10.10.99", 1000)

    baseline = _sensor_minimo(cfg, conn)._load_baseline()

    assert baseline.dhcp_server_ip == "10.10.10.99"


def test_doctor_avisa_si_el_dhcp_se_aprende(cfg, capsys):
    cfg.network.dhcp_server_ip = None
    conn = db.initialize(cfg.paths.db)
    store.heartbeat(conn, "sensor", now_ms(), json.dumps({
        "mode": "degraded", "state": "running",
        "engine": {"dhcp_server_ip": "10.10.10.3"},
    }))
    conn.close()

    cli.cmd_doctor(cfg, None)
    salida = capsys.readouterr().out
    assert "10.10.10.3" in salida
    assert "dhcp_server_ip" in salida
    assert "config.yaml" in salida


def test_doctor_no_avisa_si_esta_fijado(cfg, capsys):
    cfg.network.dhcp_server_ip = "10.10.10.1"
    conn = db.initialize(cfg.paths.db)
    store.heartbeat(conn, "sensor", now_ms(), json.dumps({
        "mode": "degraded", "state": "running",
        "engine": {"dhcp_server_ip": "10.10.10.3"},
    }))
    conn.close()

    cli.cmd_doctor(cfg, None)
    salida = capsys.readouterr().out
    assert "aprendiendo" not in salida.lower()

"""Panel: base ocupada y regresiones de las escrituras (Fase 12)."""
from __future__ import annotations

import sqlite3

import pytest

from batrade import db, store
from batrade.config import ConfigError, load_config
from batrade.dashboard.app import create_app


@pytest.fixture
def client(cfg):
    return create_app(cfg).test_client()


def _csrf(client) -> str:
    client.get("/")
    with client.session_transaction() as session:
        return session["csrf"]


def _device(cfg) -> int:
    conn = db.connect(cfg.paths.db)
    did = store.upsert_device(conn, mac="3c:22:fb:11:22:33", ip="10.10.10.50",
                              ts=1000)["device_id"]
    conn.close()
    return int(did)


# --------------------------------------------------------------------------- #
# Base ocupada
# --------------------------------------------------------------------------- #
def test_una_escritura_con_la_base_ocupada_responde_503(client, cfg, monkeypatch):
    did = _device(cfg)
    token = _csrf(client)

    def bloqueada(*_args, **_kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr("batrade.store.set_device_state", bloqueada)
    respuesta = client.post(f"/devices/{did}", data={"csrf": token, "alias": "Sala"})

    assert respuesta.status_code == 503
    cuerpo = respuesta.data.decode()
    assert "ocupada" in cuerpo.lower()
    assert "<html" in cuerpo.lower()


def test_otro_error_de_base_no_se_disfraza_de_503(client, cfg, monkeypatch):
    did = _device(cfg)
    token = _csrf(client)

    def rota(*_args, **_kwargs):
        raise sqlite3.OperationalError("no such table: devices")

    monkeypatch.setattr("batrade.store.set_device_state", rota)
    respuesta = client.post(f"/devices/{did}", data={"csrf": token, "alias": "Sala"})

    assert respuesta.status_code == 500
    assert "Error interno de la base de datos" in respuesta.data.decode()


# --------------------------------------------------------------------------- #
# Regresiones
# --------------------------------------------------------------------------- #
def test_disposicion_invalida_es_400_y_no_escribe(client, cfg):
    conn = db.connect(cfg.paths.db)
    evento = store.add_event(conn, ts=1000, tipo="device_new", severidad="warn",
                             clave_dedupe="disp-1", cooldown_s=0)
    conn.close()
    token = _csrf(client)

    respuesta = client.post(f"/events/{evento['event_id']}/disposicion",
                            data={"csrf": token, "disposicion": "lo-que-sea"})

    assert respuesta.status_code == 400
    conn = db.connect(cfg.paths.db)
    assert store.get_event(conn, evento["event_id"])["disposicion"] == "sin_evaluar"
    conn.close()


@pytest.mark.parametrize("ruta", ["/devices/{id}", "/scan", "/events/{evento}/disposicion"])
def test_las_escrituras_exigen_csrf(client, cfg, ruta):
    did = _device(cfg)
    conn = db.connect(cfg.paths.db)
    evento = store.add_event(conn, ts=1000, tipo="device_new", severidad="warn",
                             clave_dedupe="csrf-1", cooldown_s=0)
    conn.close()
    objetivo = ruta.format(id=did, evento=evento["event_id"])

    datos = {"alias": "Sala", "estado": "confiable", "objetivo": "10.10.10.50",
             "perfil": "quick", "disposicion": "fp"}
    respuesta = client.post(objetivo, data=datos)
    assert respuesta.status_code == 400

    conn = db.connect(cfg.paths.db)
    device = store.get_device(conn, did)
    assert device["alias"] is None and device["estado_confianza"] == "desconocido"
    assert conn.execute("SELECT COUNT(*) AS n FROM scan_requests").fetchone()["n"] == 0
    assert store.get_event(conn, evento["event_id"])["disposicion"] == "sin_evaluar"
    conn.close()


@pytest.mark.parametrize("objetivo", ["8.8.8.8", "-oX", "-1", "10.10.10.999",
                                      "10.10.10.0/24", ""])
def test_objetivos_de_escaneo_invalidos_se_rechazan(client, cfg, objetivo):
    token = _csrf(client)
    respuesta = client.post("/scan", data={"csrf": token, "objetivo": objetivo,
                                           "perfil": "quick"})
    assert respuesta.status_code == 302
    conn = db.connect(cfg.paths.db)
    assert conn.execute("SELECT COUNT(*) AS n FROM scan_requests").fetchone()["n"] == 0
    conn.close()


@pytest.mark.parametrize("valor", [0.1, 120, -1])
def test_timeout_s_fuera_de_rango(tmp_path, valor):
    ruta = tmp_path / "c.yaml"
    ruta.write_text(
        "network: { interface: lo, cidr: 10.10.10.0/24 }\n"
        f"notify: {{ timeout_s: {valor} }}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError) as exc:
        load_config(ruta, tmp_path)
    assert any("timeout_s" in e for e in exc.value.errors)

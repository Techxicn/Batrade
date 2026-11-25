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


# --------------------------------------------------------------------------- #
# Login CSRF y redirecciones seguras (sin open redirect)
# --------------------------------------------------------------------------- #
BAD_REDIRECTS = [
    "https://evil.example/phish",
    "http://evil.example/phish",
    "//evil.example/phish",
    "///evil.example/phish",
    "/\\evil.example",
    "\\/evil.example",
    "javascript:alert(1)",
    "devices",
    "/devices\r\nSet-Cookie: pwn=1",
]


def test_login_exige_csrf_e_incluye_el_campo_en_el_formulario(cfg):
    cfg.dashboard.auth_token = "secreto-largo-123"
    client = create_app(cfg).test_client()

    pagina = client.get("/login")
    assert pagina.status_code == 200
    assert b'name="csrf"' in pagina.data
    assert client.post("/login", data={"token": "secreto-largo-123"}).status_code == 400
    assert client.post("/login", data={"csrf": "falso",
                                       "token": "secreto-largo-123"}).status_code == 400

    with client.session_transaction() as session:
        csrf = session["csrf"]
    ok = client.post("/login", data={"csrf": csrf, "token": "secreto-largo-123"})
    assert ok.status_code == 302
    assert ok.headers["Location"] == "/"


@pytest.mark.parametrize("destino", BAD_REDIRECTS)
def test_login_rechaza_open_redirect_en_next(cfg, destino):
    cfg.dashboard.auth_token = "secreto-largo-123"
    client = create_app(cfg).test_client()
    client.get("/login")
    with client.session_transaction() as session:
        csrf = session["csrf"]

    resp = client.post(
        "/login",
        query_string={"next": destino},
        data={"csrf": csrf, "token": "secreto-largo-123"},
    )
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/"


def test_login_respeta_next_relativo_valido(cfg):
    cfg.dashboard.auth_token = "secreto-largo-123"
    client = create_app(cfg).test_client()
    client.get("/login")
    with client.session_transaction() as session:
        csrf = session["csrf"]

    resp = client.post(
        "/login",
        query_string={"next": "/events?severidad=crit"},
        data={"csrf": csrf, "token": "secreto-largo-123"},
    )
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/events?severidad=crit"


@pytest.mark.parametrize("destino", BAD_REDIRECTS)
def test_scan_rechaza_open_redirect_en_back(client, destino):
    token = _csrf(client)
    resp = client.post("/scan", data={
        "csrf": token, "objetivo": "10.10.10.50", "perfil": "quick", "back": destino,
    })
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/devices"


def test_scan_respeta_back_relativo_valido(client):
    token = _csrf(client)
    resp = client.post("/scan", data={
        "csrf": token, "objetivo": "10.10.10.50", "perfil": "quick",
        "back": "/devices/42",
    })
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/devices/42"


def test_disposicion_rechaza_referrer_externo_y_acepta_mismo_origen(client, cfg):
    conn = db.connect(cfg.paths.db)
    ev = store.add_event(conn, ts=1000, tipo="device_new", severidad="warn",
                         clave_dedupe="redir-1", cooldown_s=0)
    conn.close()
    token = _csrf(client)

    externo = client.post(
        f"/events/{ev['event_id']}/disposicion",
        data={"csrf": token, "disposicion": "fp"},
        headers={"Referer": "https://evil.example/trampa"},
    )
    assert externo.status_code == 302
    assert externo.headers["Location"] == "/events"

    local = client.post(
        f"/events/{ev['event_id']}/disposicion",
        data={"csrf": token, "disposicion": "tp"},
        headers={"Referer": "http://localhost/events?severidad=warn"},
    )
    assert local.status_code == 302
    assert local.headers["Location"] == "/events?severidad=warn"


def test_human_age_y_filtros_aceptan_epoch_cero(cfg):
    from batrade.dashboard.app import _human_age

    assert _human_age(None) == "nunca"
    assert _human_age(0) != "nunca"
    assert _human_age(0).startswith("hace ")

    app = create_app(cfg)
    assert app.jinja_env.filters["ago"](None) == "nunca"
    assert app.jinja_env.filters["ago"](0).startswith("hace ")
    assert app.jinja_env.filters["ts"](None) == "—"
    assert app.jinja_env.filters["ts"](0) != "—"


def test_devices_avisa_cuando_se_trunca_el_limite(cfg, monkeypatch):
    """M-03: si el inventario supera DEVICES_LIMIT, /devices muestra un aviso."""
    import batrade.dashboard.app as app_mod

    monkeypatch.setattr(app_mod, "DEVICES_LIMIT", 2)
    conn = db.initialize(cfg.paths.db)
    try:
        for i in range(2):
            store.upsert_device(conn, mac=f"3c:22:fb:11:22:0{i}",
                                ip=f"10.10.10.{50 + i}", ts=1000 + i)
    finally:
        conn.close()

    client = create_app(cfg).test_client()
    sin_truncar = client.get("/devices").data.decode()
    assert "Mostrando los primeros" not in sin_truncar

    conn = db.connect(cfg.paths.db)
    try:
        store.upsert_device(conn, mac="3c:22:fb:11:22:02", ip="10.10.10.52", ts=1003)
    finally:
        conn.close()

    truncado = client.get("/devices").data.decode()
    assert "Mostrando los primeros 2 dispositivos" in truncado

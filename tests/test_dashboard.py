"""Panel Flask: rutas, CSRF, autenticación y validación de objetivos."""
from __future__ import annotations

import pytest

from batrade import db, store
from batrade.dashboard.app import create_app


@pytest.fixture
def app(cfg):
    return create_app(cfg)


@pytest.fixture
def client(app):
    return app.test_client()


def _seed_device(cfg):
    conn = db.connect(cfg.paths.db)
    result = store.upsert_device(conn, mac="3c:22:fb:11:22:33", ip="10.10.10.50",
                                 ts=1000, hostname="laptop", fabricante="Apple")
    conn.close()
    return result["device_id"]


def _csrf(client):
    client.get("/")
    with client.session_transaction() as session:
        return session["csrf"]


def test_index_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Batrade" in response.data


@pytest.mark.parametrize("path", ["/devices", "/events", "/learning", "/health"])
def test_all_pages_render(client, path):
    assert client.get(path).status_code == 200


def test_device_detail_and_404(client, cfg):
    device_id = _seed_device(cfg)
    assert client.get(f"/devices/{device_id}").status_code == 200
    assert client.get("/devices/9999").status_code == 404


def test_alias_update_requires_csrf(client, cfg):
    device_id = _seed_device(cfg)
    response = client.post(f"/devices/{device_id}", data={"alias": "Sala"})
    assert response.status_code == 400


def test_alias_and_state_update(client, cfg):
    device_id = _seed_device(cfg)
    token = _csrf(client)
    response = client.post(f"/devices/{device_id}",
                           data={"csrf": token, "alias": "Smart TV Sala",
                                 "estado": "confiable"})
    assert response.status_code == 302
    conn = db.connect(cfg.paths.db)
    device = store.get_device(conn, device_id)
    conn.close()
    assert device["alias"] == "Smart TV Sala"
    assert device["estado_confianza"] == "confiable"


def test_scan_outside_cidr_is_rejected(client, cfg):
    token = _csrf(client)
    response = client.post("/scan", data={"csrf": token, "objetivo": "8.8.8.8",
                                          "perfil": "quick"})
    assert response.status_code == 302
    conn = db.connect(cfg.paths.db)
    assert conn.execute("SELECT COUNT(*) AS n FROM scan_requests").fetchone()["n"] == 0
    conn.close()


def test_scan_inside_cidr_is_queued(client, cfg):
    token = _csrf(client)
    client.post("/scan", data={"csrf": token, "objetivo": "10.10.10.50",
                               "perfil": "standard"})
    conn = db.connect(cfg.paths.db)
    row = conn.execute("SELECT * FROM scan_requests").fetchone()
    conn.close()
    assert row["objetivo"] == "10.10.10.50"
    assert row["estado"] == "pendiente"


def test_vuln_scan_requires_confirmation(client, cfg):
    token = _csrf(client)
    client.post("/scan", data={"csrf": token, "objetivo": "10.10.10.50", "perfil": "vuln"})
    conn = db.connect(cfg.paths.db)
    assert conn.execute("SELECT COUNT(*) AS n FROM scan_requests").fetchone()["n"] == 0
    conn.close()

    client.post("/scan", data={"csrf": token, "objetivo": "10.10.10.50",
                               "perfil": "vuln", "confirm": "1"})
    conn = db.connect(cfg.paths.db)
    assert conn.execute("SELECT COUNT(*) AS n FROM scan_requests").fetchone()["n"] == 1
    conn.close()


def test_event_disposition(client, cfg):
    conn = db.connect(cfg.paths.db)
    event = store.add_event(conn, ts=1000, tipo="device_new", severidad="warn",
                            clave_dedupe="d1", cooldown_s=0)
    conn.close()
    token = _csrf(client)
    client.post(f"/events/{event['event_id']}/disposicion",
                data={"csrf": token, "disposicion": "fp"})
    conn = db.connect(cfg.paths.db)
    assert store.get_event(conn, event["event_id"])["disposicion"] == "fp"
    conn.close()


def test_auth_required_when_token_configured(cfg):
    cfg.dashboard.auth_token = "s3cret"
    app = create_app(cfg)
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

    # Sin CSRF, el POST al login se rechaza (protección contra login CSRF).
    assert client.post("/login", data={"token": "s3cret"}).status_code == 400

    assert client.get("/login").status_code == 200
    with client.session_transaction() as session:
        csrf = session["csrf"]
    bad = client.post("/login", data={"csrf": csrf, "token": "malo"})
    assert bad.status_code == 200
    good = client.post("/login", data={"csrf": csrf, "token": "s3cret"})
    assert good.status_code == 302
    assert client.get("/").status_code == 200


def test_learning_approval_flow(client, cfg):
    conn = db.connect(cfg.paths.db)
    store.upsert_device(conn, mac="3c:22:fb:11:22:33", ip="10.10.10.50", ts=1000)
    conn.close()
    token = _csrf(client)
    response = client.post("/learning/approve", data={"csrf": token})
    assert response.status_code == 302
    conn = db.connect(cfg.paths.db)
    assert conn.execute(
        "SELECT COUNT(*) AS n FROM devices WHERE estado_confianza = 'confiable'"
    ).fetchone()["n"] == 1
    conn.close()

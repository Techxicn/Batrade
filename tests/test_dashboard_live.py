"""Panel en vivo: cursor de /api/live, límites, autenticación y escape."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from batrade import db, store
from batrade.config import ConfigError, load_config
from batrade.dashboard.app import LIVE_TEXT_MAX, create_app
from batrade.net.iputil import now_ms

MIN_YAML = """
network: {{ interface: lo, cidr: "10.10.10.0/24", gateway_ip: 10.10.10.1 }}
sensor: {{ mode: degraded }}
scan: {{ enabled: false }}
dashboard: {{ host: "127.0.0.1"{extra} }}
paths: {{ db: var/test.db, scans_dir: var/scans, log_dir: var/log }}
"""


def _config(tmp_path, extra: str = ""):
    path = tmp_path / "live.yaml"
    path.write_text(MIN_YAML.format(extra=extra), encoding="utf-8")
    return load_config(path, tmp_path)


@pytest.fixture
def app(cfg):
    return create_app(cfg)


@pytest.fixture
def client(app):
    return app.test_client()


def _evento(conn, *, ts=1000, severidad="warn", clave=None, tipo="arp_sweep",
            detalle=None, **extra):
    return store.add_event(
        conn, ts=ts, tipo=tipo, severidad=severidad,
        clave_dedupe=clave or f"clave-{ts}-{severidad}", detalle=detalle, **extra
    )


# --------------------------------------------------------------------------- #
# Autenticación
# --------------------------------------------------------------------------- #
def test_api_live_exige_sesion_y_no_filtra_datos(cfg):
    conn = db.initialize(cfg.paths.db)
    _evento(conn, ts=now_ms(), severidad="crit", detalle={"resumen": "secreto"})
    conn.close()

    cfg.dashboard.auth_token = "s3cret"
    client = create_app(cfg).test_client()

    respuesta = client.get("/api/live")
    assert respuesta.status_code == 401
    assert respuesta.mimetype == "application/json"
    assert b"secreto" not in respuesta.data
    assert b"resumen" not in respuesta.data

    # La ruta sigue redirigiendo al login en las páginas HTML.
    pagina = client.get("/")
    assert pagina.status_code == 302
    assert "/login" in pagina.headers["Location"]

    # El login no arranca el sondeo: sin sesión sólo habría 401 en bucle.
    acceso = client.get("/login").data.decode()
    assert "live.js" not in acceso
    assert "data-live-url" not in acceso

    assert client.post("/login", data={"token": "s3cret"}).status_code == 302
    assert client.get("/api/live").status_code == 200


def test_api_live_es_solo_lectura(client):
    # El POST choca antes con el guardia CSRF, así que se manda el token para
    # comprobar que la ruta en sí no admite escrituras.
    client.get("/")
    with client.session_transaction() as session:
        token = session["csrf"]
    assert client.post("/api/live", data={"csrf": token}).status_code == 405
    assert client.put("/api/live").status_code == 405


# --------------------------------------------------------------------------- #
# Cursor y forma de la respuesta
# --------------------------------------------------------------------------- #
def test_sin_after_no_devuelve_eventos(client, cfg):
    conn = db.connect(cfg.paths.db)
    primero = _evento(conn, ts=now_ms() - 2000, severidad="warn")
    segundo = _evento(conn, ts=now_ms(), severidad="crit")
    conn.close()

    datos = client.get("/api/live").get_json()
    assert datos["max_id"] == segundo["event_id"]
    assert "eventos" not in datos
    assert "resumen" in datos and "sensor" in datos
    assert datos["resumen"]["alertas_hoy"]["total"] >= 1
    assert set(datos["sensor"]) == {"vivo", "edad_s"}
    assert datos["max_id"] > primero["event_id"]


def test_after_devuelve_solo_lo_posterior_en_orden_ascendente(client, cfg):
    conn = db.connect(cfg.paths.db)
    primero = _evento(conn, ts=1000, severidad="warn")
    segundo = _evento(conn, ts=2000, severidad="warn")
    tercero = _evento(conn, ts=3000, severidad="crit")
    conn.close()

    datos = client.get(f"/api/live?after={primero['event_id']}").get_json()
    assert [e["id"] for e in datos["eventos"]] == [segundo["event_id"], tercero["event_id"]]
    assert datos["max_id"] == tercero["event_id"]

    # Un cursor por delante no inventa eventos, pero tampoco retrocede.
    vacio = client.get(f"/api/live?after={tercero['event_id']}").get_json()
    assert vacio["eventos"] == []
    assert vacio["max_id"] == tercero["event_id"]


@pytest.mark.parametrize("valor", ["x", "", "-1", "1.5"])
def test_after_invalido_devuelve_400(client, valor):
    respuesta = client.get(f"/api/live?after={valor}")
    assert respuesta.status_code == 400
    assert respuesta.mimetype == "application/json"
    assert "error" in respuesta.get_json()


def test_solo_se_entregan_warn_y_crit(client, cfg):
    conn = db.connect(cfg.paths.db)
    info = _evento(conn, ts=1000, severidad="info", clave="info")
    warn = _evento(conn, ts=2000, severidad="warn", clave="warn")
    crit = _evento(conn, ts=3000, severidad="crit", clave="crit")
    conn.close()

    datos = client.get("/api/live?after=0").get_json()
    assert [e["id"] for e in datos["eventos"]] == [warn["event_id"], crit["event_id"]]
    assert info["event_id"] not in [e["id"] for e in datos["eventos"]]


def test_limite_de_50_por_respuesta(client, conn):
    ids = [_evento(conn, ts=1000 + i, clave=f"e-{i}")["event_id"] for i in range(60)]
    conn.commit()

    primera = client.get("/api/live?after=0").get_json()
    assert len(primera["eventos"]) == 50
    assert [e["id"] for e in primera["eventos"]] == ids[:50]
    # El cursor no salta a max_id si la respuesta vino llena.
    assert primera["eventos"][-1]["id"] < primera["max_id"]

    resto = client.get(f"/api/live?after={ids[49]}").get_json()
    assert [e["id"] for e in resto["eventos"]] == ids[50:]

    # El tope también se aplica en el repositorio.
    assert len(store.events_since(conn, 0, limit=500)) == 50


def test_repeticion_deduplicada_no_vuelve_a_salir(client, conn):
    primero = _evento(conn, ts=1000, severidad="warn", clave="misma")
    repetido = _evento(conn, ts=1500, severidad="warn", clave="misma")
    assert repetido["is_new"] is False

    datos = client.get("/api/live?after=0").get_json()
    assert [e["id"] for e in datos["eventos"]] == [primero["event_id"]]
    assert store.get_event(conn, primero["event_id"])["repeat_count"] == 2


def test_escalada_warn_a_crit_llega_con_id_nuevo(client, conn):
    warn = _evento(conn, ts=1000, severidad="warn", clave="escala")
    crit = _evento(conn, ts=1200, severidad="crit", clave="escala")
    assert crit["is_new"] is True
    assert crit["event_id"] != warn["event_id"]

    datos = client.get(f"/api/live?after={warn['event_id']}").get_json()
    assert [e["id"] for e in datos["eventos"]] == [crit["event_id"]]
    assert datos["eventos"][0]["severidad"] == "crit"


# --------------------------------------------------------------------------- #
# Contenido de cada evento
# --------------------------------------------------------------------------- #
def test_campos_del_evento_y_detalle_json(client, conn):
    _evento(conn, ts=5000, severidad="crit", clave="detalle",
            tipo="arp_spoof_gateway",
            ip_origen="10.10.10.66", mac_origen="aa:bb:cc:00:11:22",
            ip_destino="10.10.10.1",
            detalle={"resumen": "Cambió la MAC de la puerta de enlace",
                     "por_que": "Puede haber interceptación",
                     "accion": "Revisar el router",
                     "ip_destino": "10.10.10.254",
                     "mac_destino": "00:50:56:aa:bb:01"})

    evento = client.get("/api/live?after=0").get_json()["eventos"][0]
    assert evento["severidad"] == "crit"
    assert evento["tipo"] == "arp_spoof_gateway"
    assert evento["ts"] == 5000
    assert evento["resumen"] == "Cambió la MAC de la puerta de enlace"
    assert evento["por_que"] == "Puede haber interceptación"
    assert evento["accion"] == "Revisar el router"
    assert evento["ip_origen"] == "10.10.10.66"
    assert evento["mac_origen"] == "aa:bb:cc:00:11:22"
    # detalle_json manda sobre la columna cuando trae el par completo.
    assert evento["ip_destino"] == "10.10.10.254"
    assert evento["mac_destino"] == "00:50:56:aa:bb:01"


def test_texto_recortado_y_sin_controles(client, conn):
    largo = "x" * (LIVE_TEXT_MAX + 40)
    _evento(conn, ts=6000, severidad="warn", clave="largo",
            detalle={"resumen": "uno\x00dos\x07 tres\ncuatro " + largo})

    evento = client.get("/api/live?after=0").get_json()["eventos"][0]
    assert "\x00" not in evento["resumen"] and "\x07" not in evento["resumen"]
    assert "\n" not in evento["resumen"]
    assert evento["resumen"].startswith("unodos tres cuatro")
    assert len(evento["resumen"]) == LIVE_TEXT_MAX
    assert evento["resumen"].endswith("…")


def test_contadores_del_resumen(client, cfg):
    conn = db.connect(cfg.paths.db)
    ahora = now_ms()
    uno = store.upsert_device(conn, mac="3c:22:fb:11:22:33", ip="10.10.10.50", ts=ahora)
    store.upsert_device(conn, mac="aa:bb:cc:00:11:22", ip="10.10.10.66", ts=ahora)
    store.set_device_state(conn, uno["device_id"], estado="no_autorizado")
    store.register_miss(conn, uno["device_id"], ahora + 1000, threshold=1)
    _evento(conn, ts=ahora, severidad="warn", clave="c-warn")
    _evento(conn, ts=ahora, severidad="crit", clave="c-crit")
    conn.close()

    resumen = client.get("/api/live").get_json()["resumen"]
    assert resumen["dispositivos"] == 2
    assert resumen["en_linea"] == 1
    assert resumen["no_autorizados"] == 1
    assert resumen["desconocidos"] == 1
    assert resumen["alertas_hoy"]["warn"] == 1
    assert resumen["alertas_hoy"]["crit"] == 1
    assert resumen["alertas_hoy"]["total"] >= 2


# --------------------------------------------------------------------------- #
# Escape: datos de red hostiles nunca se interpretan como HTML
# --------------------------------------------------------------------------- #
HOSTIL = "<script>alert('xss')</script>"


def test_json_escapa_y_conserva_el_texto_hostil(client, conn):
    _evento(conn, ts=7000, severidad="crit", clave="hostil",
            tipo="device_new", detalle={"resumen": HOSTIL,
                                        "por_que": "<img src=x onerror=alert(1)>"})
    respuesta = client.get("/api/live?after=0")
    assert respuesta.mimetype == "application/json"
    # El cuerpo no lleva HTML utilizable aunque algo lo sirviera como tal.
    assert b"<script" not in respuesta.data
    assert b"\\u003cscript" in respuesta.data
    # Y al deserializar el texto llega íntegro: el cliente lo pinta con textContent.
    evento = json.loads(respuesta.data)["eventos"][0]
    assert evento["resumen"] == HOSTIL
    assert evento["por_que"] == "<img src=x onerror=alert(1)>"


def test_plantilla_escapa_el_hostname_hostil(client, cfg):
    conn = db.connect(cfg.paths.db)
    store.upsert_device(conn, mac="aa:bb:cc:00:11:22", ip="10.10.10.66", ts=1000,
                        hostname=HOSTIL, fabricante="Desconocido")
    conn.close()

    cuerpo = client.get("/devices").data.decode()
    assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;" in cuerpo
    assert HOSTIL not in cuerpo


def test_plantillas_exponen_ganchos_del_panel_en_vivo(cfg):
    cfg.dashboard.live_poll_s = 7
    client = create_app(cfg).test_client()

    panel = client.get("/").data.decode()
    assert 'data-live-poll="7"' in panel
    assert 'data-live-url="/api/live"' in panel
    assert 'data-events-url="/events"' in panel
    assert 'id="live-alerts"' in panel
    assert 'aria-live="assertive"' in panel
    assert 'id="live-toggle"' in panel
    assert 'id="live-offline"' in panel
    assert 'data-live="en-linea"' in panel
    assert 'src="/static/live.js"' in panel

    alertas = client.get("/events").data.decode()
    assert 'id="events-tbody"' in alertas
    assert 'data-sev=""' in alertas
    assert 'data-tipo=""' in alertas
    assert 'data-csrf="' in alertas
    # La tabla existe aunque no haya eventos: el panel inserta filas en ella.
    assert 'id="events-table"' in alertas

    filtrada = client.get("/events?severidad=crit&tipo=arp_sweep").data.decode()
    assert 'data-sev="crit"' in filtrada
    assert 'data-tipo="arp_sweep"' in filtrada


def _live_js() -> str:
    raiz = Path(__file__).resolve().parents[1]
    return (raiz / "batrade" / "dashboard" / "static" / "live.js").read_text(encoding="utf-8")


def test_live_js_usa_textcontent_y_no_innerhtml(cfg):
    fuente = _live_js()
    assert ".innerHTML" not in fuente
    assert "insertAdjacentHTML" not in fuente
    assert "textContent" in fuente
    # Sin dependencias: nada de cargar scripts de terceros.
    assert "http://" not in fuente and "https://" not in fuente
    assert "import " not in fuente


def test_sonido_crit_no_espera_la_ventana_de_warn(cfg):
    """Regla de tiempos: el warn espera 5 s; el crit sólo el mínimo de 1 s.

    La comprobación fina (warn + crit a los 3 s, dos warn seguidos) se hizo en el
    navegador; aquí queda la guarda de los umbrales y de su uso.
    """
    fuente = _live_js()
    assert "SONIDO_MIN_MS = 1000" in fuente
    assert "SONIDO_WARN_MS = 5000" in fuente
    assert 'severidad === "crit" ? SONIDO_MIN_MS : SONIDO_WARN_MS' in fuente
    assert "esperaSonido(severidad)" in fuente


def test_sondeo_aborta_a_los_10s(cfg):
    """Gancho del tope: AbortController, 10 s y el reloj siempre cancelado."""
    fuente = _live_js()
    assert "TIEMPO_MAX_MS = 10000" in fuente
    assert "new window.AbortController()" in fuente
    assert "opciones.signal = control.signal" in fuente
    assert "control.abort()" in fuente
    # El temporizador del tope no puede sobrevivir a la respuesta.
    assert fuente.count("clearTimeout(reloj)") >= 3


# --------------------------------------------------------------------------- #
# Configuración de la cadencia
# --------------------------------------------------------------------------- #
def test_live_poll_s_por_defecto_y_personalizado(tmp_path):
    assert _config(tmp_path).dashboard.live_poll_s == 3
    assert _config(tmp_path, ", live_poll_s: 1").dashboard.live_poll_s == 1
    assert _config(tmp_path, ", live_poll_s: 60").dashboard.live_poll_s == 60


@pytest.mark.parametrize("valor", [0, 61, -3])
def test_live_poll_s_fuera_de_rango(tmp_path, valor):
    with pytest.raises(ConfigError) as exc:
        _config(tmp_path, f", live_poll_s: {valor}")
    assert any("live_poll_s" in error for error in exc.value.errors)

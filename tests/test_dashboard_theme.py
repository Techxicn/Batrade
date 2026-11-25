"""Tema «Fósforo» del panel: barra de severidad, recursos locales y empaquetado."""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

from batrade import db, store
from batrade.dashboard.app import create_app
from batrade.net.iputil import now_ms

RAIZ = Path(__file__).resolve().parent.parent
STATIC = RAIZ / "batrade" / "dashboard" / "static"
FUENTE = STATIC / "fonts" / "jetbrains-mono-latin-wght.woff2"
LICENCIA_FUENTE = STATIC / "fonts" / "OFL-JetBrainsMono.txt"


@pytest.fixture
def client(cfg):
    return create_app(cfg).test_client()


def _evento(conn, severidad: str, n: int) -> None:
    ahora = now_ms()
    for i in range(n):
        store.add_event(conn, ts=ahora, tipo="arp_sweep", severidad=severidad,
                        clave_dedupe=f"tema-{severidad}-{i}")


def _tramo(html: str, clave: str) -> str:
    """Etiqueta completa del tramo ``data-live-seg=<clave>`` de la barra."""
    match = re.search(r'<span class="sevbar-seg[^"]*" data-live-seg="%s"[^>]*>' % clave, html)
    assert match, f"falta el tramo {clave}"
    return match.group(0)


# --------------------------------------------------------------------------- #
# Barra de severidad de hoy
# --------------------------------------------------------------------------- #
def test_barra_de_severidad_proporcional_y_con_plurales(client, cfg):
    conn = db.connect(cfg.paths.db)
    _evento(conn, "crit", 2)
    _evento(conn, "warn", 1)
    conn.close()

    panel = client.get("/").data.decode()

    assert 'data-live="alertas-total">3</strong>' in panel
    assert "flex-grow: 2" in _tramo(panel, "crit")
    assert "hidden" not in _tramo(panel, "crit")
    assert "flex-grow: 1" in _tramo(panel, "warn")
    # Un recuento a 0 no ocupa sitio en la barra y la pista vacía no aparece.
    assert "hidden" in _tramo(panel, "info")
    assert "hidden" in _tramo(panel, "vacio")
    # Singular y plural correctos en la leyenda y en la etiqueta accesible.
    assert 'data-live="alertas-crit-label">críticas</span>' in panel
    assert 'data-live="alertas-warn-label">advertencia</span>' in panel
    assert 'aria-label="2 críticas, 1 advertencia, 0 informativas"' in panel


def test_barra_vacia_sin_eventos(client):
    panel = client.get("/").data.decode()
    assert 'data-live="alertas-total">0</strong>' in panel
    for clave in ("crit", "warn", "info"):
        assert "hidden" in _tramo(panel, clave)
    assert "hidden" not in _tramo(panel, "vacio")
    assert 'data-live="fp-sub">falsos positivos</span>' in panel


def test_cabecera_muestra_red_e_interfaz(client, cfg):
    panel = client.get("/").data.decode()
    assert f"red=<b>{cfg.network.cidr}</b>" in panel
    assert f"iface=<b>{cfg.network.interface}</b>" in panel
    assert 'data-live="actualizado"' in panel


def test_live_js_refresca_la_barra(cfg):
    fuente = (STATIC / "live.js").read_text(encoding="utf-8")
    assert "data-live-seg" in fuente
    assert "alertas-barra" in fuente
    assert "tramo.style.flexGrow" in fuente
    assert 'setAttribute("aria-label"' in fuente
    # El tema no reintroduce HTML dinámico.
    assert ".innerHTML" not in fuente


# --------------------------------------------------------------------------- #
# Recursos locales: el panel funciona sin internet
# --------------------------------------------------------------------------- #
def test_css_sin_recursos_externos():
    css = (STATIC / "style.css").read_text(encoding="utf-8")
    assert "http://" not in css and "https://" not in css
    assert "@import" not in css
    urls = re.findall(r'url\("([^"]+)"\)', css)
    assert urls, "el @font-face debe apuntar a la fuente local"
    for url in urls:
        assert (STATIC / url).is_file(), f"recurso inexistente: {url}"


def test_fuente_es_woff2_y_lleva_licencia():
    assert FUENTE.read_bytes()[:4] == b"wOF2"
    licencia = LICENCIA_FUENTE.read_text(encoding="utf-8")
    assert "SIL Open Font License" in licencia
    assert "JetBrains Mono" in licencia


def test_fuente_se_empaqueta():
    with (RAIZ / "pyproject.toml").open("rb") as fh:
        datos = tomllib.load(fh)["tool"]["setuptools"]["package-data"]["batrade"]
    assert "dashboard/static/fonts/*.woff2" in datos
    assert "dashboard/static/fonts/*.txt" in datos


def test_fuente_se_sirve_sin_sesion(cfg):
    """Los estáticos no exigen token: el login también usa la fuente."""
    cfg.dashboard.auth_token = "s3cret"
    client = create_app(cfg).test_client()
    assert client.get("/").status_code == 302
    respuesta = client.get("/static/fonts/jetbrains-mono-latin-wght.woff2")
    assert respuesta.status_code == 200
    assert respuesta.data[:4] == b"wOF2"

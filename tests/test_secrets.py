"""Secretos y entorno: ni tokens en errores, ni entorno heredado (S-01, S-02, S-05)."""
from __future__ import annotations

import io
import subprocess
import urllib.error
from pathlib import Path
from typing import Any

import pytest

from batrade import store
from batrade.logging_setup import setup_logging
from batrade.net import nmap_scan
from batrade.net.caps import Capabilities
from batrade.net.proc import env_minimo
from batrade.notify import NotificationError, send_discord, send_telegram
from batrade.sensor import Sensor

TOKEN = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"
WEBHOOK = "https://discord.com/api/webhooks/123456789/abcdefTOKENdePrueba"


def _http_error(url: str, code: int, body: str) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url, code, "Error", hdrs=None, fp=io.BytesIO(body.encode("utf-8"))
    )


def test_telegram_no_arrastra_el_cuerpo_de_la_respuesta(monkeypatch):
    def falla(req, timeout=None):
        raise _http_error(req.full_url, 500, f"Bad Request token {TOKEN}")

    monkeypatch.setattr("batrade.notify.urllib.request.urlopen", falla)
    with pytest.raises(NotificationError) as exc:
        send_telegram({"type": "telegram"}, "hola", 1.0,
                      {"TELEGRAM_TOKEN": TOKEN, "TELEGRAM_CHAT_ID": "1"})
    mensaje = str(exc.value)
    assert "HTTP 500" in mensaje
    assert "Bad Request" not in mensaje          # no se copia el cuerpo HTTP
    assert TOKEN not in mensaje


def test_discord_no_arrastra_el_cuerpo_de_la_respuesta(monkeypatch):
    def falla(req, timeout=None):
        raise _http_error(req.full_url, 404, f"Unknown Webhook {WEBHOOK}")

    monkeypatch.setattr("batrade.notify.urllib.request.urlopen", falla)
    with pytest.raises(NotificationError) as exc:
        send_discord({"type": "discord"}, "{}", 1.0, {"DISCORD_WEBHOOK": WEBHOOK})
    assert "Unknown Webhook" not in str(exc.value)
    assert "abcdefTOKENdePrueba" not in str(exc.value)


def test_discord_rechaza_esquemas_no_http():
    with pytest.raises(NotificationError) as exc:
        send_discord({"type": "discord"}, "{}", 1.0,
                     {"DISCORD_WEBHOOK": "file:///etc/passwd"})
    assert "http(s)" in str(exc.value)


def test_excepcion_de_requests_con_url_secreta_se_sanea(monkeypatch):
    def explota(*_a, **_k):
        raise urllib.error.URLError(
            f"HTTPSConnectionPool(host='api.telegram.org'): "
            f"url: https://api.telegram.org/bot{TOKEN}/sendMessage")

    monkeypatch.setattr("batrade.notify.urllib.request.urlopen", explota)
    with pytest.raises(NotificationError) as exc:
        send_telegram({"type": "telegram"}, "hola", 1.0,
                      {"TELEGRAM_TOKEN": TOKEN, "TELEGRAM_CHAT_ID": "1"})
    assert TOKEN not in str(exc.value)
    assert "sendMessage" not in str(exc.value)


def test_excepcion_de_discord_se_sanea(monkeypatch):
    def explota(*_a, **_k):
        raise urllib.error.URLError(f"failed for url: {WEBHOOK}")

    monkeypatch.setattr("batrade.notify.urllib.request.urlopen", explota)
    with pytest.raises(NotificationError) as exc:
        send_discord({"type": "discord"}, "{}", 1.0, {"DISCORD_WEBHOOK": WEBHOOK})
    assert "abcdefTOKENdePrueba" not in str(exc.value)


def test_la_cola_guarda_el_error_redactado(monkeypatch, cfg):
    from batrade.notify import Notifier

    monkeypatch.setattr(
        "batrade.notify.urllib.request.urlopen",
        lambda *a, **k: (_ for _ in ()).throw(
            urllib.error.URLError(f"url: https://discord.com/api/webhooks/1/{TOKEN}")),
    )
    cfg.notify.channels = [{"type": "discord"}]
    from batrade import db

    con = db.initialize(cfg.paths.db)
    ev = store.add_event(con, ts=1_000, tipo="device_new", severidad="warn",
                         clave_dedupe="s1")
    store.enqueue_notification(con, ev["event_id"], "discord", 1_000)
    notifier = Notifier(cfg, lambda: db.connect(cfg.paths.db),
                        env={"DISCORD_WEBHOOK": WEBHOOK})
    notifier.process_once()
    fila = con.execute(
        "SELECT last_error FROM notification_queue ORDER BY id DESC LIMIT 1").fetchone()
    assert fila["last_error"]
    assert TOKEN not in fila["last_error"]
    assert "webhooks/1/" not in fila["last_error"]
    con.close()


# --------------------------------------------------------------------------- #
# Entorno de los subprocesos
# --------------------------------------------------------------------------- #
def test_entorno_minimo_no_hereda_secretos(monkeypatch):
    monkeypatch.setenv("TELEGRAM_TOKEN", TOKEN)
    monkeypatch.setenv("HOME", "/home/alguien")
    entorno = env_minimo()
    assert entorno["LC_ALL"] == "C"
    assert "PATH" in entorno
    assert "TELEGRAM_TOKEN" not in entorno
    assert "HOME" not in entorno


def test_nmap_recibe_entorno_minimo(cfg, monkeypatch):
    monkeypatch.setenv("TELEGRAM_TOKEN", TOKEN)
    capturado: dict[str, Any] = {}

    def fake_run(argv, **kwargs):
        capturado.update(kwargs)
        ruta = Path(argv[argv.index("-oX") + 1])
        ruta.write_text(
            '<?xml version="1.0"?><nmaprun><host><ports/></host></nmaprun>',
            encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(nmap_scan.subprocess, "run", fake_run)
    nmap_scan.run_scan(cfg, "10.10.10.50", "quick", Capabilities())

    entorno = capturado.get("env")
    assert entorno is not None, "nmap se ejecuta con el entorno del sensor"
    assert "TELEGRAM_TOKEN" not in entorno
    assert entorno["LC_ALL"] == "C"


def test_sensor_env_solo_variables_de_canal(monkeypatch, cfg):
    monkeypatch.setenv("TELEGRAM_TOKEN", TOKEN)
    monkeypatch.setenv("HOME", "/home/alguien")
    sensor: Any = object.__new__(Sensor)
    sensor.cfg = cfg                       # por defecto sólo canal local

    assert sensor._env() == {}

    cfg.notify.channels = [{"type": "telegram"}]
    entorno = sensor._env()
    assert entorno.get("TELEGRAM_TOKEN") == TOKEN
    assert "HOME" not in entorno


# --------------------------------------------------------------------------- #
# Filtro de logging
# --------------------------------------------------------------------------- #
def test_el_log_redacta_tokens_y_webhooks(monkeypatch, tmp_path):
    monkeypatch.setenv("TELEGRAM_TOKEN", TOKEN)
    logger = setup_logging(tmp_path, component="prueba-redaccion", console=False)
    logger.info("fallo con token %s", TOKEN)
    logger.info("webhook %s", WEBHOOK,
                extra={"fields": {"error": f"url {WEBHOOK}", "token": TOKEN}})

    texto = (tmp_path / "prueba-redaccion.log").read_text(encoding="utf-8")
    assert TOKEN not in texto
    assert "abcdefTOKENdePrueba" not in texto
    assert "<redactado>" in texto


def test_el_log_y_redactar_tapan_dashboard_token(monkeypatch, tmp_path):
    from batrade.redact import redactar, secretos_conocidos

    dash_token = "dash_secreto_de_prueba_64chars_0123456789abcdef"
    monkeypatch.setenv("DASHBOARD_TOKEN", dash_token)

    assert dash_token in secretos_conocidos()
    assert dash_token not in redactar(f"fallo con token {dash_token}")

    logger = setup_logging(tmp_path, component="prueba-redaccion-dash", console=False)
    logger.warning("acceso rechazado para %s", dash_token,
                   extra={"fields": {"token": dash_token}})

    texto = (tmp_path / "prueba-redaccion-dash.log").read_text(encoding="utf-8")
    assert dash_token not in texto
    assert "<redactado>" in texto

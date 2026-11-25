"""Notificaciones con cola persistente, dedupe y backoff (RF-15, RF-16).

Canales: local (siempre disponible, sirve de auditoría), Telegram y Discord.
Un fallo de red nunca pierde la alerta: queda en notification_queue hasta
agotar los intentos, y el evento sigue visible en el dashboard.
"""
from __future__ import annotations

import html
import json
import logging
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
import urllib.error
import urllib.request

from batrade import __version__, store
from batrade.config import Config
from batrade.net.iputil import now_ms
from batrade.redact import redactar, secretos_conocidos

log = logging.getLogger("batrade.notify")

SEVERITY_LABEL = {"info": "INFO", "warn": "ADVERTENCIA", "crit": "CRITICO"}
SEVERITY_ICON = {"info": "[i]", "warn": "[!]", "crit": "[!!]"}


def _ts_str(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000).strftime("%Y-%m-%d %H:%M:%S")


def event_detail(row: Any) -> dict[str, Any]:
    try:
        data = json.loads(row["detalle_json"] or "{}")
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, TypeError, IndexError):
        return {}


def format_text(row: Any) -> str:
    """Mensaje plano con lo que el PRD exige: qué pasó, por qué y qué hacer."""
    sev = str(row["severidad"])
    det = event_detail(row)
    lines = [
        f"{SEVERITY_ICON.get(sev, '[?]')} Batrade · {SEVERITY_LABEL.get(sev, sev)}",
        f"Evento: {row['tipo']}",
        f"Cuándo: {_ts_str(int(row['last_ts']))}",
    ]
    if row["ip_origen"] or row["mac_origen"]:
        lines.append(f"Origen: {row['ip_origen'] or '-'} / {row['mac_origen'] or '-'}")
    if row["ip_destino"]:
        lines.append(f"Destino: {row['ip_destino']}")
    if det.get("resumen"):
        lines.append(f"Qué pasó: {det['resumen']}")
    if det.get("por_que"):
        lines.append(f"Por qué importa: {det['por_que']}")
    if det.get("accion"):
        lines.append(f"Qué hacer: {det['accion']}")
    repeat = int(row["repeat_count"] or 1)
    if repeat > 1:
        lines.append(f"Repeticiones acumuladas: {repeat}")
    return "\n".join(lines)


def format_telegram(row: Any) -> str:
    """HTML de Telegram con todo el texto de red escapado (RNF-05)."""
    sev = str(row["severidad"])
    det = event_detail(row)
    e = html.escape
    parts = [
        f"<b>{e(SEVERITY_ICON.get(sev, '[?]'))} Batrade · "
        f"{e(SEVERITY_LABEL.get(sev, sev))}</b>",
        f"<b>Evento:</b> {e(str(row['tipo']))}",
        f"<b>Cuándo:</b> {e(_ts_str(int(row['last_ts'])))}",
    ]
    if row["ip_origen"] or row["mac_origen"]:
        parts.append(f"<b>Origen:</b> {e(str(row['ip_origen'] or '-'))} / "
                     f"{e(str(row['mac_origen'] or '-'))}")
    if row["ip_destino"]:
        parts.append(f"<b>Destino:</b> {e(str(row['ip_destino']))}")
    for key, label in (("resumen", "Qué pasó"), ("por_que", "Por qué importa"),
                       ("accion", "Qué hacer")):
        if det.get(key):
            parts.append(f"<b>{label}:</b> {e(str(det[key]))}")
    repeat = int(row["repeat_count"] or 1)
    if repeat > 1:
        parts.append(f"<i>Repeticiones: {repeat}</i>")
    return "\n".join(parts)


def format_discord(row: Any) -> dict[str, Any]:
    text = format_text(row)
    color = {"crit": 0xD93025, "warn": 0xE8A317, "info": 0x1A73E8}.get(
        str(row["severidad"]), 0x777777
    )
    return {
        "embeds": [{
            "title": f"Batrade · {SEVERITY_LABEL.get(str(row['severidad']), row['severidad'])}",
            "description": text[:3900],
            "color": color,
        }]
    }


# --------------------------------------------------------------------------- #
# Envío
# --------------------------------------------------------------------------- #
class NotificationError(RuntimeError):
    pass


def _post_json(url: str, payload: dict[str, Any], timeout: float,
               channel_label: str, env: dict[str, str]) -> None:
    """Envía JSON por HTTP(S) usando sólo la librería estándar (sin ``requests``)."""
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": f"Batrade/{__version__}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None)
            if status is None:
                status = resp.getcode()
            status = 200 if status is None else int(status)
    except urllib.error.HTTPError as exc:
        # Sólo el código: el cuerpo de la respuesta no aporta y puede traer datos.
        raise NotificationError(f"{channel_label} HTTP {exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        # La excepción puede arrastrar la URL con el token/webhook: se sanea al origen.
        raise NotificationError(redactar(str(exc), secretos_conocidos(env))) from None
    if status >= 300:
        raise NotificationError(f"{channel_label} HTTP {status}")


def send_telegram(channel: dict[str, Any], text: str, timeout: float,
                  env: dict[str, str]) -> None:
    token = env.get(channel.get("token_env", "TELEGRAM_TOKEN"), "")
    chat_id = env.get(channel.get("chat_id_env", "TELEGRAM_CHAT_ID"), "")
    if not token or not chat_id:
        raise NotificationError("Telegram sin TELEGRAM_TOKEN/TELEGRAM_CHAT_ID configurados")
    _post_json(
        f"https://api.telegram.org/bot{token}/sendMessage",
        {"chat_id": chat_id, "text": text, "parse_mode": "HTML",
         "disable_web_page_preview": True},
        timeout,
        "Telegram",
        env,
    )


def send_discord(channel: dict[str, Any], payload_text: str, timeout: float,
                 env: dict[str, str]) -> None:
    url = env.get(channel.get("webhook_env", "DISCORD_WEBHOOK"), "")
    if not url:
        raise NotificationError("Discord sin DISCORD_WEBHOOK configurado")
    if not url.startswith(("https://", "http://")):
        raise NotificationError("Discord DISCORD_WEBHOOK debe ser una URL http(s)")
    _post_json(url, json.loads(payload_text), timeout, "Discord", env)


class LocalSink:
    """Escribe a archivo con permisos 600 y rotación por tamaño.

    Sin rotación, `var/alerts.log` crecía hasta llenar el disco y un `OSError`
    al escribir se llevaba por delante al notificador.
    """

    def __init__(self, path: Path, max_mb: int = 10, backups: int = 3):
        self.path = Path(path)
        self.max_bytes = max(1, int(max_mb)) * 1024 * 1024
        self.backups = max(0, int(backups))

    def write(self, text: str) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._rotar_si_toca()
            nuevo = not self.path.exists()
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(f"----- {datetime.now().isoformat(timespec='seconds')} -----\n")
                fh.write(redactar(text) + "\n")
            if nuevo:
                self.path.chmod(0o600)
        except OSError as exc:
            # Un disco lleno no puede tumbar la cola de notificaciones.
            log.warning("no se pudo escribir %s: %s", self.path.name, exc)

    def _rotar_si_toca(self) -> None:
        if not self.path.exists() or self.path.stat().st_size < self.max_bytes:
            return
        if self.backups <= 0:
            self.path.unlink(missing_ok=True)
            return
        for i in range(self.backups - 1, 0, -1):
            origen = self.path.with_name(f"{self.path.name}.{i}")
            if origen.exists():
                origen.replace(self.path.with_name(f"{self.path.name}.{i + 1}"))
        self.path.replace(self.path.with_name(f"{self.path.name}.1"))
        for i in range(1, self.backups + 1):
            copia = self.path.with_name(f"{self.path.name}.{i}")
            if copia.exists():
                try:
                    copia.chmod(0o600)
                except OSError:
                    pass


def backoff_seconds(attempts: int) -> int:
    """Backoff exponencial acotado: 5, 10, 20, 40, 80, 160, 300..."""
    return min(5 * (2 ** max(0, min(attempts, 6))), 300)


# --------------------------------------------------------------------------- #
# Trabajador
# --------------------------------------------------------------------------- #
class Notifier:
    def __init__(self, cfg: Config, conn_factory: Callable[[], sqlite3.Connection],
                 env: dict[str, str] | None = None,
                 sender: Callable[[dict, Any, float], None] | None = None):
        self.cfg = cfg
        self.conn_factory = conn_factory
        self.env = env or {}
        self.sender = sender
        self.sink = LocalSink(cfg.paths.alerts_log, cfg.notify.local_max_mb,
                              cfg.notify.local_backups)
        self.stop_event = threading.Event()
        self.sent = 0
        self.failed = 0

    def channels(self) -> list[dict[str, Any]]:
        return [c for c in self.cfg.notify.channels if isinstance(c, dict)]

    def enqueue(self, conn: sqlite3.Connection, event_id: int, ts: int) -> int:
        count = 0
        for ch in self.channels():
            if store.enqueue_notification(conn, event_id, str(ch.get("type")), ts):
                count += 1
        return count

    def run(self) -> None:
        log.info("notificador iniciado con %d canal(es)", len(self.channels()))
        while not self.stop_event.wait(1.0):
            try:
                self.process_once()
            except Exception:
                log.exception("error en el bucle del notificador")

    def process_once(self) -> int:
        """Procesa las notificaciones vencidas. Devuelve cuántas se enviaron."""
        ts = now_ms()
        conn = self.conn_factory()
        try:
            rows = store.due_notifications(conn, ts)
            done = 0
            for row in rows:
                if self._process_row(conn, row, ts):
                    done += 1
            return done
        finally:
            conn.close()

    def _process_row(self, conn: sqlite3.Connection, row: Any, ts: int) -> bool:
        channel_type = str(row["canal"])
        channel = next((c for c in self.channels() if str(c.get("type")) == channel_type), None)
        if channel is None:
            store.notification_failed(conn, int(row["id"]), "canal no configurado", None, True)
            return False
        try:
            self._deliver(channel, row)
        except Exception as exc:
            attempts = int(row["intentos"])
            agotado = attempts + 1 >= self.cfg.notify.max_attempts
            delay = backoff_seconds(attempts) * 1000
            # Nunca se guarda ni se registra el texto crudo: puede traer la URL
            # del webhook o el token del bot.
            error = redactar(str(exc), secretos_conocidos(self.env))
            store.notification_failed(conn, int(row["id"]), error,
                                      None if agotado else ts + delay, agotado)
            self.failed += 1
            log.warning("notificación fallida", extra={"fields": {
                "canal": channel_type, "evento": row["event_id"], "intento": attempts + 1,
                "error": error[:200]}})
            return False
        store.notification_sent(conn, int(row["id"]), int(row["event_id"]), ts)
        self.sent += 1
        return True

    def _deliver(self, channel: dict[str, Any], row: Any) -> None:
        ctype = str(channel.get("type"))
        if ctype == "local":
            self.sink.write(format_text(row))
            return
        if self.sender is not None:
            self.sender(channel, row, self.cfg.notify.timeout_s)
            return
        if ctype == "telegram":
            send_telegram(channel, format_telegram(row), self.cfg.notify.timeout_s, self.env)
            return
        if ctype == "discord":
            send_discord(channel, json.dumps(format_discord(row)),
                         self.cfg.notify.timeout_s, self.env)
            return
        raise NotificationError(f"canal desconocido: {ctype}")

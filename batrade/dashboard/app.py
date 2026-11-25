"""Panel web de solo lectura mayoritaria sobre SQLite (RF-17).

Escrituras permitidas, deliberadamente acotadas (decisión C1 del análisis):
  - devices.alias / devices.estado_confianza
  - scan_requests (botón de escaneo manual)
  - events.disposicion (marcar falso positivo, para el KPI)
El sensor es el único que escribe eventos, puertos y cola de notificación.

Rutas JSON: hay **una sola**, ``GET /api/live``, y es de sólo lectura. El panel
la sondea desde ``static/live.js`` para refrescar contadores, tabla de alertas y
latido sin recargar. Cualquier otra ruta sigue devolviendo HTML.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
import sqlite3
from datetime import datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   request, session, url_for)

from batrade import db, store
from batrade.inventory import approve_baseline, review_candidates
from batrade.inventory import status as baseline_status
from batrade.net import caps as caps_mod
from batrade.net.iputil import ip_excluded, ip_in_cidr, now_ms, valid_ipv4
from batrade.net.nmap_scan import udp_risky_ports

if TYPE_CHECKING:  # sólo para anotaciones: `from __future__ import annotations`
    from batrade.config import Config

TRUST_LABEL = {"confiable": "Confiable", "desconocido": "Desconocido",
               "no_autorizado": "No autorizado"}
log = logging.getLogger("batrade.dashboard")
SEV_LABEL = {"info": "Informativo", "warn": "Advertencia", "crit": "Crítico"}
SEV_ICON = {"info": "·", "warn": "!", "crit": "!!"}


def _human_age(ms: int | None) -> str:
    if ms is None:
        return "nunca"
    delta = max(0, now_ms() - int(ms))
    sec = delta // 1000
    if sec < 60:
        return f"hace {sec} s"
    if sec < 3600:
        return f"hace {sec // 60} min"
    if sec < 86400:
        return f"hace {sec // 3600} h"
    return f"hace {sec // 86400} d"


def verification_label(raw) -> dict | None:
    """Etiqueta del estado de verificación ARP de un evento.

    ``detalle_json.verificacion`` puede ser un texto (formato histórico, cuando
    la sonda confirmó o descartó) o un bloque ``{"estado", "motivo"}`` con
    ``no_verificable`` / ``sin_respuesta``. Devuelve ``None`` si el evento no
    tiene verificación asociada, para no inventar un estado.
    """
    try:
        detalle = json.loads(raw or "{}")
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(detalle, dict):
        return None
    info = detalle.get("verificacion")
    if isinstance(info, dict):
        estado = str(info.get("estado") or "")
        motivo = str(info.get("motivo") or "")
        if estado == "no_verificable":
            return {"clase": "", "texto": "no verificable", "motivo": motivo}
        if estado == "sin_respuesta":
            return {"clase": "warn", "texto": "sin respuesta", "motivo": motivo}
        if estado:
            return {"clase": "ok", "texto": estado, "motivo": motivo}
    # El texto plano es el formato histórico de "confirmó/descartó": la
    # etiqueta "verificado" la sigue dando la columna `verified`.
    return None


# --------------------------------------------------------------------------- #
# Panel en vivo: serialización de la única ruta JSON (GET /api/live)
# --------------------------------------------------------------------------- #
LIVE_TEXT_MAX = 300
DEVICES_LIMIT = 500
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _start_of_today_ms() -> int:
    """Medianoche local en ms epoch: el mismo corte de "hoy" que usa el panel."""
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    return int(today.timestamp() * 1000)


def _event_detail(raw) -> dict:
    try:
        data = json.loads(raw or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _clean_text(value: Any, limit: int = LIVE_TEXT_MAX) -> str | None:
    """Texto de red saneado para JSON: sin controles, en una línea y recortado.

    No escapa HTML a propósito: la respuesta va como ``application/json`` y el
    cliente pinta con ``textContent``. El serializador añade además el escape
    ``\\u003c`` / ``\\u003e`` / ``\\u0026`` como segunda barrera.
    """
    if value is None:
        return None
    text = _CONTROL_CHARS.sub("", str(value).replace("\r", " ").replace("\n", " "))
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text or None


def _live_event(row: sqlite3.Row) -> dict[str, Any]:
    """Evento warn/crit con el texto ya saneado para el sondeo del panel.

    ``detalle_json`` manda sobre las columnas: un evento que trae su par
    origen/destino completo no pierde información, y si no lo trae se usan las
    columnas del propio evento.
    """
    det = _event_detail(row["detalle_json"])
    return {
        "id": int(row["id"]),
        "severidad": str(row["severidad"]),
        "tipo": _clean_text(row["tipo"]) or "",
        "ts": int(row["last_ts"]),
        "resumen": _clean_text(det.get("resumen")),
        "por_que": _clean_text(det.get("por_que")),
        "accion": _clean_text(det.get("accion")),
        "ip_origen": _clean_text(det.get("ip_origen") or row["ip_origen"]),
        "mac_origen": _clean_text(det.get("mac_origen") or row["mac_origen"]),
        "ip_destino": _clean_text(det.get("ip_destino") or row["ip_destino"]),
        "mac_destino": _clean_text(det.get("mac_destino")),
    }


def _safe_redirect(target: str | None, fallback: str, *,
                   allow_same_origin: bool = False) -> str:
    """Valida que una redirección permanezca dentro del propio panel.

    Rechaza esquemas externos, URLs de protocolo relativo (``//host``), barras
    invertidas (``/\\host``) y caracteres de control. Con
    ``allow_same_origin=True`` (p. ej. ``Referer``) admite una URL absoluta del
    mismo ``request.host`` y devuelve sólo su ruta y query relativos.
    """
    if not target:
        return fallback
    raw = str(target).strip()
    if (not raw or "\\" in raw or raw.startswith("//")
            or any(ord(c) < 0x20 or ord(c) == 0x7F for c in raw)):
        return fallback
    parts = urlsplit(raw)
    if parts.scheme or parts.netloc:
        if not (allow_same_origin and parts.scheme in ("http", "https")
                and parts.netloc == request.host):
            return fallback
        path = parts.path or "/"
        if not path.startswith("/") or path.startswith("//"):
            return fallback
        return f"{path}?{parts.query}" if parts.query else path
    if not parts.path.startswith("/") or parts.path.startswith("//"):
        return fallback
    return f"{parts.path}?{parts.query}" if parts.query else parts.path


def _json_response(payload: dict[str, Any], status: int = 200) -> Response:
    """JSON sin caché y con ``<``/``>``/``&`` escapados (defensa en profundidad)."""
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    body = (body.replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("&", "\\u0026"))
    resp = Response(body, status=status, mimetype="application/json")
    resp.headers["Cache-Control"] = "no-store"
    return resp


def create_app(cfg: Config) -> Flask:
    cfg.ensure_dirs()
    db.initialize(cfg.paths.db)
    caps = caps_mod.probe()
    mode, mode_notes = caps_mod.resolve_mode(cfg.sensor.mode, caps)
    _udp_ports, udp_note = udp_risky_ports(cfg, caps)

    app = Flask(__name__)
    secret = (hashlib.sha256(cfg.dashboard.auth_token.encode()).hexdigest()
              if cfg.dashboard.auth_token else secrets.token_hex(16))
    app.config.update(
        SECRET_KEY=secret,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_HTTPONLY=True,
        JSON_SORT_KEYS=False,
    )
    app.config["KG_CFG"] = cfg
    app.config["KG_CAPS"] = caps
    app.config["KG_MODE"] = mode

    # ------------------------------------------------------------- conexión
    def get_db() -> sqlite3.Connection:
        if "conn" not in g:
            g.conn = db.connect(cfg.paths.db)
        return g.conn

    app.get_db = get_db  # type: ignore[attr-defined]

    @app.teardown_appcontext
    def _close(_exc):  # noqa: ANN001
        conn = g.pop("conn", None)
        if conn is not None:
            conn.close()

    def _health(conn: sqlite3.Connection) -> dict:
        hb = store.get_heartbeat(conn, "sensor")
        age = now_ms() - int(hb["ts"]) if hb else None
        stale_after = cfg.sensor.heartbeat_interval * 3000
        detail: dict = {}
        if hb is not None and hb["detalle"]:
            try:
                detail = json.loads(hb["detalle"])
            except json.JSONDecodeError:
                detail = {}
        return {
            "age": age,
            "stale": age is None or age > stale_after,
            "detail": detail,
            "mode": detail.get("mode") or mode,
            "state": detail.get("state") or ("unknown" if hb is None else "running"),
            "caps": detail.get("caps") or caps.summary(),
        }

    # --------------------------------------------------------------- sesión
    @app.before_request
    def _guard():  # noqa: ANN202
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(18)
        endpoint = request.endpoint or ""
        if endpoint == "static":
            return None
        if endpoint != "login" and cfg.dashboard.auth_token and not session.get("auth"):
            if endpoint == "api_live":
                # Un GET de datos no puede acabar en el HTML del login: 401 JSON.
                return _json_response({"error": "sesión requerida"}, 401)
            return redirect(url_for("login", next=request.path))
        if request.method == "POST":
            sent = request.form.get("csrf") or request.headers.get("X-CSRF", "")
            if not sent or not hmac.compare_digest(sent, session.get("csrf", "")):
                abort(400, "Token CSRF inválido o ausente")
        return None

    # ------------------------------------------------------------ contexto
    @app.context_processor
    def _inject():  # noqa: ANN202
        conn = get_db()
        health = _health(conn)
        return {
            "cfg": cfg,
            "csrf": session.get("csrf", ""),
            "health": health,
            "mode": health["mode"],
            "learning": baseline_status(conn)["learning"],
            "trust_label": TRUST_LABEL,
            "sev_label": SEV_LABEL,
        }

    @app.template_filter("ts")
    def _fmt_ts(ms):  # noqa: ANN001
        if ms is None or ms == "":
            return "—"
        return datetime.fromtimestamp(int(ms) / 1000).strftime("%d/%m/%Y %H:%M:%S")

    @app.template_filter("ago")
    def _fmt_ago(ms):  # noqa: ANN001
        return _human_age(None if ms is None or ms == "" else int(ms))

    @app.template_filter("mac")
    def _fmt_mac(mac):  # noqa: ANN001
        return mac or "—"

    @app.template_filter("json_pretty")
    def _json_pretty(raw):  # noqa: ANN001
        try:
            return json.dumps(json.loads(raw or "{}"), indent=2, ensure_ascii=False)
        except (json.JSONDecodeError, TypeError):
            return str(raw or "")

    @app.template_filter("verif")
    def _fmt_verif(raw):  # noqa: ANN001
        return verification_label(raw)

    # ------------------------------------------------------------- autenticación
    @app.route("/login", methods=["GET", "POST"])
    def login():  # noqa: ANN202
        if not cfg.dashboard.auth_token:
            return redirect(url_for("index"))
        if request.method == "POST":
            token = request.form.get("token", "")
            if hmac.compare_digest(token, cfg.dashboard.auth_token):
                session["auth"] = True
                return redirect(_safe_redirect(request.args.get("next"), url_for("index")))
            flash("Token incorrecto", "error")
        return render_template("login.html")

    # ------------------------------------------------------------------ panel
    @app.route("/")
    def index():  # noqa: ANN202
        conn = get_db()
        counts = store.count_devices(conn)
        since = _start_of_today_ms()
        sev = store.event_counts(conn, since)
        recent = store.list_events(conn, limit=8)
        base = baseline_status(conn)
        total_today = sum(sev.values())
        fp_today = store.false_positives_since(conn, since)
        return render_template(
            "index.html", counts=counts, sev=sev, recent=recent, base=base,
            total_today=total_today, fp_today=int(fp_today),
            health=_health(conn), caps=caps.summary(), mode_notes=mode_notes,
        )

    # ------------------------------------------------------------ dispositivos
    @app.route("/devices")
    def devices():  # noqa: ANN202
        conn = get_db()
        estado = request.args.get("estado") or None
        search = request.args.get("q") or None
        only_online = request.args.get("online") == "1"
        limite = max(1, int(DEVICES_LIMIT))
        rows = store.list_devices(conn, estado=estado, search=search,
                                  only_online=only_online, limit=limite + 1)
        truncated = len(rows) > limite
        if truncated:
            rows = rows[:limite]
        counts = store.count_devices(conn)
        return render_template("devices.html", devices=rows, counts=counts,
                               truncated=truncated, limit=limite,
                               filtro={"estado": estado or "", "q": search or "",
                                       "online": only_online})

    @app.route("/devices/<int:device_id>")
    def device_detail(device_id: int):  # noqa: ANN202
        conn = get_db()
        device = store.get_device(conn, device_id)
        if device is None:
            abort(404)
        assert device is not None  # abort no retorna; ayuda al type checker
        gateway_ip = baseline_status(conn)["gateway_ip"] or cfg.network.gateway_ip
        return render_template(
            "device.html", device=device, ports=store.list_ports(conn, device_id),
            history=store.list_history(conn, device_id),
            events=store.events_for_device(conn, device_id),
            is_gateway=(device["ip_actual"] == gateway_ip),
            scans=store.list_scans_for_device(conn, device_id, limit=10),
            profiles=("quick", "standard", "vuln"),
        )

    @app.route("/devices/<int:device_id>", methods=["POST"])
    def device_update(device_id: int):  # noqa: ANN202
        conn = get_db()
        device = store.get_device(conn, device_id)
        if device is None:
            abort(404)
        estado = request.form.get("estado") or None
        alias = request.form.get("alias")
        try:
            changed = store.set_device_state(
                conn, device_id, estado=estado if estado in TRUST_LABEL else None,
                alias=alias if alias is not None else None)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("device_detail", device_id=device_id))
        flash("Cambios guardados" if changed else "Sin cambios", "ok")
        return redirect(url_for("device_detail", device_id=device_id))

    # ----------------------------------------------------------------- alertas
    @app.route("/events")
    def events():  # noqa: ANN202
        conn = get_db()
        severidad = request.args.get("severidad") or None
        tipo = request.args.get("tipo") or None
        rows = store.list_events(conn, severidad=severidad, tipo=tipo, limit=300)
        tipos = store.list_event_types(conn)
        return render_template("events.html", events=rows, tipos=tipos,
                               filtro={"severidad": severidad or "", "tipo": tipo or ""})

    @app.route("/events/<int:event_id>/disposicion", methods=["POST"])
    def event_disposition(event_id: int):  # noqa: ANN202
        conn = get_db()
        value = request.form.get("disposicion", "sin_evaluar")
        try:
            store.set_disposition(conn, event_id, value)
        except ValueError:
            # Entrada inválida: 400 y nada escrito (antes se aceptaba en silencio).
            abort(400, description="Disposición inválida")
        flash("Disposición registrada (alimenta el KPI de falsos positivos)", "ok")
        return redirect(_safe_redirect(request.referrer, url_for("events"),
                                       allow_same_origin=True))

    # ---------------------------------------------------- panel en vivo (JSON)
    @app.route("/api/live")
    def api_live() -> Response:
        """Única ruta JSON del panel; sólo lectura (GET).

        ``?after=<id>`` entrega los eventos warn/crit posteriores al cursor, en
        orden ascendente y con tope de 50. Sin ``after`` sólo se devuelven el
        cursor inicial (``max_id``), el resumen y el latido: abrir o recargar el
        panel no dispara una avalancha de avisos. Las repeticiones deduplicadas
        no crean filas nuevas y por tanto no se repiten; una escalada warn→crit
        sí llega con su id nuevo.

        ``max_id`` se lee **antes** que los eventos para que el cursor del
        cliente nunca pueda saltarse una fila insertada mientras se responde.
        """
        conn = get_db()
        payload: dict[str, Any] = {"max_id": store.max_event_id(conn)}
        raw_after = request.args.get("after")
        if raw_after is not None:
            try:
                after = int(raw_after)
            except (TypeError, ValueError):
                return _json_response({"error": "after debe ser un entero"}, 400)
            if after < 0:
                return _json_response({"error": "after no puede ser negativo"}, 400)
            payload["eventos"] = [
                _live_event(row)
                for row in store.events_since(conn, after, limit=store.LIVE_MAX_EVENTS)
            ]
        payload["resumen"] = store.live_summary(conn, _start_of_today_ms())
        health = _health(conn)
        payload["sensor"] = {
            "vivo": not health["stale"],
            "edad_s": (None if health["age"] is None
                       else max(0, int(health["age"] // 1000))),
        }
        return _json_response(payload)

    # ------------------------------------------------------------- línea base
    @app.route("/learning")
    def learning():  # noqa: ANN202
        conn = get_db()
        return render_template("learning.html", base=baseline_status(conn),
                               pending=review_candidates(conn),
                               all_devices=store.list_devices(conn, limit=200))

    @app.route("/learning/approve", methods=["POST"])
    def learning_approve():  # noqa: ANN202
        conn = get_db()
        include = request.form.get("include_random") == "1"
        result = approve_baseline(conn, include_random_mac=include)
        flash(f"Línea base aprobada: {result['aprobados']} confiables, "
              f"{result['pendientes']} en revisión", "ok")
        return redirect(url_for("learning"))

    # ---------------------------------------------------------------- escaneo
    @app.route("/scan", methods=["POST"])
    def scan_request():  # noqa: ANN202
        conn = get_db()
        objetivo = valid_ipv4(request.form.get("objetivo"))
        perfil = request.form.get("perfil", "quick")
        back = _safe_redirect(request.form.get("back"), url_for("devices"))
        if not objetivo or not ip_in_cidr(objetivo, cfg.network.cidr):
            flash(f"Objetivo inválido o fuera de {cfg.network.cidr}", "error")
            return redirect(back)
        if ip_excluded(objetivo, cfg.scan.exclude):
            flash(f"{objetivo} está excluido en scan.exclude", "warn")
            return redirect(back)
        if perfil not in ("quick", "standard", "vuln"):
            flash("Perfil inválido", "error")
            return redirect(back)
        if perfil == "vuln" and request.form.get("confirm") != "1":
            flash("El escaneo de vulnerabilidades es intrusivo: hay que confirmarlo", "error")
            return redirect(back)
        req_id = store.create_scan_request(conn, objetivo, perfil, "dashboard", now_ms())
        if req_id is None:
            flash("Ya hay un escaneo pendiente para ese objetivo y perfil", "warn")
        else:
            flash(f"Escaneo {perfil} solicitado para {objetivo}", "ok")
        return redirect(back)

    # ------------------------------------------------------------------ salud
    @app.route("/health")
    def health_page():  # noqa: ANN202
        conn = get_db()
        health = _health(conn)
        try:
            size = cfg.paths.db.stat().st_size
        except OSError:
            size = 0
        tools = store.tool_status(conn)
        hb = store.get_heartbeat(conn, "sensor")
        return render_template("health.html", health=health, caps=caps,
                               caps_summary=caps.summary(), mode_notes=mode_notes,
                               udp_note=udp_note,
                               tools=tools, heartbeat=hb, db_size=size,
                               failed_scans=store.recent_failed_scans(conn),
                               requests=store.list_scan_requests(conn, limit=20),
                               effective_mode=mode)

    @app.errorhandler(404)
    def _404(_exc):  # noqa: ANN202
        return render_template("error.html", code=404,
                               message="Ese recurso no existe"), 404

    @app.errorhandler(sqlite3.OperationalError)
    def _db_error(exc):  # noqa: ANN202
        texto = str(exc).lower()
        if "locked" in texto or "busy" in texto:
            return render_template(
                "error.html", code=503,
                message=("La base de datos está ocupada (el sensor está escribiendo). "
                         "Espera unos segundos y vuelve a intentarlo."),
            ), 503
        # Cualquier otro error de SQLite es un fallo real: no se disfraza de 503.
        log.exception("error de base de datos en el panel: %s", exc)
        return render_template("error.html", code=500,
                               message="Error interno de la base de datos"), 500

    @app.errorhandler(400)
    def _400(exc):  # noqa: ANN202
        return render_template("error.html", code=400,
                               message=getattr(exc, "description", "Petición inválida")), 400

    return app

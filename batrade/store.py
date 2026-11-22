"""Repositorio: todo el acceso a datos, con consultas parametrizadas (RNF-05)."""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Iterable, Sequence

from batrade.config import RiskyPort
from batrade.db import get_meta, set_meta  # noqa: F401 - reexport usado por inventario/sensor

TRUST = ("confiable", "desconocido", "no_autorizado")
SEVERITY_ORDER = {"info": 0, "warn": 1, "crit": 2}
NOTIFY_SEVERITIES = ("warn", "crit")

# Tope de eventos por respuesta de GET /api/live: el panel sondea con un cursor
# y una sola respuesta no debe arrastrar el historial.
LIVE_MAX_EVENTS = 50

GENERIC_HOSTNAMES = {"", "localhost", "android", "unknown", "?", "-", "none"}


def rowdict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


# --------------------------------------------------------------------------- #
# Identidades y dispositivos
# --------------------------------------------------------------------------- #
def get_device_by_mac(conn: sqlite3.Connection, mac: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()


def get_device(conn: sqlite3.Connection, device_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()


def get_device_by_ip(conn: sqlite3.Connection, ip: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM devices WHERE ip_actual = ? ORDER BY last_seen DESC LIMIT 1", (ip,)
    ).fetchone()


def identity_for(conn: sqlite3.Connection, kind: str, key: str, ts: int) -> tuple[int, bool]:
    """Devuelve (identity_id, creada). Agrupa MACs aleatorias por hostname (RF-06)."""
    row = conn.execute("SELECT id FROM identities WHERE key = ?", (f"{kind}:{key}",)).fetchone()
    if row:
        conn.execute("UPDATE identities SET last_seen = ? WHERE id = ?", (ts, row["id"]))
        return int(row["id"]), False
    cur = conn.execute(
        "INSERT INTO identities(key, kind, first_seen, last_seen) VALUES(?,?,?,?)",
        (f"{kind}:{key}", kind, ts, ts),
    )
    return int(cur.lastrowid), True


def upsert_device(
    conn: sqlite3.Connection,
    *,
    mac: str,
    ip: str | None,
    ts: int,
    hostname: str | None = None,
    fabricante: str | None = None,
    mac_aleatoria: bool | None = None,
) -> dict[str, Any]:
    """Crea o actualiza un equipo. Devuelve el estado de la transición.

    Claves del resultado: device_id, created, identity_created, ip_changed,
    prev_ip, came_online, en_linea.
    """
    existing = get_device_by_mac(conn, mac)
    if existing is None:
        kind, key = _identity_key(mac, hostname, mac_aleatoria)
        identity_id, identity_created = identity_for(conn, kind, key, ts)
        cur = conn.execute(
            "INSERT INTO devices(mac, identity_id, ip_actual, fabricante, hostname, "
            "mac_aleatoria, first_seen, last_seen, en_linea, misses, estado_confianza) "
            "VALUES(?,?,?,?,?,?,?,?,1,0,'desconocido')",
            (mac, identity_id, ip, fabricante, hostname, int(bool(mac_aleatoria)), ts, ts),
        )
        device_id = int(cur.lastrowid)
        add_history(conn, device_id, ts, "conexion", ip=ip, detalle="primer avistamiento")
        return {
            "device_id": device_id,
            "created": True,
            "identity_created": identity_created,
            "ip_changed": False,
            "prev_ip": None,
            "came_online": True,
            "en_linea": 1,
            "estado_confianza": "desconocido",
        }

    prev_ip = existing["ip_actual"]
    ip_changed = bool(ip and prev_ip and ip != prev_ip)
    came_online = not bool(existing["en_linea"])
    conn.execute(
        "UPDATE devices SET ip_actual = COALESCE(?, ip_actual), last_seen = ?, en_linea = 1, "
        "misses = 0, hostname = COALESCE(?, hostname), fabricante = COALESCE(?, fabricante), "
        "mac_aleatoria = COALESCE(?, mac_aleatoria) WHERE id = ?",
        (ip, ts, hostname, fabricante,
         None if mac_aleatoria is None else int(bool(mac_aleatoria)), existing["id"]),
    )
    if ip_changed:
        add_history(conn, int(existing["id"]), ts, "cambio_ip", ip=ip,
                    detalle=f"{prev_ip} -> {ip}")
    if came_online:
        add_history(conn, int(existing["id"]), ts, "conexion", ip=ip, detalle="reconexion")
    return {
        "device_id": int(existing["id"]),
        "created": False,
        "identity_created": False,
        "ip_changed": ip_changed,
        "prev_ip": prev_ip,
        "came_online": came_online,
        "en_linea": 1,
        "estado_confianza": existing["estado_confianza"],
    }


def _identity_key(mac: str, hostname: str | None, mac_aleatoria: bool | None) -> tuple[str, str]:
    """Solo agrupa por hostname cuando la MAC es local y el hostname es útil (C4)."""
    host = (hostname or "").strip().lower()
    if mac_aleatoria and host not in GENERIC_HOSTNAMES and len(host) > 2:
        return "hostname", host
    return "mac", mac


def register_miss(conn: sqlite3.Connection, device_id: int, ts: int,
                  threshold: int) -> dict[str, Any] | None:
    """Suma un barrido sin respuesta; marca fuera de línea al alcanzar el umbral."""
    row = get_device(conn, device_id)
    if row is None or not row["en_linea"]:
        return None
    misses = int(row["misses"]) + 1
    conn.execute("UPDATE devices SET misses = ? WHERE id = ?", (misses, device_id))
    if misses >= threshold:
        conn.execute("UPDATE devices SET en_linea = 0 WHERE id = ?", (device_id,))
        add_history(conn, device_id, ts, "desconexion", ip=row["ip_actual"],
                    detalle=f"{misses} barridos sin respuesta")
        return {"device_id": device_id, "en_linea": 0, "misses": misses}
    return None


def set_device_state(conn: sqlite3.Connection, device_id: int, *,
                     estado: str | None = None, alias: str | None = None) -> bool:
    sets, params = [], []
    if estado is not None:
        if estado not in TRUST:
            raise ValueError(f"estado de confianza inválido: {estado}")
        sets.append("estado_confianza = ?")
        params.append(estado)
    if alias is not None:
        sets.append("alias = ?")
        params.append(alias.strip()[:64] or None)
    if not sets:
        return False
    params.append(device_id)
    cur = conn.execute(f"UPDATE devices SET {', '.join(sets)} WHERE id = ?", params)
    return cur.rowcount > 0


def list_devices(conn: sqlite3.Connection, *, estado: str | None = None,
                 search: str | None = None, only_online: bool = False,
                 limit: int = 500) -> list[sqlite3.Row]:
    where, params = [], []
    if estado:
        where.append("estado_confianza = ?")
        params.append(estado)
    if only_online:
        where.append("en_linea = 1")
    if search:
        like = f"%{search.lower()}%"
        where.append("(lower(COALESCE(alias,'')) LIKE ? OR lower(COALESCE(hostname,'')) LIKE ? "
                     "OR COALESCE(ip_actual,'') LIKE ? OR mac LIKE ?)")
        params.extend([like, like, like, like])
    sql = "SELECT * FROM devices"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY en_linea DESC, last_seen DESC LIMIT ?"
    params.append(limit)
    return list(conn.execute(sql, params))


def count_devices(conn: sqlite3.Connection) -> dict[str, int]:
    row = conn.execute(
        "SELECT COUNT(*) AS total, "
        "COALESCE(SUM(en_linea),0) AS online, "
        "COALESCE(SUM(CASE WHEN estado_confianza='desconocido' THEN 1 ELSE 0 END),0) AS desconocidos, "
        "COALESCE(SUM(CASE WHEN estado_confianza='no_autorizado' THEN 1 ELSE 0 END),0) AS no_autorizados, "
        "COALESCE(SUM(CASE WHEN estado_confianza='confiable' THEN 1 ELSE 0 END),0) AS confiables, "
        "COALESCE(SUM(mac_aleatoria),0) AS mac_aleatoria "
        "FROM devices"
    ).fetchone()
    return dict(row) if row else {}


# --------------------------------------------------------------------------- #
# Historial y puertos
# --------------------------------------------------------------------------- #
def add_history(conn: sqlite3.Connection, device_id: int, ts: int, evento: str,
                ip: str | None = None, detalle: str | None = None) -> None:
    conn.execute(
        "INSERT INTO device_history(device_id, ts, ip, evento, detalle) VALUES(?,?,?,?,?)",
        (device_id, ts, ip, evento, detalle),
    )


def list_history(conn: sqlite3.Connection, device_id: int, limit: int = 50) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT * FROM device_history WHERE device_id = ? ORDER BY ts DESC LIMIT ?",
        (device_id, limit),
    ))


def list_ports(conn: sqlite3.Connection, device_id: int) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT * FROM ports WHERE device_id = ? ORDER BY riesgoso DESC, puerto ASC",
        (device_id,),
    ))


def known_ports(conn: sqlite3.Connection, device_id: int) -> dict[tuple[str, int], sqlite3.Row]:
    rows = conn.execute("SELECT * FROM ports WHERE device_id = ?", (device_id,)).fetchall()
    return {(str(r["protocolo"]), int(r["puerto"])): r for r in rows}


def apply_scan_ports(conn: sqlite3.Connection, device_id: int, found: Iterable[dict[str, Any]],
                     ts: int, risky: dict[tuple[str, int], RiskyPort],
                     protocolos: Iterable[str] | None = None,
                     perfil: str | None = None) -> dict[str, list]:
    """Inserta/actualiza puertos y clasifica lo observado frente al catálogo.

    ``protocolos`` limita qué protocolos se consideran explorados: un puerto
    conocido de un protocolo que no se escaneó (p. ej. UDP en modo degradado)
    no puede marcarse como cerrado.

    ``perfil`` limita qué perfil puede cerrar puertos. ``quick`` usa ``-F``
    (≈100 puertos TCP), así que su silencio sobre el resto no es evidencia de
    cierre: sólo ``standard`` y ``vuln`` cierran. Sin perfil se mantiene el
    comportamiento histórico (lo usan llamadores internos y tests de diff).
    """
    before = known_ports(conn, device_id)
    explorados = {str(p).lower() for p in protocolos} if protocolos is not None else None
    cierra = perfil is None or perfil in ("standard", "vuln")
    seen_keys: set[tuple[str, int]] = set()
    new_risky: list[dict[str, Any]] = []
    new_ports: list[dict[str, Any]] = []
    disappeared: list[dict[str, Any]] = []

    for p in found:
        proto = str(p.get("protocol", "tcp")).lower()
        port = int(p["port"])
        key = (proto, port)
        seen_keys.add(key)
        risk = risky.get(key)
        servicio = p.get("service") or (risk.service if risk else None)
        version = p.get("version")
        prev = before.get(key)
        conn.execute(
            "INSERT INTO ports(device_id, protocolo, puerto, estado, servicio, version, "
            "riesgoso, first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(device_id, protocolo, puerto) DO UPDATE SET "
            "estado = excluded.estado, servicio = COALESCE(excluded.servicio, ports.servicio), "
            "version = COALESCE(excluded.version, ports.version), "
            "riesgoso = excluded.riesgoso, last_seen = excluded.last_seen",
            (device_id, proto, port, p.get("state", "open"), servicio, version,
             int(bool(risk)), ts, ts),
        )
        info = {"protocol": proto, "port": port, "service": servicio, "version": version,
                "reason": risk.reason if risk else None}
        # Un puerto que estaba cerrado y vuelve a estar abierto es una señal
        # real (servicio reactivado), igual que uno que nunca se había visto.
        reabierto = prev is not None and str(prev["estado"]) != "open"
        if risk and (prev is None or not prev["riesgoso"] or reabierto):
            new_risky.append(info)
        elif prev is None or reabierto:
            new_ports.append(info)

    # Cerrar un puerto es una afirmación ("ya no está"); sólo la hacen los
    # perfiles que cubren el rango completo.
    for key, row in (before.items() if cierra else ()):
        if explorados is not None and key[0] not in explorados:
            continue
        if key not in seen_keys and row["estado"] == "open":
            conn.execute(
                "UPDATE ports SET estado = 'closed', last_seen = ? "
                "WHERE device_id = ? AND protocolo = ? AND puerto = ?",
                (ts, device_id, key[0], key[1]),
            )
            disappeared.append({"protocol": key[0], "port": key[1],
                                "service": row["servicio"]})
    return {"new_risky": new_risky, "new_ports": new_ports, "disappeared": disappeared}


# --------------------------------------------------------------------------- #
# Escaneos
# --------------------------------------------------------------------------- #
def start_scan(conn: sqlite3.Connection, device_id: int | None, tipo: str,
               perfil: str, cmd: str, ts: int) -> int:
    cur = conn.execute(
        "INSERT INTO scans(device_id, tipo, perfil, inicio, estado, cmd) VALUES(?,?,?,?,?,?)",
        (device_id, tipo, perfil, ts, "ejecutando", cmd),
    )
    return int(cur.lastrowid)


def finish_scan(conn: sqlite3.Connection, scan_id: int, *, ts: int, estado: str,
                xml_path: str | None = None, exit_code: int | None = None,
                error: str | None = None) -> None:
    conn.execute(
        "UPDATE scans SET fin = ?, estado = ?, ruta_xml = COALESCE(?, ruta_xml), "
        "exit_code = ?, error = ? WHERE id = ?",
        (ts, estado, xml_path, exit_code, error, scan_id),
    )
    conn.execute(
        "UPDATE devices SET last_scan_ts = ?, last_scan_profile = "
        "(SELECT perfil FROM scans WHERE id = ?) WHERE id = "
        "(SELECT device_id FROM scans WHERE id = ?)",
        (ts, scan_id, scan_id),
    )


def create_scan_request(conn: sqlite3.Connection, objetivo: str, perfil: str,
                        solicitado_por: str, ts: int) -> int | None:
    """Devuelve id o None si ya había una solicitud pendiente idéntica (coalescing)."""
    row = conn.execute(
        "SELECT id FROM scan_requests WHERE objetivo = ? AND perfil = ? AND estado = 'pendiente'",
        (objetivo, perfil),
    ).fetchone()
    if row:
        return None
    cur = conn.execute(
        "INSERT INTO scan_requests(objetivo, perfil, solicitado_por, estado, ts) "
        "VALUES(?,?,?,'pendiente',?)",
        (objetivo, perfil, solicitado_por, ts),
    )
    return int(cur.lastrowid)


def claim_scan_requests(conn: sqlite3.Connection, limit: int = 5) -> list[sqlite3.Row]:
    rows = list(conn.execute(
        "SELECT * FROM scan_requests WHERE estado = 'pendiente' ORDER BY ts ASC LIMIT ?",
        (limit,),
    ))
    for r in rows:
        conn.execute("UPDATE scan_requests SET estado = 'ejecutando' WHERE id = ?", (r["id"],))
    return rows


def close_scan_request(conn: sqlite3.Connection, req_id: int, estado: str,
                       ts: int, error: str | None = None) -> None:
    conn.execute(
        "UPDATE scan_requests SET estado = ?, ts_fin = ?, error = ? WHERE id = ?",
        (estado, ts, error, req_id),
    )


def last_scan_ts(conn: sqlite3.Connection, device_id: int, perfil: str,
                 only_ok: bool = True) -> int | None:
    """Fin del último escaneo completado de ese perfil para un equipo (RF-10).

    Se consulta la tabla ``scans`` y no ``devices.last_scan_ts`` porque este
    último sólo recuerda el escaneo más reciente, sea cual sea su perfil.
    """
    sql = "SELECT MAX(fin) AS ts FROM scans WHERE device_id = ? AND perfil = ?"
    params: list[Any] = [device_id, perfil]
    if only_ok:
        sql += " AND estado = 'ok'"
    row = conn.execute(sql, params).fetchone()
    return int(row["ts"]) if row is not None and row["ts"] is not None else None


# --------------------------------------------------------------------------- #
# Eventos, dedupe y cola de notificación
# --------------------------------------------------------------------------- #
def add_event(conn: sqlite3.Connection, *, ts: int, tipo: str, severidad: str,
              clave_dedupe: str, ip_origen: str | None = None,
              mac_origen: str | None = None, ip_destino: str | None = None,
              detalle: dict | None = None, cooldown_s: int = 300,
              verified: bool = False) -> dict[str, Any]:
    """Inserta el evento o incrementa el existente si cae dentro del cooldown.

    Devuelve {event_id, is_new, repeat_count, severidad}.
    """
    if severidad not in SEVERITY_ORDER:
        raise ValueError(f"severidad inválida: {severidad}")
    recent = conn.execute(
        "SELECT id, last_ts, repeat_count, severidad FROM events WHERE clave_dedupe = ? "
        "ORDER BY last_ts DESC LIMIT 1",
        (clave_dedupe,),
    ).fetchone()
    # Sólo se fusiona si NO hay escalada: un warn que pasa a crit es un evento
    # nuevo y merece su propia notificación.
    if (recent is not None
            and (ts - int(recent["last_ts"])) <= cooldown_s * 1000
            and SEVERITY_ORDER[severidad] <= SEVERITY_ORDER[str(recent["severidad"])]):
        conn.execute(
            "UPDATE events SET last_ts = ?, repeat_count = repeat_count + 1 "
            "WHERE id = ?",
            (ts, recent["id"]),
        )
        return {"event_id": int(recent["id"]), "is_new": False,
                "repeat_count": int(recent["repeat_count"]) + 1, "severidad": severidad}
    cur = conn.execute(
        "INSERT INTO events(ts, first_ts, last_ts, severidad, tipo, ip_origen, mac_origen, "
        "ip_destino, detalle_json, clave_dedupe, repeat_count, verified) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,1,?)",
        (ts, ts, ts, severidad, tipo, ip_origen, mac_origen, ip_destino,
         json.dumps(detalle or {}, ensure_ascii=False, default=str), clave_dedupe,
         int(bool(verified))),
    )
    return {"event_id": int(cur.lastrowid), "is_new": True, "repeat_count": 1,
            "severidad": severidad}


def set_event_verified(conn: sqlite3.Connection, event_id: int, verified: bool,
                       detalle_extra: dict | None = None) -> None:
    conn.execute("UPDATE events SET verified = ? WHERE id = ?", (int(verified), event_id))
    if detalle_extra:
        row = conn.execute("SELECT detalle_json FROM events WHERE id = ?", (event_id,)).fetchone()
        if row:
            try:
                current = json.loads(row["detalle_json"] or "{}")
            except json.JSONDecodeError:
                current = {}
            current.update(detalle_extra)
            conn.execute("UPDATE events SET detalle_json = ? WHERE id = ?",
                         (json.dumps(current, ensure_ascii=False, default=str), event_id))


def enqueue_notification(conn: sqlite3.Connection, event_id: int, canal: str, ts: int) -> bool:
    exists = conn.execute(
        "SELECT 1 FROM notification_queue WHERE event_id = ? AND canal = ?", (event_id, canal)
    ).fetchone()
    if exists:
        return False
    conn.execute(
        "INSERT INTO notification_queue(event_id, canal, intentos, proximo_intento, estado, ts) "
        "VALUES(?,?,0,?,'pendiente',?)",
        (event_id, canal, ts, ts),
    )
    return True


def due_notifications(conn: sqlite3.Connection, ts: int, limit: int = 20) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT q.*, e.severidad, e.tipo, e.ip_origen, e.mac_origen, e.ip_destino, "
        "e.detalle_json, e.repeat_count, e.first_ts, e.last_ts "
        "FROM notification_queue q JOIN events e ON e.id = q.event_id "
        "WHERE q.estado = 'pendiente' AND q.proximo_intento <= ? "
        "ORDER BY q.proximo_intento ASC LIMIT ?",
        (ts, limit),
    ))


def notification_sent(conn: sqlite3.Connection, queue_id: int, event_id: int, ts: int) -> None:
    conn.execute(
        "UPDATE notification_queue SET estado = 'enviado', intentos = intentos + 1 WHERE id = ?",
        (queue_id,),
    )
    conn.execute(
        "UPDATE events SET notificado = 1, ts_notificado = ? WHERE id = ?", (ts, event_id)
    )


def notification_failed(conn: sqlite3.Connection, queue_id: int, error: str,
                        next_attempt_ts: int | None, agotado: bool) -> None:
    conn.execute(
        "UPDATE notification_queue SET intentos = intentos + 1, last_error = ?, "
        "estado = ?, proximo_intento = COALESCE(?, proximo_intento) WHERE id = ?",
        (error[:500], "agotado" if agotado else "pendiente", next_attempt_ts, queue_id),
    )


def list_events(conn: sqlite3.Connection, *, severidad: str | None = None,
                tipo: str | None = None, since: int | None = None,
                limit: int = 200) -> list[sqlite3.Row]:
    where, params = [], []
    if severidad:
        where.append("severidad = ?")
        params.append(severidad)
    if tipo:
        where.append("tipo = ?")
        params.append(tipo)
    if since:
        where.append("last_ts >= ?")
        params.append(since)
    sql = "SELECT * FROM events"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY last_ts DESC LIMIT ?"
    params.append(limit)
    return list(conn.execute(sql, params))


def get_event(conn: sqlite3.Connection, event_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()


def event_counts(conn: sqlite3.Connection, since: int) -> dict[str, int]:
    rows = conn.execute(
        "SELECT severidad, COUNT(*) AS n FROM events WHERE last_ts >= ? GROUP BY severidad",
        (since,),
    ).fetchall()
    out = {"info": 0, "warn": 0, "crit": 0}
    for r in rows:
        out[str(r["severidad"])] = int(r["n"])
    return out


def set_disposition(conn: sqlite3.Connection, event_id: int, disposicion: str) -> bool:
    if disposicion not in ("sin_evaluar", "tp", "fp"):
        raise ValueError(f"disposición inválida: {disposicion}")
    cur = conn.execute("UPDATE events SET disposicion = ? WHERE id = ?", (disposicion, event_id))
    return cur.rowcount > 0


# --------------------------------------------------------------------------- #
# Panel en vivo (sólo lectura, lo consume GET /api/live)
# --------------------------------------------------------------------------- #
def max_event_id(conn: sqlite3.Connection) -> int:
    """Id del evento más reciente (0 si la tabla está vacía).

    Es el cursor inicial del panel en vivo: al abrir o recargar no se avisa de
    lo que ya estaba en la base.
    """
    row = conn.execute("SELECT COALESCE(MAX(id), 0) AS m FROM events").fetchone()
    return int(row["m"]) if row is not None else 0


def events_since(conn: sqlite3.Connection, after_id: int,
                 limit: int = LIVE_MAX_EVENTS) -> list[sqlite3.Row]:
    """Eventos warn/crit con ``id`` mayor que ``after_id``, en orden ascendente.

    El cursor es el id autoincremental, no ``last_ts``: una repetición
    deduplicada sólo actualiza la fila existente (igual que en
    ``notification_queue``) y por tanto no vuelve a salir; una escalada
    warn→crit inserta una fila nueva y sí se entrega.

    ``limit`` se acota a 1..``LIVE_MAX_EVENTS`` para que ninguna petición
    manual pueda pedir el historial completo.
    """
    limit = max(1, min(int(limit), LIVE_MAX_EVENTS))
    return list(conn.execute(
        "SELECT * FROM events WHERE id > ? AND severidad IN ('warn','crit') "
        "ORDER BY id ASC LIMIT ?",
        (int(after_id), limit),
    ))


def live_summary(conn: sqlite3.Connection, since_ts: int) -> dict[str, Any]:
    """Contadores que el panel refresca sin recargar.

    ``since_ts`` es el inicio del día en ms UTC (mismo criterio que el panel).
    """
    counts = count_devices(conn)
    sev = event_counts(conn, since_ts)
    total_hoy = sum(sev.values())
    return {
        "dispositivos": int(counts.get("total", 0)),
        "en_linea": int(counts.get("online", 0)),
        "desconocidos": int(counts.get("desconocidos", 0)),
        "no_autorizados": int(counts.get("no_autorizados", 0)),
        "alertas_hoy": {
            "info": int(sev.get("info", 0)),
            "warn": int(sev.get("warn", 0)),
            "crit": int(sev.get("crit", 0)),
            "total": int(total_hoy),
        },
    }


def events_for_device(conn: sqlite3.Connection, device_id: int, limit: int = 50) -> list[sqlite3.Row]:
    device = get_device(conn, device_id)
    if device is None:
        return []
    return list(conn.execute(
        "SELECT * FROM events WHERE (ip_origen = ? OR ip_destino = ? OR mac_origen = ?) "
        "ORDER BY last_ts DESC LIMIT ?",
        (device["ip_actual"], device["ip_actual"], device["mac"], limit),
    ))


# --------------------------------------------------------------------------- #
# Salud, herramientas y mantenimiento
# --------------------------------------------------------------------------- #
def heartbeat(conn: sqlite3.Connection, componente: str, ts: int, detalle: str | None = None) -> None:
    conn.execute(
        "INSERT INTO heartbeat(componente, ts, detalle) VALUES(?,?,?) "
        "ON CONFLICT(componente) DO UPDATE SET ts = excluded.ts, detalle = excluded.detalle",
        (componente, ts, detalle),
    )


def get_heartbeat(conn: sqlite3.Connection, componente: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM heartbeat WHERE componente = ?", (componente,)
    ).fetchone()


def record_tool_status(conn: sqlite3.Connection, herramienta: str, ts: int, ok: bool,
                       exit_code: int | None = None, error: str | None = None) -> int:
    """Devuelve los fallos consecutivos tras registrar el intento."""
    row = conn.execute(
        "SELECT fallos_consecutivos FROM tool_status WHERE herramienta = ?", (herramienta,)
    ).fetchone()
    prev = int(row["fallos_consecutivos"]) if row else 0
    fails = 0 if ok else prev + 1
    conn.execute(
        "INSERT INTO tool_status(herramienta, ts, ok, exit_code, error, fallos_consecutivos) "
        "VALUES(?,?,?,?,?,?) ON CONFLICT(herramienta) DO UPDATE SET ts = excluded.ts, "
        "ok = excluded.ok, exit_code = excluded.exit_code, error = excluded.error, "
        "fallos_consecutivos = excluded.fallos_consecutivos",
        (herramienta, ts, int(ok), exit_code, (error or None) and error[:500], fails),
    )
    return fails


def tool_status(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return list(conn.execute("SELECT * FROM tool_status ORDER BY herramienta"))


def purge(conn: sqlite3.Connection, before_ts: int) -> dict[str, Any]:
    """Retención: elimina datos y artefactos anteriores a ``before_ts`` (RNF-06).

    Cubre eventos, escaneos terminados, historial de presencia y las
    notificaciones ya enviadas o agotadas. **Nunca** toca la cola
    ``pendiente``: un fallo de red no puede perder alertas por antigüedad.

    Devuelve los contadores y, en ``scan_xml``, las rutas de los XML de los
    escaneos purgados para que la capa que tiene acceso al sistema de archivos
    (el sensor) los elimine dentro de ``paths.scans_dir``.
    """
    xml_rows = conn.execute(
        "SELECT ruta_xml FROM scans WHERE fin IS NOT NULL AND fin < ? "
        "AND ruta_xml IS NOT NULL",
        (before_ts,),
    ).fetchall()
    scans = conn.execute(
        "DELETE FROM scans WHERE fin IS NOT NULL AND fin < ?", (before_ts,)
    ).rowcount
    # La cola se purga antes que los eventos: los eventos borrados arrastran sus
    # filas por ON DELETE CASCADE y el contador dejaría de ser informativo.
    notifications = conn.execute(
        "DELETE FROM notification_queue WHERE ts < ? AND estado IN ('enviado','agotado')",
        (before_ts,),
    ).rowcount
    events = conn.execute("DELETE FROM events WHERE last_ts < ?", (before_ts,)).rowcount
    history = conn.execute(
        "DELETE FROM device_history WHERE ts < ? AND evento IN ('conexion','desconexion','cambio_ip')",
        (before_ts,),
    ).rowcount
    return {
        "events": events,
        "scans": scans,
        "history": history,
        "notifications": notifications,
        "scan_xml": [str(r["ruta_xml"]) for r in xml_rows if r["ruta_xml"]],
    }


# --------------------------------------------------------------------------- #
# Reinicio de la base (acción manual, sólo CLI con root)
# --------------------------------------------------------------------------- #
# El alcance está fijado aquí a propósito: ningún llamador pasa nombres de
# tabla, así que no hay forma de inyectar SQL por esta vía.
RESET_TABLES_ALL = (
    "notification_queue", "events", "ports", "scans", "scan_requests",
    "device_history", "devices", "identities", "heartbeat", "tool_status",
    "network_baseline",
)
RESET_TABLES_KEEP_DEVICES = (
    "notification_queue", "events", "ports", "scans", "scan_requests", "tool_status",
)


def table_counts(conn: sqlite3.Connection) -> dict[str, int]:
    """Filas por tabla de datos, para el resumen previo al reset."""
    out: dict[str, int] = {}
    for table in RESET_TABLES_ALL:
        try:
            row = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
            out[table] = int(row["n"]) if row else 0
        except sqlite3.OperationalError:
            out[table] = 0
    return out


def _reset_tables(conn: sqlite3.Connection, tables: tuple[str, ...]) -> dict[str, int]:
    """Vacía las tablas indicadas en una única transacción."""
    counts: dict[str, int] = {}
    conn.execute("BEGIN IMMEDIATE")
    try:
        # El orden importa por las claves foráneas: primero las hijas.
        for table in tables:
            counts[table] = conn.execute(f"DELETE FROM {table}").rowcount
        try:
            # Sólo existe si alguna tabla usó AUTOINCREMENT; si no, se ignora.
            conn.execute("DELETE FROM sqlite_sequence")
        except sqlite3.OperationalError:
            pass
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    return counts


def reset_all(conn: sqlite3.Connection) -> dict[str, int]:
    """Borra todos los datos: quedan sólo el esquema y la versión."""
    return _reset_tables(conn, RESET_TABLES_ALL)


def reset_keep_devices(conn: sqlite3.Connection) -> dict[str, int]:
    """Borra eventos, puertos, escaneos y estados; conserva el inventario."""
    return _reset_tables(conn, RESET_TABLES_KEEP_DEVICES)


def vacuum(conn: sqlite3.Connection) -> None:
    """Compacta el archivo tras el reset (fuera de transacción, por diseño)."""
    conn.execute("VACUUM")

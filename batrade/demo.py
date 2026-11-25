"""Siembra de datos de demostración sin privilegios ni tráfico real.

Se usa para mostrar el panel y para probar el pipeline completo (motor ->
dedupe -> cola -> dashboard) en una VM sin CAP_NET_RAW.
"""
from __future__ import annotations

from dataclasses import replace

from batrade import db, store
from batrade.config import Config
from batrade.detect import scenarios
from batrade.detect.engine import Engine
from batrade.detect.state import Baseline
from batrade.events import persist_findings
from batrade.inventory import Inventory, approve_baseline
from batrade.net.iputil import normalize_mac, now_ms
from batrade.net.oui import OuiDB
from batrade.notify import Notifier

# Puertos plausibles para que el panel muestre superficie de ataque real.
DEMO_PORTS = {
    "victim": [
        {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh",
         "version": "OpenSSH 9.6"},
        {"port": 8000, "protocol": "tcp", "state": "open", "service": "http",
         "version": "Python http.server"},
        {"port": 2323, "protocol": "tcp", "state": "open", "service": "telnet",
         "version": None},
    ],
    "attacker": [
        {"port": 445, "protocol": "tcp", "state": "open", "service": "microsoft-ds",
         "version": None},
        {"port": 3389, "protocol": "tcp", "state": "open", "service": "ms-wbt-server",
         "version": None},
    ],
}


def seed_demo(cfg: Config, scenario_names: list[str] | None = None) -> dict[str, int]:
    names = scenario_names or ["mixed", "router_reboot"]
    cfg.ensure_dirs()
    conn = db.initialize(cfg.paths.db)
    ts_now = now_ms()
    oui = OuiDB.load(cfg.paths.oui_file)
    ctx = scenarios.ScenarioContext(cfg)

    # La demo salta el modo aprendizaje: si no, los hallazgos no se notificarían.
    store.set_meta(conn, "learning_complete", "1", ts_now)
    store.set_meta(conn, "gateway_ip", ctx.gateway_ip, ts_now)
    store.set_meta(conn, "gateway_mac", ctx.gateway_mac, ts_now)

    original_channels = list(cfg.notify.channels)
    cfg.notify.channels = [{"type": "local"}]
    notifier = Notifier(cfg, lambda: db.connect(cfg.paths.db))
    try:
        for index, name in enumerate(names):
            engine = Engine(cfg, Baseline(
                gateway_ip=ctx.gateway_ip, gateway_mac=ctx.gateway_mac,
                sensor_ips={ctx.sensor_ip},
                sensor_macs={normalize_mac(ctx.sensor_mac) or ""},
                learning=False,
            ))
            inventory = Inventory(conn, cfg, oui, learning=False)
            observations = scenarios.synthetic(name, cfg)
            if not observations:
                continue
            origin = ts_now - (len(names) - index) * 6 * 60_000
            first_ts = observations[0].ts
            for obs in observations:
                feed = replace(obs, ts=origin + int((obs.ts - first_ts) / 20))
                findings = engine.observe(feed)
                if feed.kind == "arp" and feed.ip_src and feed.mac_src:
                    findings.extend(inventory.observe_host(
                        feed.ip_src, feed.mac_src, feed.ts, source="demo"))
                if findings:
                    persist_findings(
                        conn, findings, cfg, feed.ts, learning=False,
                        enqueue=lambda eid, t: notifier.enqueue(conn, eid, t),
                    )

        _seed_ports(conn, cfg, ctx, notifier)
        approve_baseline(conn, ts_now)
        _decorate(conn, ctx)
        notifier.process_once()
    finally:
        cfg.notify.channels = original_channels

    counts = store.count_devices(conn)
    ev_counts = store.count_events(conn)
    return {
        "dispositivos": counts.get("total", 0),
        "en_linea": counts.get("online", 0),
        "desconocidos": counts.get("desconocidos", 0),
        "no_autorizados": counts.get("no_autorizados", 0),
        "eventos": ev_counts["total"],
        "notificados": ev_counts["notificados"],
    }


def _decorate(conn, ctx: scenarios.ScenarioContext) -> None:
    """Aliases y estados que hacen legible la demo."""
    gateway = store.get_device_by_mac(conn, normalize_mac(ctx.gateway_mac) or "")
    if gateway:
        store.set_device_state(conn, int(gateway["id"]), alias="Router")
    victim = store.get_device_by_mac(conn, normalize_mac(ctx.victim_mac) or "")
    if victim:
        store.set_device_state(conn, int(victim["id"]), alias="Laptop demo",
                               estado="confiable")
    attacker = store.get_device_by_mac(conn, normalize_mac(ctx.attacker_mac) or "")
    if attacker:
        store.set_device_state(conn, int(attacker["id"]),
                               alias="Equipo sospechoso (demo)", estado="no_autorizado")


def _seed_ports(conn, cfg: Config, ctx: scenarios.ScenarioContext,
                notifier: Notifier) -> None:
    """Inserta puertos del catálogo y genera los eventos de superficie expuesta."""
    from batrade.detect.observation import Finding

    targets = {"victim": str(ctx.victim_ip), "attacker": str(ctx.attacker_ip)}
    for who, ports in DEMO_PORTS.items():
        ip = targets[who]
        device = store.get_device_by_ip(conn, ip)
        if device is None:
            continue
        device_id = int(device["id"])
        diff = store.apply_scan_ports(conn, device_id, ports, now_ms(), cfg.scan.risky_ports)
        findings = []
        for p in diff["new_risky"]:
            findings.append(Finding(
                tipo="port_risky", severidad="warn",
                clave=f"port:risky:{device_id}:{p['protocol']}:{p['port']}",
                ip_origen=ip, mac_origen=device["mac"],
                detalle={
                    "resumen": (f"{ip} expone el puerto {p['port']}/{p['protocol']} "
                                f"({p['service'] or 'desconocido'})"),
                    "por_que": p["reason"],
                    "accion": "Deshabilitar el servicio o aislar el dispositivo.",
                    "puerto": p["port"], "protocolo": p["protocol"],
                    "servicio": p["service"],
                },
            ))
        if findings:
            persist_findings(conn, findings, cfg, now_ms(),
                             enqueue=lambda eid, t: notifier.enqueue(conn, eid, t))

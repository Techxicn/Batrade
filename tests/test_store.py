"""Repositorio: inventario, puertos, dedupe de eventos y retención."""
from __future__ import annotations

from batrade import store


def _device(conn, mac="3c:22:fb:11:22:33", ip="10.10.10.50", ts=1000):
    return store.upsert_device(conn, mac=mac, ip=ip, ts=ts, hostname="laptop",
                               fabricante="Apple", mac_aleatoria=False)


def test_upsert_creates_device_and_history(conn):
    result = _device(conn)
    assert result["created"] is True
    assert result["identity_created"] is True
    device = store.get_device(conn, result["device_id"])
    assert device["en_linea"] == 1
    assert device["estado_confianza"] == "desconocido"
    assert len(store.list_history(conn, result["device_id"])) == 1


def test_second_sighting_is_not_new(conn):
    first = _device(conn)
    second = store.upsert_device(conn, mac="3c:22:fb:11:22:33", ip="10.10.10.50", ts=2000)
    assert second["created"] is False
    assert second["came_online"] is False
    assert second["device_id"] == first["device_id"]
    assert store.count_devices(conn)["total"] == 1


def test_ip_change_is_recorded(conn):
    first = _device(conn)
    moved = store.upsert_device(conn, mac="3c:22:fb:11:22:33", ip="10.10.10.51", ts=3000)
    assert moved["ip_changed"] is True
    assert moved["prev_ip"] == "10.10.10.50"
    eventos = [h["evento"] for h in store.list_history(conn, first["device_id"])]
    assert "cambio_ip" in eventos


def test_presence_misses_until_offline(conn, cfg):
    device = _device(conn)
    did = device["device_id"]
    threshold = cfg.sensor.presence_misses
    for _ in range(threshold - 1):
        assert store.register_miss(conn, did, 10_000, threshold) is None
    assert store.get_device(conn, did)["en_linea"] == 1
    offline = store.register_miss(conn, did, 20_000, threshold)
    assert offline["en_linea"] == 0
    assert store.get_device(conn, did)["en_linea"] == 0
    # Reconexión posterior
    again = store.upsert_device(conn, mac="3c:22:fb:11:22:33", ip="10.10.10.50", ts=30_000)
    assert again["came_online"] is True


def test_set_device_state_validates(conn):
    did = _device(conn)["device_id"]
    assert store.set_device_state(conn, did, estado="confiable", alias="  Sala  ")
    device = store.get_device(conn, did)
    assert device["estado_confianza"] == "confiable"
    assert device["alias"] == "Sala"
    try:
        store.set_device_state(conn, did, estado="inventado")
    except ValueError as exc:
        assert "inválido" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("debía rechazar el estado")


def test_apply_scan_ports_classifies_and_closes(conn, cfg):
    did = _device(conn)["device_id"]
    risky = cfg.scan.risky_ports
    found = [
        {"port": 23, "protocol": "tcp", "state": "open", "service": "telnet"},
        {"port": 8000, "protocol": "tcp", "state": "open", "service": "http"},
    ]
    diff = store.apply_scan_ports(conn, did, found, 1000, risky)
    assert [p["port"] for p in diff["new_risky"]] == [23]
    assert [p["port"] for p in diff["new_ports"]] == [8000]

    # Repetir el mismo escaneo no genera novedades
    same = store.apply_scan_ports(conn, did, found, 2000, risky)
    assert same == {"new_risky": [], "new_ports": [], "disappeared": []}

    # Un puerto que ya no aparece queda cerrado
    gone = store.apply_scan_ports(conn, did, [], 3000, risky)
    assert [p["port"] for p in gone["disappeared"]] == [23, 8000]
    states = {p["puerto"]: p["estado"] for p in store.list_ports(conn, did)}
    assert states[8000] == "closed"
    assert states[23] == "closed"


def test_event_dedupe_and_repeat_count(conn):
    first = store.add_event(conn, ts=1000, tipo="arp_gateway_mac_change",
                            severidad="crit", clave_dedupe="k1", cooldown_s=300)
    assert first["is_new"] is True
    again = store.add_event(conn, ts=2000, tipo="arp_gateway_mac_change",
                            severidad="crit", clave_dedupe="k1", cooldown_s=300)
    assert again["is_new"] is False
    assert again["repeat_count"] == 2
    assert store.get_event(conn, first["event_id"])["repeat_count"] == 2

    after_cooldown = store.add_event(conn, ts=302_001, tipo="arp_gateway_mac_change",
                                     severidad="crit", clave_dedupe="k1", cooldown_s=300)
    assert after_cooldown["is_new"] is True


def test_severity_escalation_is_not_swallowed(conn):
    """Un warn que pasa a crit no puede fundirse en el mismo registro (bug real)."""
    low = store.add_event(conn, ts=1000, tipo="scan_ports_aggressive",
                          severidad="warn", clave_dedupe="scan:x", cooldown_s=300)
    high = store.add_event(conn, ts=1500, tipo="scan_ports_aggressive",
                           severidad="crit", clave_dedupe="scan:x", cooldown_s=300)
    assert low["is_new"] is True
    assert high["is_new"] is True
    assert high["event_id"] != low["event_id"]


def test_notification_queue_lifecycle(conn):
    event = store.add_event(conn, ts=1000, tipo="device_new", severidad="warn",
                            clave_dedupe="dev:1", cooldown_s=0)
    eid = event["event_id"]
    assert store.enqueue_notification(conn, eid, "local", 1000) is True
    assert store.enqueue_notification(conn, eid, "local", 1000) is False
    due = store.due_notifications(conn, 1000)
    assert len(due) == 1
    store.notification_sent(conn, due[0]["id"], eid, 1200)
    assert store.get_event(conn, eid)["notificado"] == 1
    assert store.due_notifications(conn, 2000) == []


def test_disposition_and_purge(conn):
    event = store.add_event(conn, ts=1000, tipo="x", severidad="warn",
                            clave_dedupe="x", cooldown_s=0)
    assert store.set_disposition(conn, event["event_id"], "fp")
    assert store.get_event(conn, event["event_id"])["disposicion"] == "fp"
    for bad in ("no", ""):
        try:
            store.set_disposition(conn, event["event_id"], bad)
        except ValueError:
            pass
        else:  # pragma: no cover
            raise AssertionError("disposición inválida aceptada")
    purged = store.purge(conn, 5000)
    assert purged["events"] == 1


def test_scan_request_coalescing(conn):
    assert store.create_scan_request(conn, "10.10.10.50", "quick", "test", 1000) is not None
    assert store.create_scan_request(conn, "10.10.10.50", "quick", "test", 2000) is None
    claimed = store.claim_scan_requests(conn)
    assert len(claimed) == 1
    store.close_scan_request(conn, claimed[0]["id"], "hecho", 3000)
    assert store.create_scan_request(conn, "10.10.10.50", "quick", "test", 4000) is not None


def test_events_for_device_no_mezcla_ips_reutilizadas(conn):
    """F-06: un equipo nuevo con la IP de otro no hereda sus eventos."""
    desde_a = store.upsert_device(conn, mac="3c:22:fb:11:22:33", ip="10.10.10.50",
                                  ts=1000)["device_id"]
    store.add_history(conn, desde_a, 1000, "conexion", ip="10.10.10.50")
    # Un evento sin MAC del periodo de A: sólo lo puede reclamar el periodo A.
    e1 = store.add_event(conn, ts=2000, tipo="port_scan", severidad="warn",
                         clave_dedupe="f6-1", ip_origen="10.10.10.50",
                         detalle={"resumen": "de A"})
    e2 = store.add_event(conn, ts=2500, tipo="arp_spoof", severidad="crit",
                         clave_dedupe="f6-2", ip_origen="10.10.10.50",
                         mac_origen="3c:22:fb:11:22:33", detalle={"resumen": "de A"})
    # A se va y B hereda la IP mucho después.
    store.set_device_state(conn, desde_a, estado="confiable")
    b = store.upsert_device(conn, mac="aa:bb:cc:00:11:22", ip="10.10.10.50",
                            ts=5000)["device_id"]
    store.add_history(conn, b, 5000, "conexion", ip="10.10.10.50")
    e3 = store.add_event(conn, ts=6000, tipo="port_scan", severidad="warn",
                         clave_dedupe="f6-3", ip_origen="10.10.10.50",
                         detalle={"resumen": "de B"})
    # El equipo fue víctima: ip_destino cuenta aunque la MAC sea del atacante.
    e4 = store.add_event(conn, ts=7000, tipo="arp_spoof", severidad="crit",
                         clave_dedupe="f6-4", ip_origen="10.10.10.66",
                         mac_origen="de:ad:be:ef:00:01", ip_destino="10.10.10.50",
                         detalle={"resumen": "B fue la víctima"})
    conn.commit()

    ids_a = {e["id"] for e in store.events_for_device(conn, int(desde_a))}
    ids_b = {e["id"] for e in store.events_for_device(conn, int(b))}

    assert e1["event_id"] in ids_a            # evento sin MAC del periodo de A
    assert e1["event_id"] not in ids_b        # B llegó después: no lo hereda
    assert e2["event_id"] in ids_a
    assert e3["event_id"] in ids_b
    assert e4["event_id"] in ids_b
    assert e4["event_id"] not in ids_a        # B era el destino, no A

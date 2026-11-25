"""Inventario: modo aprendizaje, identidad y línea base (RF-04..06, C7)."""
from __future__ import annotations

from batrade import store
from batrade.inventory import Inventory, approve_baseline, review_candidates, status

NORMAL = "3c:22:fb:11:22:33"
RANDOM = "aa:bb:cc:00:11:22"


def test_new_device_during_learning_is_silent(conn, cfg, oui):
    inv = Inventory(conn, cfg, oui, learning=True)
    findings = inv.observe_host("10.10.10.50", NORMAL, 1000)
    assert len(findings) == 1
    assert findings[0].tipo == "device_new"
    assert findings[0].severidad == "info"
    assert findings[0].notificar is False


def test_new_device_after_learning_warns(conn, cfg, oui):
    inv = Inventory(conn, cfg, oui, learning=False)
    findings = inv.observe_host("10.10.10.50", NORMAL, 1000)
    assert findings[0].severidad == "warn"
    assert findings[0].notificar is True
    assert "Apple" in findings[0].detalle["resumen"]


def test_random_mac_is_flagged_and_has_no_vendor(conn, cfg, oui):
    inv = Inventory(conn, cfg, oui, learning=False)
    inv.observe_host("10.10.10.60", RANDOM, 1000)
    device = store.get_device_by_mac(conn, RANDOM)
    assert device["mac_aleatoria"] == 1
    assert device["fabricante"] is None       # el OUI de una MAC local es basura


def test_random_mac_with_same_hostname_is_grouped(conn, cfg, oui):
    """RF-06/C4: dos MACs aleatorias con el mismo hostname son un solo equipo."""
    inv = Inventory(conn, cfg, oui, learning=False)
    first = inv.observe_host("10.10.10.60", RANDOM, 1000, hostname="Pixel-7")
    second = inv.observe_host("10.10.10.61", "ba:bb:cc:00:11:22", 2000,
                              hostname="Pixel-7")
    assert first[0].tipo == "device_new"
    assert second[0].tipo == "device_mac_rotated"
    assert second[0].notificar is False
    assert store.count_devices(conn)["total"] == 2   # dos MACs...


def test_reconnect_of_unauthorized_is_critical(conn, cfg, oui):
    inv = Inventory(conn, cfg, oui, learning=False)
    inv.observe_host("10.10.10.50", NORMAL, 1000)
    did = store.get_device_by_mac(conn, NORMAL)["id"]
    store.set_device_state(conn, did, estado="no_autorizado")
    store.register_miss(conn, did, 2000, 1)          # fuera de línea
    findings = inv.observe_host("10.10.10.50", NORMAL, 3000)
    assert findings[0].tipo == "device_unauthorized_online"
    assert findings[0].severidad == "crit"


def test_trusted_reconnect_is_informational(conn, cfg, oui):
    inv = Inventory(conn, cfg, oui, learning=False)
    inv.observe_host("10.10.10.50", NORMAL, 1000)
    did = store.get_device_by_mac(conn, NORMAL)["id"]
    store.set_device_state(conn, did, estado="confiable")
    store.register_miss(conn, did, 2000, 1)
    findings = inv.observe_host("10.10.10.50", NORMAL, 3000)
    assert findings[0].tipo == "device_online"
    assert findings[0].severidad == "info"
    assert findings[0].notificar is False


def test_sweep_marks_absent_devices_offline(conn, cfg, oui):
    inv = Inventory(conn, cfg, oui, learning=False)
    inv.observe_host("10.10.10.50", NORMAL, 1000)
    inv.observe_host("10.10.10.51", "00:1a:2b:00:00:02", 1000)
    seen = {"10.10.10.50": NORMAL}
    for i in range(cfg.sensor.presence_misses):
        findings = inv.apply_sweep(seen, 2000 + i)
    assert store.get_device_by_mac(conn, NORMAL)["en_linea"] == 1
    other = store.get_device_by_mac(conn, "00:1a:2b:00:00:02")
    assert other["en_linea"] == 0
    assert "device_offline" in [f.tipo for f in findings]


def test_sweep_ignores_online_devices_from_other_subnet(conn, cfg, oui):
    """L-04: un equipo de otra subred no recibe misses ni device_offline."""
    inv = Inventory(conn, cfg, oui, learning=False)
    inv.observe_host("10.10.10.50", NORMAL, 1000)
    inv.observe_host("192.168.99.20", "00:1a:2b:00:00:99", 1000)

    seen = {"10.10.10.50": NORMAL}
    all_findings = []
    for i in range(cfg.sensor.presence_misses + 1):
        all_findings.extend(inv.apply_sweep(seen, 2000 + i))

    ajeno = store.get_device_by_mac(conn, "00:1a:2b:00:00:99")
    assert ajeno["en_linea"] == 1
    assert ajeno["misses"] == 0
    assert "device_offline" not in [f.tipo for f in all_findings]


def test_approve_baseline_keeps_random_macs_for_review(conn, cfg, oui):
    inv = Inventory(conn, cfg, oui, learning=True)
    inv.observe_host("10.10.10.50", NORMAL, 1000)
    inv.observe_host("10.10.10.60", RANDOM, 1000)
    result = approve_baseline(conn, 5000)
    assert result == {"aprobados": 1, "pendientes": 1}
    assert store.get_device_by_mac(conn, NORMAL)["estado_confianza"] == "confiable"
    assert store.get_device_by_mac(conn, RANDOM)["estado_confianza"] == "desconocido"
    pending = review_candidates(conn)
    assert [p["mac"] for p in pending] == [RANDOM]
    assert status(conn)["learning"] is False


def test_approve_all_can_include_random(conn, cfg, oui):
    inv = Inventory(conn, cfg, oui, learning=True)
    inv.observe_host("10.10.10.60", RANDOM, 1000)
    result = approve_baseline(conn, 5000, include_random_mac=True)
    assert result["aprobados"] == 1
    assert result["pendientes"] == 0

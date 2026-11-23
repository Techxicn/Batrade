"""Reglas de detección: positivos esperados y, sobre todo, negativos."""
from __future__ import annotations

from batrade.detect.observation import DHCP, Observation
from batrade.detect.rules import BINDING_REUSE_MS

from tests.conftest import ATTACKER_IP, ATTACKER_MAC, GW_IP, GW_MAC, HOST_IP, HOST_MAC


def _tipos(findings):
    return [f.tipo for f in findings]


# ------------------------------------------------ RF-11: ARP spoofing
def test_gateway_mac_change_is_critical(engine, arp):
    engine.observe(arp(1000, GW_IP, GW_MAC))
    findings = engine.observe(arp(2000, GW_IP, ATTACKER_MAC, gratuitous=True))
    assert "arp_gateway_mac_change" in _tipos(findings)
    crit = next(f for f in findings if f.tipo == "arp_gateway_mac_change")
    assert crit.severidad == "crit"
    assert crit.needs_verify == GW_IP          # se pide verificación activa
    assert crit.detalle["accion"]             # el PRD exige acción sugerida


def test_non_gateway_mac_change_is_warning(engine, arp):
    engine.observe(arp(1000, HOST_IP, HOST_MAC))
    findings = engine.observe(arp(3000, HOST_IP, ATTACKER_MAC))
    assert "arp_ip_mac_change" in _tipos(findings)
    assert next(f for f in findings if f.tipo == "arp_ip_mac_change").severidad == "warn"


def test_stale_binding_reuse_is_informational(engine, arp):
    """Reasignación legítima de IP por DHCP: no debe gritar."""
    engine.observe(arp(1000, HOST_IP, HOST_MAC))
    findings = engine.observe(arp(1000 + BINDING_REUSE_MS + 60_000, HOST_IP, ATTACKER_MAC))
    tipos = _tipos(findings)
    assert "arp_ip_mac_change" not in tipos
    assert "arp_ip_reuse" in tipos
    assert next(f for f in findings if f.tipo == "arp_ip_reuse").severidad == "info"


def test_same_mac_claiming_gateway_is_critical(engine, arp):
    engine.observe(arp(1000, GW_IP, GW_MAC))
    engine.observe(arp(1100, HOST_IP, ATTACKER_MAC))
    # El atacante ahora también reclama la IP del gateway
    findings = engine.observe(arp(5000, GW_IP, ATTACKER_MAC))
    multi = [f for f in findings if f.tipo == "arp_mac_multiple_ips"]
    assert multi and multi[0].severidad == "crit"


def test_same_mac_several_hosts_is_warning(engine, arp):
    engine.observe(arp(1000, "10.10.10.70", ATTACKER_MAC))
    findings = engine.observe(arp(1100, "10.10.10.71", ATTACKER_MAC))
    multi = [f for f in findings if f.tipo == "arp_mac_multiple_ips"]
    assert multi and multi[0].severidad == "warn"


def test_arp_exceptions_are_respected(cfg, baseline, arp):
    from batrade.detect.engine import Engine

    baseline.exceptions = {ATTACKER_MAC}
    engine = Engine(cfg, baseline)
    engine.observe(arp(1000, "10.10.10.70", ATTACKER_MAC))
    findings = engine.observe(arp(1100, "10.10.10.71", ATTACKER_MAC))
    assert "arp_mac_multiple_ips" not in _tipos(findings)


def test_sensor_itself_is_never_flagged(engine, arp):
    from tests.conftest import SENSOR_IP, SENSOR_MAC

    engine.observe(arp(1000, SENSOR_IP, SENSOR_MAC))
    findings = engine.observe(arp(1100, SENSOR_IP, "00:11:22:33:44:55"))
    assert findings == []


def test_router_reboot_burst_is_not_an_attack(engine, arp):
    """PA-05: ráfaga gratuita con la MAC correcta no puede alertar (C6)."""
    engine.observe(arp(1000, GW_IP, GW_MAC))
    findings = []
    for i in range(60):
        findings += engine.observe(arp(2000 + i * 50, GW_IP, GW_MAC, gratuitous=True))
    assert findings == []


def test_burst_with_conflicting_binding_does_alert(engine, arp):
    engine.observe(arp(1000, GW_IP, GW_MAC))
    engine.observe(arp(1001, HOST_IP, HOST_MAC))
    engine.observe(arp(2000, HOST_IP, ATTACKER_MAC))       # conflicto real
    findings = []
    for i in range(25):
        findings += engine.observe(arp(2100 + i * 20, HOST_IP, ATTACKER_MAC))
    assert "arp_flood" in _tipos(findings)


# ------------------------------------------------ RF-12: barridos
def test_arp_sweep_warns_at_threshold(engine, arp):
    findings = []
    for i in range(31):
        findings += engine.observe(arp(1000 + i * 50, ATTACKER_IP, ATTACKER_MAC,
                                       ip_dst=f"10.10.10.{i + 10}", op="request"))
    sweeps = [f for f in findings if f.tipo == "arp_sweep"]
    assert sweeps and sweeps[0].severidad == "warn"
    assert sweeps[0].detalle["distinct_ips"] >= 30


def test_arp_sweep_escalates_when_massive(engine, arp):
    findings = []
    for i in range(91):
        findings += engine.observe(arp(1000 + i * 10, ATTACKER_IP, ATTACKER_MAC,
                                       ip_dst=f"10.10.10.{i % 250 + 2}", op="request"))
    assert any(f.tipo == "arp_sweep" and f.severidad == "crit" for f in findings)


def test_gateway_sweep_is_ignored(engine, arp):
    findings = []
    for i in range(60):
        findings += engine.observe(arp(1000 + i * 10, GW_IP, GW_MAC,
                                       ip_dst=f"10.10.10.{i + 2}", op="request"))
    assert "arp_sweep" not in _tipos(findings)


def test_syn_scan_moderate_warns(engine, syn):
    findings = []
    for port in range(1, 16):
        findings += engine.observe(syn(1000 + port * 10, ATTACKER_IP, HOST_IP, port))
    assert any(f.tipo == "scan_ports_moderate" for f in findings)


def test_syn_scan_aggressive_is_critical(engine, syn):
    findings = []
    for port in range(1, 101):
        findings += engine.observe(syn(1000 + port * 5, ATTACKER_IP, HOST_IP, port))
    assert any(f.tipo == "scan_ports_aggressive" and f.severidad == "crit"
               for f in findings)


def test_syn_multi_host_sweep_is_critical(engine, syn):
    findings = []
    for i in range(26):
        findings += engine.observe(syn(1000 + i * 10, ATTACKER_IP, f"10.10.10.{i + 20}", 80))
    assert any(f.tipo == "scan_hosts_aggressive" for f in findings)


def test_own_scan_is_not_an_alert(engine, syn):
    """PA-08: el nmap del propio sensor no puede disparar la regla."""
    from tests.conftest import SENSOR_IP

    findings = []
    for port in range(1, 120):
        findings += engine.observe(syn(1000 + port * 5, SENSOR_IP, HOST_IP, port))
    assert findings == []


def test_syn_ack_is_not_counted(engine, syn):
    findings = []
    for port in range(1, 120):
        findings += engine.observe(syn(1000 + port * 5, ATTACKER_IP, HOST_IP, port,
                                       flags="SA"))
    assert findings == []


def test_window_slides(engine, syn):
    """Puertos separados más que la ventana no forman un escaneo."""
    findings = []
    for i in range(20):
        findings += engine.observe(syn(1000 + i * 20_000, ATTACKER_IP, HOST_IP, i + 1))
    assert findings == []


# ------------------------------------------------ RF-13: DHCP rogue
def test_rogue_dhcp_server_is_critical(engine):
    from tests.conftest import GW_MAC as _gw

    engine.baseline.dhcp_server_ip = GW_IP
    obs = Observation(kind=DHCP, ts=1000, ip_src="10.10.10.99", mac_src=ATTACKER_MAC,
                      op="offer", extra={"yiaddr": HOST_IP, "msg_type": 2})
    findings = engine.observe(obs)
    rogue = [f for f in findings if f.tipo == "dhcp_rogue"]
    assert rogue and rogue[0].severidad == "crit"
    assert rogue[0].detalle["expected"] == GW_IP
    del _gw


def test_expected_dhcp_server_is_silent(engine):
    engine.baseline.dhcp_server_ip = GW_IP
    obs = Observation(kind=DHCP, ts=1000, ip_src=GW_IP, mac_src=GW_MAC,
                      op="offer", extra={"yiaddr": HOST_IP, "msg_type": 2})
    assert engine.observe(obs) == []


def test_dhcp_server_is_learned_when_unknown(engine):
    engine.baseline.dhcp_server_ip = None
    obs = Observation(kind=DHCP, ts=1000, ip_src="10.10.10.3", mac_src="00:50:56:00:00:03",
                      op="offer", extra={"yiaddr": HOST_IP, "msg_type": 2})
    assert engine.observe(obs) == []
    assert engine.baseline.dhcp_server_ip == "10.10.10.3"


def test_el_gateway_no_adopta_la_mac_del_atacante(engine, arp):
    """L-01: decisión tomada. El binding del gateway conserva la MAC legítima.

    Si el sensor adoptara la MAC del primer atacante, el segundo ataque se
    compararía contra la del atacante y pasaría por «vuelta a la normalidad».
    """
    engine.observe(arp(1000, GW_IP, GW_MAC))
    engine.observe(arp(2000, GW_IP, ATTACKER_MAC))               # primer spoof
    findings = engine.observe(arp(3000, GW_IP, "aa:bb:cc:00:99:99"))  # segundo
    segundo = next(f for f in findings if f.tipo == "arp_gateway_mac_change")
    assert segundo.detalle["prev_mac"] == GW_MAC

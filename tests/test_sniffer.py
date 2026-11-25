"""Sniffer en puerto espejo: modo promiscuo e interfaz en la observación."""
from __future__ import annotations

import threading

import pytest

scapy = pytest.importorskip("scapy.all")

from scapy.all import ARP as ScapyARP  # noqa: E402
from scapy.all import BOOTP, DHCP as ScapyDHCP, Ether, IP, TCP, UDP  # noqa: E402

from batrade.detect.observation import ARP, DHCP, SYN  # noqa: E402
from batrade.detect.scenarios import observation_from_packet  # noqa: E402
from batrade.detect.sniffer import (DEFAULT_FILTER, FLOW_FILTER,  # noqa: E402
                                    sniff_observations)


def _de_cable(paquete):
    """Vuelve a diseccionar desde bytes, como el paquete que llega del cable.

    scapy deja `options=[("message-type", "offer")]` como texto en un paquete
    construido en memoria; del cable llega ya como entero 2.
    """
    return Ether(bytes(paquete))


def _paquete_arp(mac_dst: str = "ff:ff:ff:ff:ff:ff"):
    return Ether(src="aa:bb:cc:00:11:22", dst=mac_dst) / ScapyARP(
        op=2, hwsrc="aa:bb:cc:00:11:22", psrc="10.10.10.99",
        hwdst="3c:22:fb:11:22:33", pdst="10.10.10.50",
    )


def _paquete_dhcp():
    return (Ether(src="aa:bb:cc:00:11:22", dst="ff:ff:ff:ff:ff:ff") /
            IP(src="10.10.10.99", dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, yiaddr="10.10.10.50") /
            ScapyDHCP(options=[("message-type", "offer"), "end"]))


def _paquete_syn():
    return (Ether(src="aa:bb:cc:00:11:22", dst="3c:22:fb:11:22:33") /
            IP(src="10.10.10.99", dst="10.10.10.50") /
            TCP(sport=40000, dport=22, flags="S"))


# --------------------------------------------------------------------------- #
# Punto 1: promiscuo y punto 3: la interfaz llega a la observación
# --------------------------------------------------------------------------- #
def test_sniff_pide_modo_promiscuo_y_propaga_la_interfaz(monkeypatch):
    llamadas: list[dict] = []
    stop = threading.Event()
    paquete = _de_cable(_paquete_arp())

    def falso_sniff(**kwargs):
        llamadas.append(kwargs)
        kwargs["prn"](paquete)   # el sniffer entrega un paquete como lo haría scapy
        stop.set()               # una sola vuelta del bucle

    monkeypatch.setattr("scapy.all.sniff", falso_sniff)
    recibidas = []
    sniff_observations("sp0", recibidas.append, stop)

    assert len(llamadas) == 1
    assert llamadas[0]["promisc"] is True
    assert llamadas[0]["iface"] == "sp0"
    assert llamadas[0]["store"] is False
    assert len(recibidas) == 1
    assert recibidas[0].iface == "sp0"
    assert recibidas[0].kind == ARP


def test_sniff_no_pierde_el_bpf_por_defecto(monkeypatch):
    llamadas: list[dict] = []
    stop = threading.Event()

    def falso_sniff(**kwargs):
        llamadas.append(kwargs)
        stop.set()

    monkeypatch.setattr("scapy.all.sniff", falso_sniff)
    sniff_observations("sp0", lambda _obs: None, stop)

    assert llamadas[0]["filter"] == DEFAULT_FILTER


def test_sniff_usa_flow_filter_cuando_hay_on_packet(monkeypatch):
    llamadas: list[dict] = []
    stop = threading.Event()

    def falso_sniff(**kwargs):
        llamadas.append(kwargs)
        stop.set()

    monkeypatch.setattr("scapy.all.sniff", falso_sniff)
    sniff_observations("sp0", lambda _obs: None, stop,
                       on_packet=lambda _pkt, _ts: None)
    assert llamadas[0]["filter"] == FLOW_FILTER

    # Un BPF explícito siempre gana, incluso con on_packet activo.
    llamadas.clear()
    stop.clear()
    sniff_observations("sp0", lambda _obs: None, stop, bpf="arp",
                       on_packet=lambda _pkt, _ts: None)
    assert llamadas[0]["filter"] == "arp"


def test_observation_from_packet_ignora_tcp_sin_syn_y_udp_no_dhcp(monkeypatch):
    ack = _de_cable(
        Ether(src="aa:bb:cc:00:11:22", dst="3c:22:fb:11:22:33") /
        IP(src="10.10.10.99", dst="10.10.10.50") /
        TCP(sport=40000, dport=443, flags="PA")
    )
    dns = _de_cable(
        Ether(src="aa:bb:cc:00:11:22", dst="3c:22:fb:11:22:33") /
        IP(src="10.10.10.99", dst="10.10.10.1") /
        UDP(sport=51000, dport=53)
    )
    assert observation_from_packet(ack, 1000, iface="sp0") is None
    assert observation_from_packet(dns, 1000, iface="sp0") is None

    # En vivo con on_packet, el paquete crudo sí llega al motor de flujos
    # aunque no genere observación de reglas.
    crudos = []
    observaciones = []
    stop = threading.Event()

    def falso_sniff(**kwargs):
        kwargs["prn"](ack)
        kwargs["prn"](dns)
        stop.set()

    monkeypatch.setattr("scapy.all.sniff", falso_sniff)
    sniff_observations("sp0", observaciones.append, stop,
                       on_packet=lambda pkt, ts: crudos.append((pkt, ts)))

    assert len(crudos) == 2
    assert observaciones == []


# --------------------------------------------------------------------------- #
# Punto 2a: la interfaz en los tres tipos de observación
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("paquete, kind", [
    (_de_cable(_paquete_arp()), ARP),
    (_de_cable(_paquete_dhcp()), DHCP),
    (_de_cable(_paquete_syn()), SYN),
])
def test_observation_from_packet_rellena_la_interfaz(paquete, kind):
    obs = observation_from_packet(paquete, 1000, iface="sp0")
    assert obs is not None
    assert obs.kind == kind
    assert obs.iface == "sp0"


def test_el_replay_sin_interfaz_no_inventa_una():
    assert observation_from_packet(_de_cable(_paquete_arp()), 1000).iface is None


# --------------------------------------------------------------------------- #
# Punto 2b: tráfico ajeno al sensor también se observa (puerto espejo)
# --------------------------------------------------------------------------- #
def test_acepta_trafico_entre_terceros_que_no_va_al_sensor():
    paquete = (Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") /
               ScapyARP(op=1, hwsrc="00:11:22:33:44:55", psrc="10.10.10.20",
                        hwdst="00:00:00:00:00:00", pdst="10.10.10.30"))
    obs = observation_from_packet(paquete, 1000, iface="sp0")
    assert obs is not None
    assert (obs.ip_src, obs.ip_dst) == ("10.10.10.20", "10.10.10.30")


# --------------------------------------------------------------------------- #
# Punto 2c: flags solo en SYN
# --------------------------------------------------------------------------- #
def test_flags_solo_en_syn_y_op_en_arp_y_dhcp():
    syn = observation_from_packet(_de_cable(_paquete_syn()), 1000, iface="sp0")
    assert syn.flags == "S"

    arp = observation_from_packet(_de_cable(_paquete_arp()), 1000, iface="sp0")
    assert arp.flags == "" and arp.op == "reply"

    dhcp = observation_from_packet(_de_cable(_paquete_dhcp()), 1000, iface="sp0")
    assert dhcp.flags == "" and dhcp.op == "offer"


def test_observation_from_packet_recibe_iface_y_sensor_mac(monkeypatch):
    """Cada paquete llega al conversor con la interfaz y la MAC del sensor."""
    from tests.conftest import SENSOR_MAC

    recibidas: list[dict] = []
    real = observation_from_packet

    def espia(pkt, ts, iface=None, sensor_mac=None):
        recibidas.append({"iface": iface, "sensor_mac": sensor_mac})
        return real(pkt, ts, iface=iface, sensor_mac=sensor_mac)

    monkeypatch.setattr("batrade.detect.sniffer.observation_from_packet", espia)

    # Trama dirigida al sensor: además de la propagación prueba direction="in".
    paquete = Ether(src="00:50:56:aa:bb:01", dst=SENSOR_MAC) / ScapyARP(
        op=2, hwsrc="00:50:56:aa:bb:01", psrc="10.10.10.1",
        hwdst=SENSOR_MAC, pdst="10.10.10.200")

    stop = threading.Event()
    salida: list = []

    def falso_sniff(**kwargs):
        kwargs["prn"](paquete)
        stop.set()

    monkeypatch.setattr("scapy.all.sniff", falso_sniff)
    sniff_observations("sp0", salida.append, stop, sensor_mac=SENSOR_MAC)

    assert recibidas == [{"iface": "sp0", "sensor_mac": SENSOR_MAC}]
    assert salida[0].iface == "sp0"
    assert salida[0].direction == "in"

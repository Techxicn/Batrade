"""Escenarios sintéticos y replay de pcap (RNF-09).

Aquí está la razón por la que el MVP es demostrable sin CAP_NET_RAW: las mismas
detecciones se pueden alimentar desde un pcap grabado, desde tráfico sintético o
desde el sniffer real. Las tres rutas producen ``Observation`` idénticas.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable

from batrade.config import Config
from batrade.detect.observation import ARP, DHCP, SYN, Observation
from batrade.net.iputil import normalize_mac

BASE_TS = 1_760_000_000_000  # ancla fija para que los tests sean deterministas

GW_MAC = "00:0c:29:1b:2c:3d"
ATTACKER_MAC = "aa:bb:cc:00:11:22"
VICTIM_MAC = "3c:22:fb:11:22:33"
SENSOR_MAC = "00:50:56:ee:00:03"

SCENARIO_NAMES = ("arp_spoof", "arp_sweep", "syn_scan", "dhcp_rogue",
                  "router_reboot", "mixed")


class ScenarioContext:
    """Direcciones coherentes con la subred configurada."""

    def __init__(self, cfg: Config):
        net = ipaddress.IPv4Network(cfg.network.cidr, strict=False)
        hosts = list(net.hosts())
        self.gateway_ip = cfg.network.gateway_ip or (str(hosts[0]) if hosts else "192.168.1.1")
        self.sensor_ip = _pick(hosts, 200, fallback="192.168.1.200")
        self.attacker_ip = _pick(hosts, 66, fallback="192.168.1.66")
        self.victim_ip = _pick(hosts, 50, fallback="192.168.1.50")
        self.rogue_dhcp_ip = _pick(hosts, 99, fallback="192.168.1.99")
        self.gateway_mac = GW_MAC
        self.attacker_mac = ATTACKER_MAC
        self.victim_mac = VICTIM_MAC
        self.sensor_mac = SENSOR_MAC


def _pick(hosts: list, index: int, fallback: str) -> str:
    if not hosts:
        return fallback
    return str(hosts[min(index, len(hosts) - 1)])


def _ctx(cfg: Config) -> ScenarioContext:
    return ScenarioContext(cfg)


# --------------------------------------------------------------------------- #
# Escenarios
# --------------------------------------------------------------------------- #
def synthetic(name: str, cfg: Config, base_ts: int = BASE_TS) -> list[Observation]:
    """Genera la secuencia de observaciones de un escenario."""
    if name not in SCENARIO_NAMES:
        raise ValueError(f"escenario desconocido: {name!r} (válidos: {', '.join(SCENARIO_NAMES)})")
    c = _ctx(cfg)
    if name == "arp_spoof":
        return _arp_spoof(c, base_ts)
    if name == "arp_sweep":
        return _arp_sweep(c, base_ts)
    if name == "syn_scan":
        return _syn_scan(c, base_ts)
    if name == "dhcp_rogue":
        return _dhcp_rogue(c, base_ts)
    if name == "router_reboot":
        return _router_reboot(c, base_ts)
    return (_arp_spoof(c, base_ts) + _arp_sweep(c, base_ts + 120_000)
            + _syn_scan(c, base_ts + 240_000))


def _arp(c: ScenarioContext, ts: int, *, ip_src: str, mac_src: str, ip_dst: str,
         mac_dst: str, op: str, gratuitous: bool = False) -> Observation:
    return Observation(kind=ARP, ts=ts, ip_src=ip_src, mac_src=normalize_mac(mac_src),
                       ip_dst=ip_dst, mac_dst=mac_dst, op=op,
                       extra={"gratuitous": gratuitous})


def _baseline_traffic(c: ScenarioContext, ts: int) -> list[Observation]:
    """Tráfico normal previo: el gateway responde por su IP y un host la suya."""
    return [
        _arp(c, ts, ip_src=c.gateway_ip, mac_src=c.gateway_mac, ip_dst=c.sensor_ip,
             mac_dst=c.sensor_mac, op="reply"),
        _arp(c, ts + 500, ip_src=c.victim_ip, mac_src=c.victim_mac, ip_dst=c.gateway_ip,
             mac_dst=c.gateway_mac, op="reply"),
    ]


def _arp_spoof(c: ScenarioContext, ts: int) -> list[Observation]:
    obs = _baseline_traffic(c, ts)
    # El atacante se anuncia como el gateway (gratuitous ARP) y responde por él.
    for i in range(6):
        obs.append(_arp(c, ts + 10_000 + i * 400, ip_src=c.gateway_ip,
                        mac_src=c.attacker_mac, ip_dst=c.gateway_ip,
                        mac_dst="ff:ff:ff:ff:ff:ff", op="reply", gratuitous=True))
    # Y además contesta al sensor haciéndose pasar por el gateway.
    for i in range(4):
        obs.append(_arp(c, ts + 12_000 + i * 300, ip_src=c.gateway_ip,
                        mac_src=c.attacker_mac, ip_dst=c.sensor_ip,
                        mac_dst=c.sensor_mac, op="reply"))
    return obs


def _arp_sweep(c: ScenarioContext, ts: int) -> list[Observation]:
    obs: list[Observation] = []
    base = ipaddress.IPv4Address(c.victim_ip)
    for i in range(40):
        target = str(base + i + 1)
        obs.append(_arp(c, ts + i * 120, ip_src=c.attacker_ip, mac_src=c.attacker_mac,
                        ip_dst=target, mac_dst="00:00:00:00:00:00", op="request"))
    return obs


def _syn_scan(c: ScenarioContext, ts: int) -> list[Observation]:
    """Escaneo de puertos a un host + barrido de hosts (lo que ve el señuelo)."""
    obs: list[Observation] = []
    for i, port in enumerate(range(1, 121)):
        obs.append(Observation(kind=SYN, ts=ts + i * 25,
                               ip_src=c.attacker_ip, mac_src=c.attacker_mac,
                               ip_dst=c.victim_ip, port_dst=port,
                               extra={"flags": "S"}))
    base = ipaddress.IPv4Address(c.victim_ip)
    for i in range(30):
        obs.append(Observation(kind=SYN, ts=ts + 3_200 + i * 50,
                               ip_src=c.attacker_ip, mac_src=c.attacker_mac,
                               ip_dst=str(base - 20 + i), port_dst=80,
                               extra={"flags": "S"}))
    return obs


def _dhcp_rogue(c: ScenarioContext, ts: int) -> list[Observation]:
    return [
        Observation(kind=DHCP, ts=ts, ip_src=c.gateway_ip, mac_src=c.gateway_mac,
                    op="offer", extra={"yiaddr": c.victim_ip, "msg_type": 2}),
        Observation(kind=DHCP, ts=ts + 5_000, ip_src=c.rogue_dhcp_ip,
                    mac_src=c.attacker_mac, op="offer",
                    extra={"yiaddr": c.victim_ip, "msg_type": 2}),
    ]


def _router_reboot(c: ScenarioContext, ts: int) -> list[Observation]:
    """Falso positivo a evitar (PA-05): ráfaga gratuita con la MAC correcta."""
    obs: list[Observation] = []
    for i in range(60):
        obs.append(_arp(c, ts + i * 50, ip_src=c.gateway_ip, mac_src=c.gateway_mac,
                        ip_dst=c.gateway_ip, mac_dst="ff:ff:ff:ff:ff:ff",
                        op="reply", gratuitous=True))
    for i in range(10):
        obs.append(_arp(c, ts + 4_000 + i * 80, ip_src=c.victim_ip,
                        mac_src=c.victim_mac, ip_dst=c.gateway_ip,
                        mac_dst=c.gateway_mac, op="reply"))
    return obs


# --------------------------------------------------------------------------- #
# pcap: escritura (fixtures) y lectura (replay)
# --------------------------------------------------------------------------- #
def write_pcap(scenario: str, path: str, cfg: Config, base_ts: int = BASE_TS) -> str:
    """Materializa un escenario como .pcap real para probar la ruta de sniffer."""
    from scapy.all import ARP as ScapyARP
    from scapy.all import (BOOTP, DHCP as ScapyDHCP, Ether, IP, TCP, UDP,  # noqa: F401
                           wrpcap)

    c = _ctx(cfg)
    packets = []
    t0 = base_ts / 1000.0
    for obs in synthetic(scenario, cfg, base_ts):
        rel = (obs.ts - base_ts) / 1000.0
        if obs.kind == ARP:
            pkt = Ether(src=obs.mac_src, dst=obs.mac_dst or "ff:ff:ff:ff:ff:ff") / ScapyARP(
                op=2 if obs.op == "reply" else 1, hwsrc=obs.mac_src, psrc=obs.ip_src,
                hwdst=obs.mac_dst or "00:00:00:00:00:00", pdst=obs.ip_dst,
            )
        elif obs.kind == SYN:
            pkt = (Ether(src=obs.mac_src, dst="ff:ff:ff:ff:ff:ff") /
                   IP(src=obs.ip_src, dst=obs.ip_dst) /
                   TCP(sport=40000 + (obs.port_dst or 0), dport=obs.port_dst, flags="S"))
        elif obs.kind == DHCP:
            pkt = (Ether(src=obs.mac_src, dst="ff:ff:ff:ff:ff:ff") /
                   IP(src=obs.ip_src, dst="255.255.255.255") /
                   UDP(sport=67, dport=68) /
                   BOOTP(op=2, yiaddr=obs.extra.get("yiaddr", "0.0.0.0")) /
                   ScapyDHCP(options=[("message-type", "offer"), "end"]))
        else:
            continue
        pkt.time = t0 + rel
        packets.append(pkt)
    if not packets:
        raise ValueError(f"el escenario {scenario!r} no produjo paquetes")
    packets.sort(key=lambda p: p.time)
    wrpcap(path, packets)
    return path


def _direction(pkt, sensor_mac: str | None) -> str | None:
    """``in``/``out`` respecto al sensor, o ``None`` si la trama no es suya.

    Sólo se puede afirmar cuando la MAC del sensor aparece en la trama. En un
    puerto espejo la mayor parte del tráfico es de terceros, y el switch no nos
    dice por qué puerto entró: ahí se deja ``None`` en vez de inventar un valor.
    """
    if not sensor_mac:
        return None
    from scapy.all import Ether
    if not pkt.haslayer(Ether):
        return None
    propio = normalize_mac(sensor_mac)
    if normalize_mac(pkt[Ether].dst) == propio:
        return "in"
    if normalize_mac(pkt[Ether].src) == propio:
        return "out"
    return None


def observation_from_packet(pkt, ts: int, iface: str | None = None,
                            sensor_mac: str | None = None) -> Observation | None:
    """Traduce un paquete scapy a observación normalizada. None si no interesa.

    ``iface`` es la interfaz por la que se capturó (el puerto espejo); en replay
    de pcap no hay una sola interfaz viva y se deja en ``None``. ``sensor_mac``
    sólo sirve para etiquetar la dirección; sin él, ``direction`` queda en None.
    """
    from scapy.all import ARP as ScapyARP
    from scapy.all import BOOTP, DHCP as ScapyDHCP, IP, TCP

    direction = _direction(pkt, sensor_mac)
    if pkt.haslayer(ScapyARP):
        arp = pkt[ScapyARP]
        return Observation(
            kind=ARP, ts=ts, iface=iface, ip_src=str(arp.psrc),
            mac_src=normalize_mac(arp.hwsrc),
            ip_dst=str(arp.pdst), mac_dst=normalize_mac(arp.hwdst),
            op="reply" if int(arp.op) == 2 else "request",
            extra={"gratuitous": str(arp.psrc) == str(arp.pdst)},
            direction=direction,
        )
    if pkt.haslayer(BOOTP) and pkt.haslayer(ScapyDHCP):
        try:
            mtype = int(pkt[ScapyDHCP].options[0][1])
        except (IndexError, TypeError, ValueError):
            mtype = 0
        if mtype in (2, 5):  # OFFER / ACK
            return Observation(
                kind=DHCP, ts=ts, iface=iface, ip_src=pkt[IP].src,
                mac_src=normalize_mac(pkt.src),
                op="offer" if mtype == 2 else "ack",
                extra={"yiaddr": str(pkt[BOOTP].yiaddr), "msg_type": mtype},
                direction=direction,
            )
        return None
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        tcp = pkt[TCP]
        return Observation(
            kind=SYN, ts=ts, iface=iface, ip_src=pkt[IP].src,
            mac_src=normalize_mac(pkt.src),
            ip_dst=pkt[IP].dst, port_dst=int(tcp.dport),
            extra={"flags": str(tcp.flags)},
            direction=direction,
        )
    return None


def write_baseline_pcap(path: str, cfg: Config, base_ts: int = BASE_TS,
                        clientes: int = 30, semilla: int = 7) -> str:
    """Escribe un pcap de **tráfico normal** para entrenar el motor de flujos.

    Sesiones TCP completas con huecos irregulares, consultas DNS y ARP: lo que
    un hogar produce sin atacante. Determinista para una ``semilla``. No usa
    ``write_pcap`` porque ése materializa escenarios de ataque, y aquí hacen
    falta respuestas (SYN-ACK, ACK, FIN) que un escenario de escaneo no tiene.
    """
    import random

    from scapy.all import ARP as ScapyARP
    from scapy.all import TCP, UDP, Ether, IP, Raw, wrpcap

    c = _ctx(cfg)
    rng = random.Random(semilla)
    paquetes = []
    t = base_ts / 1000.0
    cliente_base = int(ipaddress.IPv4Address(c.victim_ip))

    def empujar(pkt, retardo_ms: int) -> None:
        nonlocal t
        t += retardo_ms / 1000.0
        pkt.time = t
        paquetes.append(pkt)

    def sesion(cliente: str, servidor: str, sport: int, dport: int) -> None:
        mac_cli, mac_srv = c.victim_mac, GW_MAC
        huecos = [rng.choice([70, 90, 120, 150, 200, 260, 340, 420]) for _ in range(6)]
        cuerpo = bytes(rng.randrange(100, 1200) % 256 for _ in range(
            rng.randrange(120, 1400)))
        tcp_cli = dict(sport=sport, dport=dport)
        tcp_srv = dict(sport=dport, dport=sport)
        empujar(Ether(src=mac_cli, dst=mac_srv) / IP(src=cliente, dst=servidor) /
                TCP(flags="S", **tcp_cli), 0)
        empujar(Ether(src=mac_srv, dst=mac_cli) / IP(src=servidor, dst=cliente) /
                TCP(flags="SA", **tcp_srv), huecos[0])
        empujar(Ether(src=mac_cli, dst=mac_srv) / IP(src=cliente, dst=servidor) /
                TCP(flags="A", **tcp_cli), huecos[1])
        empujar(Ether(src=mac_cli, dst=mac_srv) / IP(src=cliente, dst=servidor) /
                TCP(flags="PA", **tcp_cli) / Raw(cuerpo), huecos[2])
        empujar(Ether(src=mac_srv, dst=mac_cli) / IP(src=servidor, dst=cliente) /
                TCP(flags="A", **tcp_srv), huecos[3])
        empujar(Ether(src=mac_srv, dst=mac_cli) / IP(src=servidor, dst=cliente) /
                TCP(flags="FA", **tcp_srv) / Raw(cuerpo[: rng.randrange(40, 400)]),
                huecos[4])
        empujar(Ether(src=mac_cli, dst=mac_srv) / IP(src=cliente, dst=servidor) /
                TCP(flags="A", **tcp_cli), huecos[5])

    for i in range(clientes):
        cliente = str(ipaddress.IPv4Address(cliente_base + i))
        puerto = 40000 + i
        sesion(cliente, str(ipaddress.IPv4Address(cliente_base + 120)), puerto, 80)
        sesion(cliente, str(ipaddress.IPv4Address(cliente_base + 121)), puerto + 500, 443)
        # DNS: pregunta y respuesta.
        empujar(Ether(src=c.victim_mac, dst=GW_MAC) / IP(src=cliente, dst=c.gateway_ip) /
                UDP(sport=50000 + i, dport=53) / Raw(b"\x12\x34" + bytes(28)), 60)
        empujar(Ether(src=GW_MAC, dst=c.victim_mac) / IP(src=c.gateway_ip, dst=cliente) /
                UDP(sport=53, dport=50000 + i) / Raw(bytes(80)), 40)
        # ARP del cliente preguntando por el gateway.
        empujar(Ether(src=c.victim_mac, dst="ff:ff:ff:ff:ff:ff") /
                ScapyARP(op=1, hwsrc=c.victim_mac, psrc=cliente,
                         hwdst="00:00:00:00:00:00", pdst=c.gateway_ip), 30)

    paquetes.sort(key=lambda p: p.time)
    wrpcap(path, paquetes)
    return path


def observations_from_pcap(path: str, speed: float = 0.0,
                           base_ts: int | None = None) -> list[Observation]:
    """Convierte un pcap en observaciones. ``speed`` 0 = mantener timestamps."""
    from scapy.all import PcapReader

    obs: list[Observation] = []
    first: float | None = None
    for pkt in PcapReader(path):
        try:
            ts_real = float(pkt.time)
        except (TypeError, ValueError):
            ts_real = 0.0
        if first is None:
            first = ts_real
        if base_ts is not None:
            scale = 1.0 / speed if speed and speed > 0 else 1.0
            ts = base_ts + int((ts_real - first) * 1000 * scale)
        else:
            ts = int(ts_real * 1000)
        converted = observation_from_packet(pkt, ts)
        if converted is not None:
            obs.append(converted)
    return obs


def scenario_duration_ms(observations: Iterable[Observation]) -> int:
    ts = [o.ts for o in observations]
    return max(ts) - min(ts) if ts else 0

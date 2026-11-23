"""Motor de flujos: colector, características, scorer y cableado del sniffer."""
from __future__ import annotations

import dataclasses
import json
import threading
import time
from typing import Any

import pytest

scapy_all = pytest.importorskip("scapy.all")
Ether = scapy_all.Ether
IP = scapy_all.IP
TCP = scapy_all.TCP
UDP = scapy_all.UDP
ICMP = scapy_all.ICMP
Raw = scapy_all.Raw

from batrade import db  # noqa: E402
from batrade.config import ConfigError, load_config  # noqa: E402
from batrade.flow import (DummyScorer, Flow, FlowCollector, FlowEngine,  # noqa: E402
                          FlowFeatures, Scorer, extract)
from batrade.detect.sniffer import sniff_observations  # noqa: E402
from batrade.sensor import Sensor  # noqa: E402

from tests.conftest import SENSOR_MAC  # noqa: E402


def _tcp(src: str, sport: int, dst: str, dport: int, flags: str = "S",
         carga: int = 0):
    paquete = (Ether(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02") /
               IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags))
    if carga:
        paquete = paquete / Raw(b"x" * carga)
    return Ether(bytes(paquete))          # como llega del cable


def _udp(src: str, sport: int, dst: str, dport: int):
    return Ether(bytes(Ether(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02") /
                       IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)))


def _flujo_lleno(**cambios) -> Flow:
    datos: dict[str, Any] = dict(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=40000,
                 dst_port=22, proto="tcp", ts_start=0, ts_end=500,
                 packets=4, bytes=240, syn_count=1, rst_count=0, fin_count=0,
                 ack_count=2, packet_sizes=[60, 60, 60, 60],
                 inter_arrival_ms=[100, 200, 200], bytes_src=180, bytes_dst=60)
    datos.update(cambios)
    return Flow(**datos)


# --------------------------------------------------------------------------- #
# Colector
# --------------------------------------------------------------------------- #
def test_collector_agrupa_por_cinco_tupla():
    colector = FlowCollector(window_s=60)
    assert colector.add(_tcp("10.0.0.1", 40000, "10.0.0.2", 22), 1000) == []
    colector.add(_tcp("10.0.0.1", 40000, "10.0.0.2", 22), 1500)
    colector.add(_tcp("10.0.0.1", 40001, "10.0.0.2", 22), 1600)
    colector.add(_udp("10.0.0.1", 40000, "10.0.0.2", 53), 1700)

    assert colector.abiertos == 3
    flujos = {(f.proto, f.src_port): f for f in colector.flush()}
    assert flujos[("tcp", 40000)].packets == 2
    assert flujos[("tcp", 40000)].inter_arrival_ms == [500]
    assert flujos[("tcp", 40001)].packets == 1
    assert flujos[("udp", 40000)].packets == 1


def test_collector_cierra_al_cumplir_la_ventana():
    colector = FlowCollector(window_s=1)          # 1000 ms
    colector.add(_tcp("10.0.0.1", 1111, "10.0.0.2", 22), 1000)
    cerrados = colector.add(_tcp("10.0.0.3", 2222, "10.0.0.4", 80), 2001)

    assert [f.src_port for f in cerrados] == [1111]
    assert cerrados[0].ts_end == 1000
    assert colector.abiertos == 1


def test_collector_flush_devuelve_lo_abierto_y_vacia():
    colector = FlowCollector(window_s=60)
    colector.add(_tcp("10.0.0.1", 1111, "10.0.0.2", 22), 1000)
    assert len(colector.flush(ts=1500)) == 1
    assert colector.abiertos == 0
    assert colector.flush() == []


def test_flujo_bidireccional_junta_ida_y_vuelta():
    colector = FlowCollector(window_s=60)
    colector.add(_tcp("10.0.0.1", 40000, "10.0.0.2", 80, "S"), 1000)
    colector.add(_tcp("10.0.0.2", 80, "10.0.0.1", 40000, "SA"), 1010)
    flujo = colector.flush()[0]

    assert flujo.packets == 2
    assert flujo.src_ip == "10.0.0.1"      # el iniciador manda
    assert flujo.bytes_src > 0 and flujo.bytes_dst > 0
    assert flujo.syn_count == 2            # SYN y SYN-ACK llevan el bit S
    assert flujo.ack_count == 1


def test_collector_ignora_lo_que_no_es_tcp_udp_ni_arp():
    colector = FlowCollector(window_s=60)
    icmp = Ether(bytes(Ether(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02") /
                       IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()))
    assert colector.add(icmp, 1000) == []
    assert colector.abiertos == 0


def test_collector_cuenta_arp():
    colector = FlowCollector(window_s=60)
    from scapy.all import ARP as ScapyARP
    arp = Ether(bytes(Ether(src="aa:bb:cc:00:00:01", dst="ff:ff:ff:ff:ff:ff") /
                      ScapyARP(op=1, psrc="10.0.0.1", pdst="10.0.0.2")))
    colector.add(arp, 1000)
    flujo = colector.flush()[0]
    assert flujo.proto == "arp" and flujo.packets == 1


# --------------------------------------------------------------------------- #
# Características
# --------------------------------------------------------------------------- #
def test_features_devuelve_las_claves_esperadas():
    caracteristicas = extract(_flujo_lleno())
    assert isinstance(caracteristicas, FlowFeatures)
    assert set(dataclasses.asdict(caracteristicas)) == {
        "packets", "bytes", "bytes_por_direccion", "tamano_medio",
        "desviacion_estandar_tiempo_entre_paquetes", "ratio_syn_ack",
        "puertos_distintos_por_ip_origen", "destinos_distintos_por_ip_origen",
    }
    assert caracteristicas.packets == 4
    assert caracteristicas.tamano_medio == 60.0
    assert caracteristicas.bytes_por_direccion == {"10.0.0.1": 180, "10.0.0.2": 60}
    assert caracteristicas.ratio_syn_ack == 0.5
    assert caracteristicas.desviacion_estandar_tiempo_entre_paquetes > 0
    json.dumps(dataclasses.asdict(caracteristicas))     # serializable para el evento


def test_features_con_flujo_vacio_no_revienta():
    vacio = Flow(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1,
                 dst_port=2, proto="tcp", ts_start=0)
    caracteristicas = extract(vacio)
    assert caracteristicas.packets == 0
    assert caracteristicas.tamano_medio == 0.0
    assert caracteristicas.ratio_syn_ack == 0.0
    assert caracteristicas.desviacion_estandar_tiempo_entre_paquetes == 0.0
    assert caracteristicas.bytes_por_direccion == {}


def test_ratio_syn_ack_sin_acks_es_el_numero_de_syn():
    escaneo = _flujo_lleno(syn_count=12, ack_count=0)
    assert extract(escaneo).ratio_syn_ack == 12.0


# --------------------------------------------------------------------------- #
# Scorer y motor
# --------------------------------------------------------------------------- #
class _TodoAnomalo(Scorer):
    def fit(self, flows_normales):
        return None

    def score(self, flow):
        return 1.0


def _config_con_motor(tmp_path, **flow):
    ruta = tmp_path / "smoke.yaml"
    ruta.write_text(
        "network: { interface: lo, cidr: 10.0.0.0/24 }\n"
        "flow: { enabled: true, window_s: 1, anomaly_threshold: 0.5 }\n"
        if not flow else
        "network: { interface: lo, cidr: 10.0.0.0/24 }\n"
        f"flow: {flow}\n",
        encoding="utf-8")
    return load_config(ruta, tmp_path)


def test_dummy_scorer_devuelve_cero():
    scorer = DummyScorer()
    scorer.fit([_flujo_lleno()])
    assert scorer.score(_flujo_lleno()) == 0.0


def test_el_motor_con_dummy_no_emite(tmp_path):
    motor = FlowEngine(_config_con_motor(tmp_path))
    assert motor._evaluar(_flujo_lleno()) is None
    assert motor.emitted == []


def test_el_motor_emite_flow_anomaly_cuando_supera_el_umbral(tmp_path):
    capturados = []
    motor = FlowEngine(_config_con_motor(tmp_path), scorer=_TodoAnomalo(),
                       on_finding=capturados.append)
    hallazgo = motor._evaluar(_flujo_lleno())

    assert hallazgo is not None and capturados == [hallazgo]
    assert hallazgo.tipo == "flow_anomaly"
    assert hallazgo.severidad == "warn"
    assert hallazgo.clave == "flow:10.0.0.1:10.0.0.2:22"
    assert {"resumen", "por_que", "accion", "features"} <= set(hallazgo.detalle)
    assert hallazgo.detalle["features"]["packets"] == 4
    json.dumps(hallazgo.detalle)          # el evento se guarda como JSON


def test_el_motor_procesa_la_cola_y_entrega_el_hallazgo(tmp_path):
    recibidos = []
    motor = FlowEngine(_config_con_motor(tmp_path), scorer=_TodoAnomalo(),
                       on_finding=recibidos.append)
    motor.start()
    try:
        motor.enqueue(_tcp("10.0.0.1", 40000, "10.0.0.2", 22), 1000)
        limite = time.time() + 3
        while not recibidos and time.time() < limite:
            time.sleep(0.02)
    finally:
        motor.stop()

    assert recibidos and recibidos[0].tipo == "flow_anomaly"
    assert motor._hilo is None            # stop() une el hilo y lo olvida


def test_el_motor_descarta_sin_bloquear_con_la_cola_llena(tmp_path):
    motor = FlowEngine(_config_con_motor(tmp_path))
    motor.cola = __import__("queue").Queue(maxsize=1)
    assert motor.enqueue(object(), 1000) is True
    assert motor.enqueue(object(), 1001) is False
    assert motor.descartados == 1


# --------------------------------------------------------------------------- #
# Sniffer: on_packet opcional
# --------------------------------------------------------------------------- #
def _arp_a_terceros():
    from scapy.all import ARP as ScapyARP
    return Ether(bytes(Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") /
                       ScapyARP(op=1, hwsrc="00:11:22:33:44:55", psrc="10.0.0.20",
                                pdst="10.0.0.30")))


def _sniff_una_vez(monkeypatch, **kwargs):
    paquete = _arp_a_terceros()
    stop = threading.Event()

    def falso_sniff(**kw):
        kw["prn"](paquete)
        stop.set()

    monkeypatch.setattr("scapy.all.sniff", falso_sniff)
    salida = []
    sniff_observations("sp0", salida.append, stop, **kwargs)
    return salida


def test_sin_on_packet_el_sniffer_se_comporta_igual(monkeypatch):
    salida = _sniff_una_vez(monkeypatch, sensor_mac=SENSOR_MAC)
    assert len(salida) == 1
    assert salida[0].iface == "sp0"
    assert salida[0].kind == "arp"


def test_on_packet_recibe_el_paquete_crudo_antes_de_convertir(monkeypatch):
    orden = []
    import batrade.detect.sniffer as sniffer_mod

    real = sniffer_mod.observation_from_packet

    def espia_convertir(pkt, ts, iface=None, sensor_mac=None):
        orden.append("convertir")
        return real(pkt, ts, iface=iface, sensor_mac=sensor_mac)

    monkeypatch.setattr(sniffer_mod, "observation_from_packet", espia_convertir)
    salida = _sniff_una_vez(monkeypatch, on_packet=lambda pkt, ts: orden.append("crudo"))

    assert orden == ["crudo", "convertir"]
    assert len(salida) == 1


def test_un_on_packet_roto_no_tumba_la_captura(monkeypatch):
    def revienta(_pkt, _ts):
        raise RuntimeError("consumidor roto")

    salida = _sniff_una_vez(monkeypatch, on_packet=revienta)
    assert len(salida) == 1          # la observación sigue su camino


# --------------------------------------------------------------------------- #
# Configuración
# --------------------------------------------------------------------------- #
def test_flow_apagado_por_defecto(cfg):
    assert cfg.flow.enabled is False
    assert cfg.flow.window_s == 60
    assert cfg.flow.anomaly_threshold == 0.99


@pytest.mark.parametrize("bloque", ["window_s: 0", "window_s: 7200",
                                    "anomaly_threshold: 1.5",
                                    "anomaly_threshold: -0.1"])
def test_flow_con_valores_fuera_de_rango_es_error(tmp_path, bloque):
    ruta = tmp_path / "malo.yaml"
    ruta.write_text("network: { interface: lo, cidr: 10.0.0.0/24 }\n"
                    f"flow: {{ {bloque} }}\n", encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        load_config(ruta, tmp_path)
    assert any("flow." in e for e in exc.value.errors)


# --------------------------------------------------------------------------- #
# Cableado del sensor
# --------------------------------------------------------------------------- #
class _SensorTonto:
    def __init__(self, cfg):
        self.cfg = cfg
        self.stop_event = threading.Event()
        self.sensor_mac = SENSOR_MAC
        self.flow_engine = None

    def _conn(self):
        return db.connect(self.cfg.paths.db)

    def _note_observation(self, kind, ts):
        pass

    def _on_flow_finding(self, finding):
        pass


def _sniff_loop_con_espia(cfg, monkeypatch):
    llamadas: list[dict] = []

    def falso_sniff(iface, on_observation, stop_event, sensor_mac=None,
                    on_packet=None):
        llamadas.append({"on_packet": on_packet})

    monkeypatch.setattr("batrade.detect.sniffer.sniff_observations", falso_sniff)
    tonto = _SensorTonto(cfg)
    Sensor._sniff_loop(tonto)
    return llamadas, tonto


def test_el_sensor_no_crea_motor_si_flow_esta_apagado(cfg, monkeypatch):
    llamadas, tonto = _sniff_loop_con_espia(cfg, monkeypatch)
    assert llamadas == [{"on_packet": None}]
    assert tonto.flow_engine is None


def test_el_sensor_arranca_y_para_el_motor_cuando_esta_activo(cfg, monkeypatch):
    cfg.flow.enabled = True
    creados = []

    class _MotorFalso:
        def __init__(self, _cfg, on_finding=None):
            self.arrancado = self.parado = False
            self.on_finding = on_finding
            creados.append(self)

        def start(self):
            self.arrancado = True

        def stop(self):
            self.parado = True

        def enqueue(self, packet, ts):
            return True

    monkeypatch.setattr("batrade.flow.FlowEngine", _MotorFalso)
    llamadas, tonto = _sniff_loop_con_espia(cfg, monkeypatch)

    assert len(creados) == 1
    assert creados[0].arrancado and creados[0].parado
    assert llamadas[0]["on_packet"] == creados[0].enqueue
    assert tonto.flow_engine is None       # se limpia al salir del bucle

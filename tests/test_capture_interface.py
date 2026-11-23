"""Interfaz de captura (puerto espejo) y dirección de la observación."""
from __future__ import annotations

import threading
from pathlib import Path
from typing import cast

import pytest

scapy_all = pytest.importorskip("scapy.all")
ScapyARP = scapy_all.ARP
Ether = scapy_all.Ether

from batrade import cli, db
from batrade.config import ConfigError, load_config
from batrade.detect.observation import ARP, Observation
from batrade.net.ifaces import IfaceInfo, find as find_real
from batrade.net import ifaces as ifaces_mod
from batrade.net.discovery import Discovery
from batrade.sensor import Sensor

from tests.conftest import SENSOR_MAC


def _yaml(tmp_path, red: str, extra: str = "") -> Path:
    ruta = tmp_path / "c.yaml"
    ruta.write_text(f"network:\n{red}\n{extra}", encoding="utf-8")
    return ruta


def _falsas(monkeypatch, **extras: IfaceInfo) -> None:
    """Añade interfaces inventadas al `find` real (lo demás sigue existiendo)."""
    def falso(nombre):
        if nombre in extras:
            return extras[nombre]
        return find_real(nombre)
    monkeypatch.setattr(ifaces_mod, "find", falso)


# --------------------------------------------------------------------------- #
# config: resolución y validación
# --------------------------------------------------------------------------- #
def test_capture_interface_null_usa_la_de_gestion(cfg):
    assert cfg.network.capture_interface == cfg.network.interface
    assert cfg.capture_explicit is False


def test_capture_interface_explicita_se_resuelve(tmp_path, monkeypatch):
    _falsas(monkeypatch, sp0=IfaceInfo(name="sp0", ip=None, up=True))
    cfg = load_config(_yaml(tmp_path, "  interface: lo\n  cidr: 10.10.10.0/24\n"
                                     "  capture_interface: sp0\n"), tmp_path)
    assert cfg.network.capture_interface == "sp0"
    assert cfg.network.interface == "lo"          # la de gestión no cambia
    assert cfg.capture_explicit is True


def test_capture_interface_inexistente_es_error(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load_config(_yaml(tmp_path, "  interface: lo\n  cidr: 10.10.10.0/24\n"
                                    "  capture_interface: sp9\n"), tmp_path)
    assert any("capture_interface inexistente" in e for e in exc.value.errors)


def test_capture_interface_loopback_es_error(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load_config(_yaml(tmp_path, "  interface: lo\n  cidr: 10.10.10.0/24\n"
                                    "  capture_interface: lo\n"), tmp_path)
    assert any("loopback" in e for e in exc.value.errors)


# --------------------------------------------------------------------------- #
# sensor: el sniffer usa la de captura
# --------------------------------------------------------------------------- #
class _SensorTonto:
    """Lo mínimo que toca `_sniff_loop` antes de entregar el control al sniffer."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.stop_event = threading.Event()
        self.sensor_mac = SENSOR_MAC
        self._lock = threading.Lock()

    def _conn(self):
        return db.connect(self.cfg.paths.db)

    def _note_observation(self, kind, ts):
        pass


def test_el_sniffer_usa_la_interfaz_de_captura(cfg, monkeypatch):
    cfg.network.capture_interface = "sp0"
    llamadas = []

    def falso_sniff(iface, on_observation, stop_event, sensor_mac=None,
                    on_packet=None):
        llamadas.append({"iface": iface, "sensor_mac": sensor_mac,
                         "on_packet": on_packet})

    monkeypatch.setattr("batrade.detect.sniffer.sniff_observations", falso_sniff)
    Sensor._sniff_loop(cast(Sensor, _SensorTonto(cfg)))

    assert llamadas == [{"iface": "sp0", "sensor_mac": SENSOR_MAC,
                         "on_packet": None}]


def test_el_sniffer_cae_en_la_de_gestion_si_no_hay_captura(cfg, monkeypatch):
    llamadas = []

    def falso_sniff(iface, on_observation, stop_event, sensor_mac=None,
                    on_packet=None):
        llamadas.append(iface)

    monkeypatch.setattr("batrade.detect.sniffer.sniff_observations", falso_sniff)
    Sensor._sniff_loop(cast(Sensor, _SensorTonto(cfg)))

    assert llamadas == [cfg.network.interface]


# --------------------------------------------------------------------------- #
# discovery: captura si puede transmitir, gestión si no
# --------------------------------------------------------------------------- #
def test_discovery_usa_la_captura_cuando_tiene_ip(cfg, monkeypatch):
    cfg.network.capture_interface = "sp0"
    _falsas(monkeypatch, sp0=IfaceInfo(name="sp0", ip="10.10.10.201", prefixlen=24))
    assert Discovery(cfg).iface == "sp0"


def test_discovery_usa_la_gestion_si_la_captura_no_tiene_ip(cfg, monkeypatch):
    cfg.network.capture_interface = "sp0"
    _falsas(monkeypatch, sp0=IfaceInfo(name="sp0", ip=None, up=True))
    assert Discovery(cfg).iface == cfg.network.interface


# --------------------------------------------------------------------------- #
# doctor: muestra ambas y avisa
# --------------------------------------------------------------------------- #
def test_doctor_muestra_ambas_interfaces(cfg, capsys, monkeypatch):
    cfg.network.capture_interface = "sp0"
    _falsas(monkeypatch, sp0=IfaceInfo(name="sp0", ip=None, up=True))
    cli.cmd_doctor(cfg, None)
    salida = capsys.readouterr().out

    assert f"interfaz        : {cfg.network.interface}" in salida
    assert "captura         : sp0 (sin IPv4 (normal en puerto espejo))" in salida
    assert "sp0 no tiene IPv4 (normal en espejo)" in salida


def test_doctor_avisa_si_captura_es_igual_a_gestion(cfg, capsys):
    cfg.capture_explicit = True   # el fixture la deja en null: esto simula YAML explícito
    cli.cmd_doctor(cfg, None)
    salida = capsys.readouterr().out

    assert "captura         : " in salida
    assert "misma que la de gestión" in salida
    assert "es igual a network.interface" in salida


def test_doctor_no_avisa_cuando_la_captura_es_el_valor_por_defecto(cfg, capsys):
    cli.cmd_doctor(cfg, None)     # capture_interface: null, sin YAML explícito
    salida = capsys.readouterr().out

    assert "misma que la de gestión" in salida
    assert "es igual a network.interface" not in salida


def test_doctor_no_avisa_cuando_la_captura_tiene_ip(cfg, capsys, monkeypatch):
    cfg.network.capture_interface = "sp0"
    _falsas(monkeypatch, sp0=IfaceInfo(name="sp0", ip="10.10.10.201", prefixlen=24))
    cli.cmd_doctor(cfg, None)
    salida = capsys.readouterr().out

    assert "sp0 (10.10.10.201/24, ethernet)" in salida
    assert "no tiene IPv4" not in salida


# --------------------------------------------------------------------------- #
# Observation.direction
# --------------------------------------------------------------------------- #
def test_observation_acepta_direction_y_por_defecto_es_none():
    assert Observation(kind=ARP, ts=1).direction is None
    assert Observation(kind=ARP, ts=1, direction="in").direction == "in"


def test_las_observaciones_viejas_siguen_construyendose_igual():
    obs = Observation(kind=ARP, ts=1000, ip_src="10.10.10.1", mac_src="00:50:56:aa:bb:01",
                      ip_dst="10.10.10.50", mac_dst="3c:22:fb:11:22:33", op="reply",
                      extra={"gratuitous": False})
    assert (obs.kind, obs.op, obs.direction) == (ARP, "reply", None)


def test_direction_in_out_y_none_desde_el_paquete():
    from batrade.detect.scenarios import observation_from_packet

    def paquete(mac_src: str, mac_dst: str):
        return Ether(src=mac_src, dst=mac_dst) / ScapyARP(
            op=2, hwsrc=mac_src, psrc="10.10.10.1",
            hwdst=mac_dst, pdst="10.10.10.50")

    hacia_el_sensor = observation_from_packet(
        paquete("00:50:56:aa:bb:01", SENSOR_MAC), 1000, sensor_mac=SENSOR_MAC)
    desde_el_sensor = observation_from_packet(
        paquete(SENSOR_MAC, "00:50:56:aa:bb:01"), 1000, sensor_mac=SENSOR_MAC)
    terceros = observation_from_packet(
        paquete("00:50:56:aa:bb:01", "3c:22:fb:11:22:33"), 1000, sensor_mac=SENSOR_MAC)

    assert hacia_el_sensor is not None and hacia_el_sensor.direction == "in"
    assert desde_el_sensor is not None and desde_el_sensor.direction == "out"
    assert terceros is not None and terceros.direction is None   # espejado: no se inventa


def test_sin_mac_del_sensor_no_hay_direction():
    from batrade.detect.scenarios import observation_from_packet

    paquete = Ether(src="00:50:56:aa:bb:01", dst=SENSOR_MAC) / ScapyARP(
        op=2, hwsrc="00:50:56:aa:bb:01", psrc="10.10.10.1",
        hwdst=SENSOR_MAC, pdst="10.10.10.50")
    obs = observation_from_packet(paquete, 1000)
    assert obs is not None and obs.direction is None


def test_capture_interface_null_entre_comillas_tambien_usa_la_de_gestion(tmp_path):
    cfg = load_config(_yaml(tmp_path, '  interface: lo\n  cidr: 10.10.10.0/24\n'
                                     '  capture_interface: "null"\n'), tmp_path)
    assert cfg.network.capture_interface == "lo"

"""Fixtures compartidas de la suite."""
from __future__ import annotations

import pytest

from batrade import db
from batrade.config import load_config
from batrade.detect.engine import Engine
from batrade.detect.state import Baseline
from batrade.net.oui import OuiDB

GW_IP = "10.10.10.1"
GW_MAC = "00:50:56:aa:bb:01"
SENSOR_IP = "10.10.10.200"
SENSOR_MAC = "00:50:56:aa:bb:02"
HOST_IP = "10.10.10.50"
HOST_MAC = "3c:22:fb:11:22:33"
ATTACKER_IP = "10.10.10.66"
ATTACKER_MAC = "aa:bb:cc:00:11:22"

BASE_YAML = """
network:
  interface: lo
  cidr: 10.10.10.0/24
  gateway_ip: 10.10.10.1
  dhcp_server_ip: null
sensor:
  mode: degraded
  sweep_interval: 30
  presence_misses: 3
  heartbeat_interval: 15
  retention_days: 90
  neighbor_watch: false
scan:
  enabled: false
  max_concurrent: 2
  timing: "-T3"
  standard_timeout: 300
  quick_timeout: 120
  udp_timeout: 60
  quick_periodic_hours: 24
  weekly_rescan_days: 7
  risky_ports:
    - { port: 23, protocol: tcp, service: "Telnet", reason: "Acceso remoto sin cifrar" }
    - { port: 445, protocol: tcp, service: "SMB", reason: "Compartición expuesta" }
    - { port: 1900, protocol: udp, service: "UPnP", reason: "Mapeo automático" }
detect:
  window_s: 10
  syn_ports_warn: 15
  syn_ports_crit: 100
  syn_dsts_crit: 25
  arp_sweep_ips: 30
  arp_verify: false
  arp_verify_timeout: 1.5
  arp_exceptions: []
  cooldown_s: 300
notify:
  channels:
    - { type: local }
  timeout_s: 2
  max_attempts: 3
dashboard:
  host: 127.0.0.1
  port: 8000
paths:
  db: var/test.db
  scans_dir: var/scans
  log_dir: var/log
  alerts_log: var/alerts.log
  oui_file: /usr/share/nmap/nmap-mac-prefixes
"""


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.delenv("DASHBOARD_TOKEN", raising=False)
    path = tmp_path / "config.yaml"
    path.write_text(BASE_YAML, encoding="utf-8")
    loaded = load_config(path, tmp_path)
    loaded.ensure_dirs()
    return loaded


@pytest.fixture
def conn(cfg):
    """Misma base de datos que cfg.Paths: dashboard, notificador y repositorio comparten archivo."""
    connection = db.initialize(cfg.paths.db)
    yield connection
    connection.close()


@pytest.fixture
def oui():
    return OuiDB({"005056": "VMware", "3C22FB": "Apple", "001A2B": "Cisco"})


@pytest.fixture
def baseline():
    return Baseline(
        gateway_ip=GW_IP, gateway_mac=GW_MAC,
        sensor_ips={SENSOR_IP}, sensor_macs={SENSOR_MAC},
        learning=False,
    )


@pytest.fixture
def engine(cfg, baseline):
    engine = Engine(cfg, baseline)
    engine.register_sensor(SENSOR_IP, SENSOR_MAC)
    return engine


@pytest.fixture
def arp():
    """Constructor de observaciones ARP legibles para los tests de reglas."""
    from batrade.detect.observation import ARP, Observation

    def build(ts, ip_src, mac_src, ip_dst="10.10.10.254", op="reply",
              gratuitous=False, mac_dst="ff:ff:ff:ff:ff:ff"):
        return Observation(kind=ARP, ts=ts, ip_src=ip_src, mac_src=mac_src,
                           ip_dst=ip_dst, mac_dst=mac_dst, op=op,
                           extra={"gratuitous": gratuitous})
    return build


@pytest.fixture
def syn():
    from batrade.detect.observation import SYN, Observation

    def build(ts, ip_src, ip_dst, port, mac_src=None, flags="S"):
        return Observation(kind=SYN, ts=ts, ip_src=ip_src, ip_dst=ip_dst,
                           port_dst=port, mac_src=mac_src, extra={"flags": flags})
    return build

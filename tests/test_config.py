"""Configuración: validaciones que deben impedir arrancar con datos erróneos."""
from __future__ import annotations

import pytest

from batrade.config import ConfigError, load_config, load_dotenv

BASE = """
network: {{ interface: lo, cidr: "{cidr}", gateway_ip: {gw} }}
sensor: {{ mode: degraded, sweep_interval: {sweep} }}
dashboard: {{ host: "{host}" }}
scan: {{ risky_ports: [{ports}] }}
"""


def _write(tmp_path, cidr="10.10.10.0/24", gw="10.10.10.1", sweep=30,
           host="127.0.0.1", ports='{ port: 23, protocol: tcp, service: T, reason: R }'):
    path = tmp_path / "c.yaml"
    path.write_text(BASE.format(cidr=cidr, gw=gw, sweep=sweep, host=host, ports=ports))
    return path


def test_defaults_and_derived_network(cfg):
    assert cfg.network.cidr == "10.10.10.0/24"
    assert str(cfg.network_obj) == "10.10.10.0/24"
    assert cfg.detect.syn_ports_warn < cfg.detect.syn_ports_crit
    assert cfg.paths.db.name == "test.db"


def test_interval_out_of_range(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load_config(_write(tmp_path, sweep=5), tmp_path)
    assert any("sweep_interval" in e for e in exc.value.errors)


def test_cidr_not_normalized(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load_config(_write(tmp_path, cidr="10.10.10.5/24"), tmp_path)
    assert any("no está normalizado" in e for e in exc.value.errors)


def test_gateway_outside_cidr(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load_config(_write(tmp_path, gw="192.168.1.1"), tmp_path)
    assert any("no pertenece" in e for e in exc.value.errors)


def test_missing_interface(tmp_path):
    path = _write(tmp_path)
    path.write_text(path.read_text().replace("interface: lo", "interface: noexiste0"))
    with pytest.raises(ConfigError) as exc:
        load_config(path, tmp_path)
    assert any("inexistente" in e for e in exc.value.errors)


def test_exposed_dashboard_requires_token(tmp_path, monkeypatch):
    monkeypatch.delenv("DASHBOARD_TOKEN", raising=False)
    with pytest.raises(ConfigError) as exc:
        load_config(_write(tmp_path, host="0.0.0.0"), tmp_path)
    assert any("fuera de loopback" in e for e in exc.value.errors)
    monkeypatch.setenv("DASHBOARD_TOKEN", "secreto")
    cfg = load_config(_write(tmp_path, host="0.0.0.0"), tmp_path)
    assert cfg.dashboard.auth_token == "secreto"


def test_risky_ports_protocol_required(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load_config(_write(tmp_path, ports='{ port: 1900, protocol: icmp }'), tmp_path)
    assert any("protocolo inválido" in e for e in exc.value.errors)


def test_udp_and_tcp_catalog_coexist(cfg):
    assert ("udp", 1900) in cfg.scan.risky_ports
    assert ("tcp", 23) in cfg.scan.risky_ports
    assert cfg.scan.risky_ports[("tcp", 445)].service == "SMB"


def test_unreadable_dotenv_is_ignored(tmp_path):
    # En systemd el .env puede pertenecer a otro usuario: no debe tumbar el arranque.
    assert load_dotenv(tmp_path) == {}


def test_load_dotenv_does_not_pollute_os_environ(tmp_path, monkeypatch):
    """S-02: los secretos de .env viajan en Config.secrets, no en os.environ."""
    import os
    from batrade.config import load

    monkeypatch.delenv("TELEGRAM_TOKEN", raising=False)
    monkeypatch.delenv("DASHBOARD_TOKEN", raising=False)
    (tmp_path / ".env").write_text(
        "TELEGRAM_TOKEN=123456789:secret_from_dotenv_value\n"
        "DASHBOARD_TOKEN=dash_token_from_dotenv_12345\n",
        encoding="utf-8",
    )
    cfg_path = _write(tmp_path, host="0.0.0.0")

    cfg = load(str(cfg_path), tmp_path)
    assert "TELEGRAM_TOKEN" not in os.environ
    assert "DASHBOARD_TOKEN" not in os.environ
    assert cfg.dashboard.auth_token == "dash_token_from_dotenv_12345"
    assert cfg.secrets["TELEGRAM_TOKEN"] == "123456789:secret_from_dotenv_value"
    assert "secret_from_dotenv_value" not in repr(cfg)


def test_load_config_has_no_filesystem_side_effects(tmp_path):
    """D-04: validar/cargar config.yaml no crea directorios en disco."""
    cfg_path = _write(tmp_path)
    cfg = load_config(cfg_path, tmp_path)
    assert not (tmp_path / "var").exists()
    cfg.ensure_dirs()
    assert cfg.paths.scans_dir.is_dir()
    assert cfg.paths.log_dir.is_dir()

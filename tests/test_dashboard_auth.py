"""Panel expuesto: `--host` aplica la misma regla que config.yaml (RNF-05).

`load_config` rechaza `dashboard.host` fuera de loopback sin token; hasta ahora
`batrade dashboard --host 0.0.0.0` sólo advertía y arrancaba. Estos tests fijan
que los dos caminos comparten la regla y que el caso loopback no cambia.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from batrade import cli
from batrade.config import ConfigError, load_config, validar_host_expuesto


def _cfg(tmp_path, monkeypatch, *, token: str | None = None, host: str = "127.0.0.1"):
    if token is None:
        monkeypatch.delenv("DASHBOARD_TOKEN", raising=False)
    else:
        monkeypatch.setenv("DASHBOARD_TOKEN", token)
    ruta = tmp_path / "config.yaml"
    ruta.write_text(
        "network: { interface: lo, cidr: 10.10.10.0/24 }\n"
        f"dashboard: {{ host: {host}, port: 8000 }}\n",
        encoding="utf-8",
    )
    return load_config(ruta, tmp_path)


class _AppFalsa:
    """Sustituye a la app Flask: registra los argumentos en vez de escuchar."""

    def __init__(self) -> None:
        self.llamadas: list[dict] = []

    def run(self, **kwargs) -> None:
        self.llamadas.append(kwargs)


@pytest.fixture
def app_falsa(monkeypatch):
    falsa = _AppFalsa()
    monkeypatch.setattr("batrade.dashboard.app.create_app", lambda cfg: falsa)
    return falsa


def _args(host: str = "127.0.0.1", port: int = 8000):
    return SimpleNamespace(host=host, port=port)


def test_host_expuesto_sin_token_no_arranca(tmp_path, monkeypatch, app_falsa, capsys):
    cfg = _cfg(tmp_path, monkeypatch, host="127.0.0.1")

    codigo = cli.cmd_dashboard(cfg, _args("0.0.0.0"))
    error = capsys.readouterr().err

    assert codigo == 1
    assert "DASHBOARD_TOKEN" in error
    assert "fuera de loopback" in error
    assert app_falsa.llamadas == []          # no se abrió ningún socket


def test_host_expuesto_con_token_arranca(tmp_path, monkeypatch, app_falsa):
    cfg = _cfg(tmp_path, monkeypatch, token="secreto")

    codigo = cli.cmd_dashboard(cfg, _args("0.0.0.0", 8043))

    assert codigo == 0
    assert cfg.dashboard.auth_token == "secreto"
    assert app_falsa.llamadas == [
        {"host": "0.0.0.0", "port": 8043, "debug": False,
         "use_reloader": False, "threaded": True}
    ]


def test_loopback_sin_token_arranca(tmp_path, monkeypatch, app_falsa, capsys):
    cfg = _cfg(tmp_path, monkeypatch)

    codigo = cli.cmd_dashboard(cfg, _args())
    salida = capsys.readouterr()

    assert codigo == 0
    assert app_falsa.llamadas[0]["host"] == "127.0.0.1"
    assert app_falsa.llamadas[0]["port"] == 8000
    assert "Panel en http://127.0.0.1:8000" in salida.out


def test_la_cli_y_la_config_dan_el_mismo_error(tmp_path, monkeypatch, app_falsa, capsys):
    """Una sola frase para el operador: si divergen, una de las dos miente."""
    cfg = _cfg(tmp_path, monkeypatch)
    assert cli.cmd_dashboard(cfg, _args("0.0.0.0")) == 1
    desde_cli = capsys.readouterr().err

    monkeypatch.delenv("DASHBOARD_TOKEN", raising=False)
    ruta = tmp_path / "expuesto.yaml"
    ruta.write_text(
        "network: { interface: lo, cidr: 10.10.10.0/24 }\n"
        "dashboard: { host: 0.0.0.0, port: 8000 }\n", encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        load_config(ruta, tmp_path)
    desde_config = " ".join(exc.value.errors)

    esperado = validar_host_expuesto("0.0.0.0", None)
    assert esperado and esperado in desde_cli and esperado in desde_config

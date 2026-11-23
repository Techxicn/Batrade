"""Multi-instancia (una por VLAN) y `--proxy` del instalador.

No se ejecuta una instalación completa: se comprueba que dos prefijos resuelven
a rutas distintas, que operar sobre uno no toca el otro, y que `--proxy` sólo
imprime la receta. `BATRADE_TEST_FAKE_ROOT=1` evita exigir root; `BATRADE_BIN_DIR`
redirige el comando para no escribir nunca en /usr/local/bin.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALL = REPO / "install.sh"


def _run(args, *, bin_dir=None, fake_root=False, cwd=None):
    env = {k: v for k, v in os.environ.items()
           if k not in ("BATRADE_ROOT", "BATRADE_BIN_DIR", "BATRADE_TEST_FAKE_ROOT")}
    if fake_root:
        env["BATRADE_TEST_FAKE_ROOT"] = "1"
    if bin_dir is not None:
        env["BATRADE_BIN_DIR"] = str(bin_dir)
    return subprocess.run(["bash", str(INSTALL), *args], cwd=str(cwd or REPO),
                          env=env, capture_output=True, text=True, timeout=180)


def _instancia(tmp_path: Path, nombre: str, db: str) -> tuple[Path, Path]:
    """Árbol de una instancia ya instalada, sin ejecutar pip."""
    prefix = tmp_path / "opt" / nombre
    (prefix / "batrade").mkdir(parents=True)
    (prefix / "batrade" / "__init__.py").write_text("__version__='x'\n", encoding="utf-8")
    (prefix / ".venv" / "bin").mkdir(parents=True)
    (prefix / "var").mkdir(parents=True)
    (prefix / "var" / "batrade.db").write_text(db, encoding="utf-8")
    (prefix / "config.yaml").write_text("network: {}\n", encoding="utf-8")
    (prefix / ".env").write_text("TELEGRAM_TOKEN=\n", encoding="utf-8")
    bin_dir = tmp_path / "bin" / nombre
    bin_dir.mkdir(parents=True)
    (bin_dir / "batrade").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    return prefix, bin_dir


# --------------------------------------------------------------------------- #
# Una instancia por VLAN
# --------------------------------------------------------------------------- #
def test_dos_prefijos_resuelven_a_rutas_distintas(tmp_path):
    vlan10 = tmp_path / "opt" / "batrade-vlan10"
    vlan20 = tmp_path / "opt" / "batrade-vlan20"
    bin10, bin20 = tmp_path / "bin10", tmp_path / "bin20"

    r10 = _run(["--system", "--dry-run", "--prefix", str(vlan10)],
               bin_dir=bin10, fake_root=True)
    r20 = _run(["--system", "--dry-run", "--prefix", str(vlan20)],
               bin_dir=bin20, fake_root=True)

    assert r10.returncode == 0, r10.stderr
    assert r20.returncode == 0, r20.stderr
    s10, s20 = r10.stdout + r10.stderr, r20.stdout + r20.stderr

    # Cada plan habla sólo de su prefijo y de su propio comando.
    assert str(vlan10) in s10 and str(vlan20) not in s10
    assert str(vlan20) in s20 and str(vlan10) not in s20
    assert str(bin10 / "batrade") in s10 and str(bin20 / "batrade") in s20
    # La base se inicializa contra la raíz de cada instancia: var/ y SQLite no
    # se comparten porque cuelgan del prefijo.
    assert f"--root {vlan10}" in s10
    assert f"--root {vlan20}" in s20
    assert (vlan10 / "var" / "batrade.db") != (vlan20 / "var" / "batrade.db")


def test_operar_sobre_una_instancia_no_toca_la_otra(tmp_path):
    vlan10, bin10 = _instancia(tmp_path, "batrade-vlan10", "datos vlan10")
    vlan20, bin20 = _instancia(tmp_path, "batrade-vlan20", "datos vlan20")

    resultado = _run(["--uninstall", "--prefix", str(vlan10)], bin_dir=bin10,
                     fake_root=True)

    assert resultado.returncode == 0, resultado.stderr
    assert not (vlan10 / "batrade").exists()          # código de la 10 fuera
    assert (vlan10 / "var" / "batrade.db").read_text(encoding="utf-8") == "datos vlan10"
    # La otra instancia, intacta en código, datos y comando.
    assert (vlan20 / "batrade" / "__init__.py").exists()
    assert (vlan20 / "var" / "batrade.db").read_text(encoding="utf-8") == "datos vlan20"
    assert (bin20 / "batrade").exists()


# --------------------------------------------------------------------------- #
# --proxy
# --------------------------------------------------------------------------- #
def test_proxy_no_necesita_root_ni_instala_nada(tmp_path):
    resultado = _run(["--proxy"], cwd=tmp_path)      # sin FAKE_ROOT

    assert resultado.returncode == 0, resultado.stderr
    salida = resultado.stdout
    assert "reverse_proxy 127.0.0.1:8000" in salida
    assert "proxy_pass http://127.0.0.1:8000" in salida
    assert "openssl rand -hex 32" in salida
    assert "DASHBOARD_TOKEN" in salida
    assert "chmod 600" in salida
    assert "127.0.0.1:8000" in salida                # el Flask no se mueve
    assert "[dry-run]" not in salida                 # no es un plan: no hace nada
    assert list(tmp_path.iterdir()) == []            # ni un fichero


def test_help_documenta_proxy_y_bin_dir():
    resultado = _run(["--help"])

    assert resultado.returncode == 0
    assert "--proxy" in resultado.stdout
    assert "BATRADE_BIN_DIR" in resultado.stdout
